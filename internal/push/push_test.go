package push

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const testOrigin = "example.com/log"

// hashStore is an in-memory tlog.HashReader, so tests build real trees and
// real proofs rather than stubbing the cryptography they are meant to check.
type hashStore []tlog.Hash

func (h hashStore) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		if x < 0 || x >= int64(len(h)) {
			return nil, fmt.Errorf("hash index %d out of range", x)
		}
		out[i] = h[x]
	}
	return out, nil
}

type testLog struct {
	t      *testing.T
	signer note.Signer
	vkey   note.Verifier
	hashes hashStore
	n      int64
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return &testLog{t: t, signer: s, vkey: v}
}

func (l *testLog) grow(k int) {
	for range k {
		hs, err := tlog.StoredHashes(l.n, []byte(fmt.Sprintf("leaf %d", l.n)), l.hashes)
		if err != nil {
			l.t.Fatal(err)
		}
		l.hashes = append(l.hashes, hs...)
		l.n++
	}
}

func (l *testLog) text(size int64, ext string) string {
	h, err := tlog.TreeHash(size, l.hashes)
	if err != nil {
		l.t.Fatal(err)
	}
	return torchwood.Checkpoint{Origin: testOrigin, Tree: tlog.Tree{N: size, Hash: h}, Extension: ext}.String()
}

func signNote(t *testing.T, text string, s note.Signer) []byte {
	t.Helper()
	b, err := note.Sign(&note.Note{Text: text}, s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (l *testLog) checkpoint(size int64) []byte {
	return signNote(l.t, l.text(size, ""), l.signer)
}

func (l *testLog) proof(old, size int64) tlog.TreeProof {
	p, err := tlog.ProveTree(size, old, l.hashes)
	if err != nil {
		l.t.Fatal(err)
	}
	return p
}

func body(old int64, proof tlog.TreeProof, signed []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "old %d\n", old)
	for _, h := range proof {
		b.WriteString(h.String() + "\n")
	}
	b.WriteString("\n")
	b.Write(signed)
	return b.String()
}

type mapRegistry struct {
	mu   sync.Mutex
	logs map[string]*Log
}

func (r *mapRegistry) Lookup(origin string) (*Log, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.logs[origin]
	return l, ok
}

type fixture struct {
	t      *testing.T
	log    *testLog
	w      *witness.Witness
	db     *store.Store
	h      *Handler
	signer *torchwood.CosignatureSigner
	now    time.Time
}

func newFixture(t *testing.T, qpd int64) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := torchwood.NewCosignatureSigner("witness.test", priv)
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &witness.Witness{Signer: signer, Store: db, Log: quiet, MaxSignDelay: time.Minute}
	tl := newTestLog(t)
	f := &fixture{t: t, log: tl, w: w, db: db, signer: signer, now: time.Now()}
	reg := &mapRegistry{logs: map[string]*Log{
		testOrigin: {Origin: testOrigin, Verifier: tl.vkey, QPD: qpd},
	}}
	f.h = New(Config{Witness: w, Registry: reg, Log: quiet, Now: func() time.Time { return f.now }})
	return f
}

func (f *fixture) do(method, reqBody string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/add-checkpoint", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) post(reqBody string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, reqBody)
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d; body %q", rec.Code, status, rec.Body.String())
	}
}

// expectCosigned checks a 200 body is exactly our cosignature line over text,
// and that it verifies with our cosignature/v1 key.
func (f *fixture) expectCosigned(rec *httptest.ResponseRecorder, text string) {
	f.t.Helper()
	expect(f.t, rec, http.StatusOK)
	got := rec.Body.String()
	if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "— witness.test ") {
		f.t.Fatalf("want exactly one line of ours, got %q", got)
	}
	n, err := note.Open([]byte(text+"\n"+got), note.VerifierList(f.signer.Verifier()))
	if err != nil {
		f.t.Fatalf("cosignature does not verify over the checkpoint: %v", err)
	}
	if len(n.Sigs) != 1 {
		f.t.Fatalf("verified %d signatures, want 1", len(n.Sigs))
	}
}

func (f *fixture) expectConflict(rec *httptest.ResponseRecorder, size int64) {
	f.t.Helper()
	expect(f.t, rec, http.StatusConflict)
	if ct := rec.Header().Get("Content-Type"); ct != "text/x.tlog.size" {
		f.t.Fatalf("Content-Type %q", ct)
	}
	if got, want := rec.Body.String(), fmt.Sprintf("%d\n", size); got != want {
		f.t.Fatalf("409 body %q, want %q", got, want)
	}
}

// seed brings the witness to size n via a fresh push.
func (f *fixture) seed(n int) {
	f.t.Helper()
	f.log.grow(n)
	f.expectCosigned(f.post(body(0, nil, f.log.checkpoint(f.log.n))), f.log.text(f.log.n, ""))
}

func TestUnknownOrigin(t *testing.T) {
	f := newFixture(t, 0)
	other := newTestLog(t)
	other.grow(1)
	text := strings.Replace(other.text(1, ""), testOrigin, "example.com/other", 1)
	s, _ := note.NewSigner(mustKey(t, "example.com/other"))
	expect(t, f.post(body(0, nil, signNote(t, text, s))), http.StatusNotFound)
}

func mustKey(t *testing.T, name string) string {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return skey
}

func TestBadLogSignature(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(1)
	// Right name, wrong key: the signature line is simply not the log's.
	s, _ := note.NewSigner(mustKey(t, testOrigin))
	expect(t, f.post(body(0, nil, signNote(t, f.log.text(1, ""), s))), http.StatusForbidden)
	if rec, _ := f.db.Get(testOrigin); rec != nil {
		t.Fatal("stored a head from a checkpoint the log did not sign")
	}
}

func TestFreshLogIsCosigned(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	rec, _ := f.db.Get(testOrigin)
	if rec == nil || rec.Size != 3 {
		t.Fatalf("head not persisted: %+v", rec)
	}
}

func TestOtherWitnessLinesAreIgnoredAndNotEchoed(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(2)
	_, peerPriv, _ := ed25519.GenerateKey(nil)
	peer, _ := torchwood.NewCosignatureSigner("peer.test", peerPriv)
	text := f.log.text(2, "")
	signed, err := note.Sign(&note.Note{Text: text}, f.log.signer, peer)
	if err != nil {
		t.Fatal(err)
	}
	f.expectCosigned(f.post(body(0, nil, signed)), text)
}

func TestAdvanceWithProof(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	f.log.grow(5)
	f.expectCosigned(f.post(body(3, f.log.proof(3, 8), f.log.checkpoint(8))), f.log.text(8, ""))
	if rec, _ := f.db.Get(testOrigin); rec.Size != 8 {
		t.Fatalf("stored size %d, want 8", rec.Size)
	}
}

func TestAdvanceFromEmptyTree(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(0)
	f.log.grow(4)
	f.expectCosigned(f.post(body(0, nil, f.log.checkpoint(4))), f.log.text(4, ""))
}

func TestWrongOldSizeConflicts(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	f.log.grow(5)
	f.expectConflict(f.post(body(2, f.log.proof(2, 8), f.log.checkpoint(8))), 3)
}

func TestOldZeroOnHeldLogConflicts(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	f.log.grow(2)
	f.expectConflict(f.post(body(0, nil, f.log.checkpoint(5))), 3)
}

func TestOldLargerThanCheckpointIsBadRequest(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	expect(t, f.post(body(4, nil, f.log.checkpoint(3))), http.StatusBadRequest)
}

func TestProofWithOldZeroIsBadRequest(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(4)
	p := f.log.proof(2, 4)
	expect(t, f.post(body(0, p, f.log.checkpoint(4))), http.StatusBadRequest)
}

func TestMalformedBody(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(1)
	cp := f.log.checkpoint(1)
	for name, b := range map[string]string{
		"no blank line": "old 0\n" + string(cp),
		"no old line":   "\n" + string(cp),
		"bad old":       "old 01\n\n" + string(cp),
		"bad proof":     "old 0\nnot-base64\n\n" + string(cp),
		"not a note":    "old 0\n\n" + testOrigin + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.post(b)
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 400 (or 403 for an unsigned note); body %q", rec.Code, rec.Body.String())
			}
		})
	}
}

// A proof that fails to verify is the client's error, not the log's signed
// statement, so it must never poison the log.
func TestInvalidProofIsNotAFork(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	f.log.grow(5)
	p := f.log.proof(3, 8)
	p[0][0] ^= 1
	expect(t, f.post(body(3, p, f.log.checkpoint(8))), http.StatusUnprocessableEntity)
	if forked, _ := f.db.IsForked(testOrigin); forked {
		t.Fatal("an invalid client proof recorded a fork")
	}
	// And the log can still proceed with a good one.
	f.expectCosigned(f.post(body(3, f.log.proof(3, 8), f.log.checkpoint(8))), f.log.text(8, ""))
}

func TestIdenticalRepushReturnsCosignature(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	before, _ := f.db.Get(testOrigin)
	f.expectCosigned(f.post(body(3, nil, f.log.checkpoint(3))), f.log.text(3, ""))
	after, _ := f.db.Get(testOrigin)
	if after.WitnessedAt.Equal(before.WitnessedAt) {
		t.Fatal("identical re-push should be cosigned afresh, as litewitness does")
	}
}

// Same tree, different body: the stored cosignature is over other bytes, so the
// core re-cosigns rather than answering with a signature that would not verify.
func TestSameTreeNewExtensionIsRecosigned(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	text := f.log.text(3, "extension line\n")
	f.expectCosigned(f.post(body(3, nil, signNote(t, text, f.log.signer))), text)
	if forked, _ := f.db.IsForked(testOrigin); forked {
		t.Fatal("a changed extension line at the same tree recorded a fork")
	}
}

// The log signing two roots at one size is equivocation: 409 per the spec, the
// fork recorded, and the log refused from then on.
func TestSplitViewConflictsAndPoisons(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)

	other := newTestLog(t)
	other.signer = f.log.signer
	other.hashes = nil
	for i := range 3 {
		hs, _ := tlog.StoredHashes(int64(i), []byte(fmt.Sprintf("other %d", i)), other.hashes)
		other.hashes = append(other.hashes, hs...)
	}
	f.expectConflict(f.post(body(3, nil, other.checkpoint(3))), 3)
	if forked, _ := f.db.IsForked(testOrigin); !forked {
		t.Fatal("a signed split view was not recorded as a fork")
	}

	f.log.grow(2)
	rec := f.post(body(3, f.log.proof(3, 5), f.log.checkpoint(5)))
	expect(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), "forked") {
		t.Fatalf("403 body does not say why: %q", rec.Body.String())
	}
}

func TestRateLimited(t *testing.T) {
	f := newFixture(t, 2)
	f.seed(1)
	f.log.grow(1)
	f.expectCosigned(f.post(body(1, f.log.proof(1, 2), f.log.checkpoint(2))), f.log.text(2, ""))
	f.log.grow(1)
	rec := f.post(body(2, f.log.proof(2, 3), f.log.checkpoint(3)))
	expect(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// Half a day later, at two a day, one token is back.
	f.now = f.now.Add(12*time.Hour + time.Second)
	f.expectCosigned(f.post(body(2, f.log.proof(2, 3), f.log.checkpoint(3))), f.log.text(3, ""))
}

// Unauthenticated junk must not spend a log's allowance.
func TestBadSignatureDoesNotSpendQuota(t *testing.T) {
	f := newFixture(t, 1)
	f.log.grow(1)
	s, _ := note.NewSigner(mustKey(t, testOrigin))
	for range 3 {
		expect(t, f.post(body(0, nil, signNote(t, f.log.text(1, ""), s))), http.StatusForbidden)
	}
	f.expectCosigned(f.post(body(0, nil, f.log.checkpoint(1))), f.log.text(1, ""))
}

// A head we took too long to sign is withheld, and the log told to retry.
func TestStaleViewIsUnavailable(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(1)
	f.now = time.Now().Add(-time.Hour) // FetchedAt, against a one-minute MaxSignDelay
	expect(t, f.post(body(0, nil, f.log.checkpoint(1))), http.StatusServiceUnavailable)
}

func TestGetNotAllowed(t *testing.T) {
	f := newFixture(t, 0)
	rec := f.do(http.MethodGet, "")
	expect(t, rec, http.StatusMethodNotAllowed)
	if rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow %q", rec.Header().Get("Allow"))
	}
}

func TestOversizeBody(t *testing.T) {
	f := newFixture(t, 0)
	f.h.cfg.MaxBodyBytes = 64
	expect(t, f.post(strings.Repeat("x", 65)), http.StatusRequestEntityTooLarge)
}

// The adapter only vouches for the pair of trees the request named. Asked
// about any other pair — the stored head moved between the handler's read and
// the core's — it says so rather than judging the proof, and certainly without
// a ForkError.
func TestAdapterRefusesOtherPairs(t *testing.T) {
	l := newTestLog(t)
	l.grow(8)
	h3, _ := tlog.TreeHash(3, l.hashes)
	h6, _ := tlog.TreeHash(6, l.hashes)
	h8, _ := tlog.TreeHash(8, l.hashes)
	next := &source.Head{Origin: testOrigin, Size: 8, Hash: h8}
	s := &pushedSource{head: next, old: 3, proof: l.proof(3, 8)}
	if err := s.VerifyConsistency(context.Background(), &source.Head{Size: 3, Hash: h3}, next); err != nil {
		t.Fatalf("the named pair should verify: %v", err)
	}
	err := s.VerifyConsistency(context.Background(), &source.Head{Size: 6, Hash: h6}, next)
	if !errors.Is(err, errMoved) {
		t.Fatalf("got %v, want errMoved", err)
	}
	if err := s.VerifyConsistency(context.Background(), nil, next); !errors.Is(err, errMoved) {
		t.Fatalf("got %v, want errMoved for a vanished record", err)
	}
}

// A log whose old size is stale because the poller advanced us is told our new
// size, not accused.
func TestPollerAdvancedBeforeRequest(t *testing.T) {
	f := newFixture(t, 0)
	f.seed(3)
	f.log.grow(5)
	// Simulate the poller: store size 6 behind the handler's back.
	cur, _ := f.db.Get(testOrigin)
	h, _ := tlog.TreeHash(6, f.log.hashes)
	next := &store.Record{Origin: testOrigin, Size: 6, Hash: h,
		Cosigned: signNote(t, f.log.text(6, ""), f.log.signer), WitnessedAt: time.Now()}
	if err := f.db.CompareAndSet(cur, next); err != nil {
		t.Fatal(err)
	}
	f.expectConflict(f.post(body(3, f.log.proof(3, 8), f.log.checkpoint(8))), 6)
	if forked, _ := f.db.IsForked(testOrigin); forked {
		t.Fatal("a race recorded a fork")
	}
}
