package signal

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// --- minimal protobuf writer, so tests can build the responses Signal would
// send, and ones it would not.

func tag(field int, wire byte) []byte { return uvarintBytes(uint64(field)<<3 | uint64(wire)) }

func uvarintBytes(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func lenField(field int, v []byte) []byte {
	out := tag(field, 2)
	out = append(out, uvarintBytes(uint64(len(v)))...)
	return append(out, v...)
}

func varField(field int, v uint64) []byte {
	return append(tag(field, 0), uvarintBytes(v)...)
}

type auditor struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	size uint64

	// rootOverride puts this auditor on a different history from the others.
	rootOverride *hash
	// tamperRootAfterSigning swaps the served root without re-signing it.
	tamperRootAfterSigning *hash
	// suppressSignature emits the tree head with no signature at all.
	suppressSignature bool
}

// fakeSignal builds responses over a real reference tree, so the consistency
// proofs are genuine and the derive path is actually exercised.
type fakeSignal struct {
	t *testing.T

	svcPub  ed25519.PublicKey
	svcPriv ed25519.PrivateKey

	tree        referenceTree
	serviceSize uint64
	timestamp   int64
	auditors    []*auditor

	breakServiceSignature bool
	omitServiceSignature  bool
}

func (f *fakeSignal) serviceRoot() hash { return f.tree.root(f.t, f.serviceSize) }

func (f *fakeSignal) build(s *Source, lastSize uint64) []byte {
	f.t.Helper()
	svcRoot := f.serviceRoot()

	// TreeHead{1:tree_size, 2:timestamp, 3:repeated Signature}
	th := append(varField(1, f.serviceSize), varField(2, uint64(f.timestamp))...)
	if !f.omitServiceSignature {
		for _, a := range f.auditors {
			signedRoot := svcRoot
			if f.breakServiceSignature {
				signedRoot[0] ^= 0xFF
			}
			sig := ed25519.Sign(f.svcPriv, s.signable(a.pub, f.serviceSize, f.timestamp, signedRoot[:]))
			sm := append(lenField(1, a.pub), lenField(2, sig)...)
			th = append(th, lenField(3, sm)...)
		}
	}

	fth := lenField(1, th)

	for _, a := range f.auditors {
		aRoot := f.tree.root(f.t, a.size)
		if a.rootOverride != nil {
			aRoot = *a.rootOverride
		}
		sig := ed25519.Sign(a.priv, s.signable(a.pub, a.size, f.timestamp, aRoot[:]))

		served := aRoot
		if a.tamperRootAfterSigning != nil {
			served = *a.tamperRootAfterSigning
		}

		// AuditorTreeHead{1:tree_size, 2:timestamp, 3:signature}
		ah := append(varField(1, a.size), varField(2, uint64(f.timestamp))...)
		if !a.suppressSignature {
			ah = append(ah, lenField(3, sig)...)
		}

		// FullAuditorTreeHead{1:tree_head, 2:root_value, 3:consistency, 4:public_key}
		fa := append(lenField(1, ah), lenField(2, served[:])...)
		for _, h := range f.tree.proof(f.t, a.size, f.serviceSize) {
			fa = append(fa, lenField(3, h[:])...)
		}
		fa = append(fa, lenField(4, a.pub)...)

		fth = append(fth, lenField(4, fa)...)
	}

	// FullTreeHead field 3: consistency against the size the client asked about.
	if lastSize > 0 && lastSize < f.serviceSize {
		for _, h := range f.tree.proof(f.t, lastSize, f.serviceSize) {
			fth = append(fth, lenField(3, h[:])...)
		}
	}

	return lenField(1, fth)
}

func newFake(t *testing.T, serviceSize uint64, auditorSizes ...uint64) (*Source, *fakeSignal) {
	t.Helper()
	svcPub, svcPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeSignal{
		t: t, svcPub: svcPub, svcPriv: svcPriv,
		serviceSize: serviceSize, timestamp: 1788307451558,
	}
	var keys []string
	for _, sz := range auditorSizes {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		f.auditors = append(f.auditors, &auditor{pub: pub, priv: priv, size: sz})
		keys = append(keys, hex.EncodeToString(pub))
	}

	s, err := New(Config{
		Origin:      "signal.org/kt",
		AuditorKeys: keys,
		MinAuditors: 1,
		SigningKey:  hex.EncodeToString(svcPub),
		// These fixtures forge tree heads, not directory contents: they have no
		// VRF key and no prefix tree, so there is no search proof to open. The
		// search path has its own tests, against live production proofs.
		SkipSearchProof: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var last uint64
		if v := r.URL.Query().Get("lastTreeHeadSize"); v != "" {
			last, _ = strconv.ParseUint(v, 10, 64)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"serializedResponse": base64.RawStdEncoding.EncodeToString(f.build(s, last)),
		})
	}))
	t.Cleanup(srv.Close)

	s.cfg.Endpoint = srv.URL
	s.client = srv.Client()
	return s, f
}

// The whole point: the service root is never served, so it must be derived from
// the auditors' proofs and then confirmed by Signal's own signature.
func TestFetchDerivesAndVerifiesServiceRoot(t *testing.T) {
	s, f := newFake(t, 20, 12, 15, 18)

	head, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("a well-formed response should verify: %v", err)
	}
	if head.Size != 20 {
		t.Fatalf("want service size 20, got %d", head.Size)
	}
	if want := f.serviceRoot(); head.Hash != want {
		t.Fatalf("head hash %x is not the derived service root %x", head.Hash, want)
	}
}

// Auditors starting from different sizes must land on the same root. One on a
// different history is a contradiction between signed statements.
func TestAuditorOnDifferentHistoryIsRejected(t *testing.T) {
	s, f := newFake(t, 20, 12, 15)

	bogus := referenceTree{}.root(t, 13)
	f.auditors[1].rootOverride = &bogus

	_, err := s.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("an auditor on a different history must not be accepted")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		if !strings.Contains(fe.Reason, "disagree") {
			t.Errorf("fork reason should describe the disagreement, got %q", fe.Reason)
		}
		return
	}
	// Often the bad root fails its own consistency proof first, which is an
	// equally correct refusal.
	t.Logf("rejected before the cross-check, also correct: %v", err)
}

// The auditor's signature must cover the root actually served.
func TestTamperedAuditorRootIsRejected(t *testing.T) {
	s, f := newFake(t, 20, 12)
	bogus := referenceTree{}.root(t, 7)
	f.auditors[0].tamperRootAfterSigning = &bogus

	if _, err := s.Fetch(context.Background(), nil); err == nil {
		t.Fatal("a root the auditor did not sign must be rejected")
	}
}

// Deriving a root is not enough: Signal must have signed it.
func TestServiceSignatureOverWrongRootIsRejected(t *testing.T) {
	s, f := newFake(t, 20, 12, 15)
	f.breakServiceSignature = true

	_, err := s.Fetch(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no service signature verifies") {
		t.Fatalf("want rejection for a service signature over the wrong root, got %v", err)
	}
}

func TestMissingServiceSignatureIsRejected(t *testing.T) {
	s, f := newFake(t, 20, 12)
	f.omitServiceSignature = true

	if _, err := s.Fetch(context.Background(), nil); err == nil {
		t.Fatal("a response with no service signature must be rejected")
	}
}

// A quorum guards against a single auditor moving our view on its own.
func TestBelowMinAuditorsIsRejected(t *testing.T) {
	s, _ := newFake(t, 20, 12)
	s.cfg.MinAuditors = 2

	_, err := s.Fetch(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "need 2") {
		t.Fatalf("want a quorum error, got %v", err)
	}
}

func TestConsistencyAcrossObservations(t *testing.T) {
	s, f := newFake(t, 20, 12, 15)

	prev, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	f.serviceSize = 31
	f.auditors[0].size, f.auditors[1].size = 25, 28

	next, err := s.Fetch(context.Background(), prev)
	if err != nil {
		t.Fatal(err)
	}
	if next.Size != 31 {
		t.Fatalf("want size 31, got %d", next.Size)
	}
	if err := s.VerifyConsistency(context.Background(), prev, next); err != nil {
		t.Fatalf("a genuine extension should verify: %v", err)
	}
}

// A proof that does not connect the two roots means we could not check, not that
// we caught Signal forking: a fork and a broken proof look the same from here,
// and the accusation is permanent.
func TestBrokenConsistencyWithholdsWithoutAccusing(t *testing.T) {
	s, f := newFake(t, 20, 12, 15)

	prev, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.serviceSize = 31
	f.auditors[0].size, f.auditors[1].size = 25, 28
	next, err := s.Fetch(context.Background(), prev)
	if err != nil {
		t.Fatal(err)
	}

	s.lastProof[0][0] ^= 0xFF

	err = s.VerifyConsistency(context.Background(), prev, next)
	if err == nil {
		t.Fatal("a proof that does not connect the roots must withhold")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("a broken proof must not be recorded as a fork")
	}
}

// A proof fetched for a different starting size must not be reused.
func TestProofFromDifferentSizeIsRefused(t *testing.T) {
	s, _ := newFake(t, 20, 12, 15)
	prev, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.lastProofFrom = 999

	if err := s.VerifyConsistency(context.Background(), prev, prev); err == nil {
		t.Fatal("a proof fetched against another size must not be used")
	}
}

// Pinned production key material must not drift.
func TestProductionKeysAreWellFormed(t *testing.T) {
	for name, k := range map[string]string{"signing": ProdSigningKey, "vrf": ProdVRFKey} {
		if _, err := decodeKey(k, name); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	if len(ProdAuditorKeys) != 3 {
		t.Fatalf("Signal deploys three auditors, config has %d", len(ProdAuditorKeys))
	}
	seen := map[string]bool{}
	for _, k := range ProdAuditorKeys {
		if _, err := decodeKey(k, "auditor"); err != nil {
			t.Errorf("auditor key %s: %v", k[:8], err)
		}
		if seen[k] {
			t.Errorf("duplicate auditor key %s", k[:8])
		}
		seen[k] = true
	}
}

func TestSignablePreimageLayout(t *testing.T) {
	s, err := New(Config{Origin: "signal.org/kt"})
	if err != nil {
		t.Fatal(err)
	}
	got := s.signable(s.auditors[0], 1, 2, make([]byte, 32))

	// 2 ciphersuite + 1 mode + 3*(2 + 32) + 8 size + 8 timestamp + 32 root
	const want = 2 + 1 + 3*(2+32) + 8 + 8 + 32
	if len(got) != want {
		t.Fatalf("preimage is %d bytes, want %d", len(got), want)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != deploymentModeThirdPartyAuditing {
		t.Fatalf("preimage must start with ciphersuite 0,0 then mode 3, got %v", got[:3])
	}
	if binary.BigEndian.Uint64(got[want-48:want-40]) != 1 {
		t.Fatal("tree size not encoded big-endian where expected")
	}
}

// An auditor that has caught up but supplies no signature must not be counted:
// otherwise MinAuditors silently means fewer verified auditors than it says.
func TestCaughtUpAuditorWithoutSignatureIsNotCounted(t *testing.T) {
	s, f := newFake(t, 20, 20, 15)
	s.cfg.MinAuditors = 2

	// Strip the caught-up auditor's signature by giving it a key nobody signs
	// with: rebuild its entry with an empty signature.
	f.auditors[0].suppressSignature = true

	_, err := s.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("an unsigned auditor root must not satisfy the quorum")
	}
	if !strings.Contains(err.Error(), "need 2") {
		t.Fatalf("want a quorum error, got %v", err)
	}
}
