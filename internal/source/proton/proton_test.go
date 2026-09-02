package proton

import (
	"context"
	"crypto/sha256"
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

// chainHash is the rule under test, written out independently of the
// implementation so the test would catch the implementation changing.
func chainHash(prevHex, treeHex string) string {
	prev, _ := hex.DecodeString(prevHex)
	tree, _ := hex.DecodeString(treeHex)
	h := sha256.New()
	h.Write(prev)
	h.Write(tree)
	return hex.EncodeToString(h.Sum(nil))
}

func hx(b byte) string {
	var raw [32]byte
	for i := range raw {
		raw[i] = b
	}
	return hex.EncodeToString(raw[:])
}

// buildChain makes epochs [start,end] correctly chained from a genesis hash.
func buildChain(start, end int64) map[int64]*epoch {
	out := map[int64]*epoch{}
	prev := hx(0)
	for id := start; id <= end; id++ {
		tree := hx(byte(id))
		ch := chainHash(prev, tree)
		out[id] = &epoch{
			EpochID: id, TreeHash: tree, ChainHash: ch, PrevChainHash: prev,
			ClaimedTime: 1700000000 + id*14400, CertificateTime: 1700000000 + id*14400,
			Domain: "keytransparency.ch",
		}
		prev = ch
	}
	return out
}

func newTestSource(t *testing.T, epochs map[int64]*epoch, tip int64) *Source {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/kt/v1/epochs" {
			json.NewEncoder(w).Encode(map[string]any{"Epochs": []*epoch{epochs[tip]}})
			return
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/kt/v1/epochs/"), 10, 64)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		e, ok := epochs[id]
		if !ok {
			http.Error(w, "no such epoch", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(e)
	}))
	t.Cleanup(srv.Close)

	s, err := New(Config{Origin: "proton.test/kt", APIBase: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func head(t *testing.T, id int64, hashHex string) *source.Head {
	t.Helper()
	h, err := hashOf(hashHex)
	if err != nil {
		t.Fatal(err)
	}
	return &source.Head{Origin: "proton.test/kt", Size: id, Hash: h}
}

func TestChainHashVerification(t *testing.T) {
	e := &epoch{EpochID: 5, TreeHash: hx(5), PrevChainHash: hx(4)}
	e.ChainHash = chainHash(e.PrevChainHash, e.TreeHash)
	if err := e.verifyChainHash(); err != nil {
		t.Fatalf("correct chain hash rejected: %v", err)
	}

	e.ChainHash = hx(99)
	if err := e.verifyChainHash(); err == nil {
		t.Fatal("a chain hash that is not SHA-256(prev||tree) must be rejected")
	}
}

// Golden test pinned to real production data (epoch 6706, observed
// 2026-09-01). If Proton ever changes the commitment name format, this fails
// rather than the adapter silently accepting certificates that commit to
// nothing.
func TestExpectedSANMatchesProduction(t *testing.T) {
	e := &epoch{
		EpochID:         6706,
		ChainHash:       "cebd7b01ae26d3d39a3bff112ec1c02f3480fe8bdfb6d96fb97dfb4845e699bc",
		CertificateTime: 1788298290,
		Domain:          "keytransparency.ch",
	}
	const want = "cebd7b01ae26d3d39a3bff112ec1c02f.3480fe8bdfb6d96fb97dfb4845e699bc." +
		"1788298290.6706.1.keytransparency.ch"

	got, err := e.expectedSAN()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("commitment name mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestExpectedSANRejectsMalformedChainHash(t *testing.T) {
	e := &epoch{EpochID: 1, ChainHash: "abcd", Domain: "x"}
	if _, err := e.expectedSAN(); err == nil {
		t.Fatal("want error for a short chain hash")
	}
}

func TestChainWalkAcceptsContinuousHistory(t *testing.T) {
	epochs := buildChain(1, 20)
	s := newTestSource(t, epochs, 20)
	if err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 12, epochs[12].ChainHash)); err != nil {
		t.Fatalf("continuous chain should verify: %v", err)
	}
}

// A link that does not follow its predecessor is conclusive: the chain hash is a
// hash of the previous chain hash, so a mismatch is two incompatible histories.
func TestBrokenLinkIsFork(t *testing.T) {
	epochs := buildChain(1, 20)
	epochs[8].PrevChainHash = hx(200)
	epochs[8].ChainHash = chainHash(epochs[8].PrevChainHash, epochs[8].TreeHash)
	s := newTestSource(t, epochs, 20)

	err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 12, epochs[12].ChainHash))

	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError, got %v", err)
	}
	if !strings.Contains(fe.Reason, "epoch 8") {
		t.Errorf("reason should name the epoch, got %q", fe.Reason)
	}
}

// An epoch whose own chain hash does not match its inputs is equally conclusive.
func TestSelfInconsistentEpochIsFork(t *testing.T) {
	epochs := buildChain(1, 20)
	epochs[9].ChainHash = hx(123) // no longer SHA-256(prev||tree)
	epochs[10].PrevChainHash = hx(123)
	epochs[10].ChainHash = chainHash(hx(123), epochs[10].TreeHash)
	s := newTestSource(t, epochs, 20)

	var fe *source.ForkError
	if err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 12, epochs[12].ChainHash)); !errors.As(err, &fe) {
		t.Fatalf("want ForkError, got %v", err)
	}
}

func TestTipDisagreeingWithWalkIsFork(t *testing.T) {
	epochs := buildChain(1, 20)
	s := newTestSource(t, epochs, 20)

	var fe *source.ForkError
	if err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 12, hx(250))); !errors.As(err, &fe) {
		t.Fatalf("want ForkError when the tip is not where the walk lands, got %v", err)
	}
}

// A missing epoch means we could not read the history, not that Proton rewrote
// it. It must withhold without accusing.
func TestMissingEpochWithholdsWithoutAccusing(t *testing.T) {
	epochs := buildChain(1, 20)
	delete(epochs, 8)
	s := newTestSource(t, epochs, 20)

	err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 12, epochs[12].ChainHash))
	if err == nil {
		t.Fatal("must withhold")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("an unreadable epoch must not be recorded as a fork")
	}
}

func TestExcessiveGapIsNotAFork(t *testing.T) {
	epochs := buildChain(1, 200)
	s := newTestSource(t, epochs, 200)
	s.cfg.MaxEpochsPerRound = 3

	err := s.VerifyConsistency(context.Background(),
		head(t, 5, epochs[5].ChainHash), head(t, 100, epochs[100].ChainHash))
	if err == nil {
		t.Fatal("should withhold when too far behind")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("being behind must not be recorded as a fork")
	}
}

// Catch-up must converge rather than repeatedly attempting one huge walk.
func TestFetchStepsForwardWhenFarBehind(t *testing.T) {
	epochs := buildChain(1, 200)
	s := newTestSource(t, epochs, 200)
	s.cfg.MaxEpochsPerRound = 10

	// Certificate verification is not exercised here: these synthetic epochs
	// carry no certificate, so Fetch is driven through the stepping path only.
	prev := head(t, 100, epochs[100].ChainHash)
	got, err := s.stepTowards(context.Background(), prev, epochs[200])
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 110 {
		t.Fatalf("want intermediate head at 110, got %d", got.Size)
	}
	if err := s.VerifyConsistency(context.Background(), prev, got); err != nil {
		t.Fatalf("the intermediate step must verify: %v", err)
	}
}

func TestFirstObservationPins(t *testing.T) {
	epochs := buildChain(1, 20)
	s := newTestSource(t, epochs, 20)
	if err := s.VerifyConsistency(context.Background(), nil, head(t, 12, epochs[12].ChainHash)); err != nil {
		t.Fatalf("first observation should pin: %v", err)
	}
}
