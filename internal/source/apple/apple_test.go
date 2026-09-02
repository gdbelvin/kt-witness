package apple

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/pbwire"
	"github.com/gdbsecurity/kt-witness/internal/source"
)

func newSource(t *testing.T) *Source {
	t.Helper()
	s, err := New(Config{Origin: "apple.com/kt/top-level-tree"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The request encoding is load-bearing in an unusual way: getting it subtly
// wrong yields a valid, correctly signed answer about the wrong thing.
func TestLogHeadRequestEncoding(t *testing.T) {
	s := newSource(t)
	got := hex.EncodeToString(s.logHeadRequest())
	const want = "08031090deafacfba55d20ffffffffffffffffff01"
	if got != want {
		t.Fatalf("request encoding drifted:\n got %s\nwant %s", got, want)
	}

	// Field 4 must be present and be the 10-byte encoding of -1. Omitting it
	// defaults to revision 0, for which the server returns the empty tree.
	m := pbwire.Parse(s.logHeadRequest())
	if len(m[4]) == 0 {
		t.Fatal("revision field missing: the server would answer with the empty tree head")
	}
	if pbwire.Uint64(m, 2) != TopLevelTreeID {
		t.Fatalf("wrong tree id: %d", pbwire.Uint64(m, 2))
	}
}

func TestPinnedKeyMatchesItsAdvertisedHash(t *testing.T) {
	s := newSource(t)
	// Apple identifies its signing key by SHA-256 of the DER SPKI, and that hash
	// appears in every signature. If our pinned key did not hash to the value
	// Apple advertises, every head would be rejected.
	const want = "2508cfb4b3cc106367d1393ada183e2c1df7dd010dfc89b5f929c48b796ce608"
	if got := hex.EncodeToString(s.keyID[:]); got != want {
		t.Fatalf("pinned key hashes to %s, but Apple signs with %s", got, want)
	}
}

// A captured production response, so signature verification is exercised without
// the network — and so a change to the parsing or preimage fails loudly.
const liveLogHeadResponse = "080122b3010a4208d794f194b63110cda2641a20027b7d7e433a63089e854" +
	"76cccf2669dd4728cc474038c20bb435f86aa96ef3c20bde43b28033890deafacfba55d40b4fff7fc853" +
	"4126d0a47304502205f04b561796fe82a422f289f45f90ef3b57c1752ba065ea57cd5ac60ce2a0002022" +
	"100ac8855644c43ee5940facab740bab0d1cd6509aa92b8e8806f3a7e6adb3c53ad12202508cfb4b3cc1" +
	"06367d1393ada183e2c1df7dd010dfc89b5f929c48b796ce6081801"

func captured(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(liveLogHeadResponse)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifiesCapturedProductionHead(t *testing.T) {
	s := newSource(t)
	st, err := s.verifyHeadResponse(captured(t))
	if err != nil {
		t.Fatalf("a genuine signed head should verify: %v", err)
	}
	if st.size != 1642829 {
		t.Fatalf("want tree size 1642829, got %d", st.size)
	}
	if st.revision != 979517 {
		t.Fatalf("want revision 979517, got %d", st.revision)
	}
	const wantRoot = "027b7d7e433a63089e85476cccf2669dd4728cc474038c20bb435f86aa96ef3c"
	if got := hex.EncodeToString(st.root[:]); got != wantRoot {
		t.Fatalf("root %s, want %s", got, wantRoot)
	}
}

// Flipping a byte of the signed payload must break verification, or the check is
// decorative.
func TestTamperedHeadIsRejected(t *testing.T) {
	s := newSource(t)
	body := captured(t)

	// The root hash sits well inside the signed object; any flip will do.
	for i := range body {
		if body[i] == 0x7b {
			body[i] ^= 0xFF
			break
		}
	}
	if _, err := s.verifyHeadResponse(body); err == nil {
		t.Fatal("a modified tree head must not verify")
	}
}

func TestHeadSignedByAnotherKeyIsRejected(t *testing.T) {
	// The PCC trees use a different key; a head signed by it must not be
	// accepted for the Top-Level Tree.
	const pccKey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004c4ad1582c97e1a89" +
		"371e10051e815b87abdb1473394a4ddae7ff0892a50be59b105547a637f0ca875bd8927f810169ca5e" +
		"6fa1fe0f2819aeadd76a9a909fc31e"
	s, err := New(Config{Origin: "x", PublicKeyDER: pccKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.verifyHeadResponse(captured(t))
	if err == nil || !strings.Contains(err.Error(), "not the pinned key") {
		t.Fatalf("want a pinned-key mismatch, got %v", err)
	}
}

func TestRejectsMalformedResponses(t *testing.T) {
	s := newSource(t)
	for name, body := range map[string][]byte{
		"empty":     {},
		"garbage":   []byte{0xff, 0xff, 0xff},
		"truncated": captured(t)[:20],
	} {
		if _, err := s.verifyHeadResponse(body); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// Live: the whole path, against Apple. Skipped unless KT_WITNESS_LIVE=1.
func TestLiveFetch(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := newSource(t)
	head, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("live fetch: %v", err)
	}
	if head.Size == 0 {
		t.Fatal("empty tree head accepted")
	}
	t.Logf("Apple top-level tree: size=%d root=%x", head.Size, head.Hash)
}

func TestLogLeavesRequestIncludesMergeGroups(t *testing.T) {
	s := newSource(t)
	m := pbwire.Parse(s.logLeavesRequest(100, 200))

	// Omitting the merge-group fields returns HTTP 200 with an empty leaf list,
	// which is indistinguishable from a log with no leaves. They must be present.
	if len(m[7]) == 0 || len(m[8]) == 0 {
		t.Fatal("merge group bounds missing: the server would return an empty list, not an error")
	}
	if pbwire.Uint64(m, 4) != 100 || pbwire.Uint64(m, 5) != 200 {
		t.Fatalf("index range wrong: %d..%d", pbwire.Uint64(m, 4), pbwire.Uint64(m, 5))
	}
	if pbwire.Uint64(m, 2) != TopLevelTreeID {
		t.Fatal("wrong tree id")
	}
}

// Live: the only public route to iMessage's Key Transparency state.
func TestLiveScanFindsIMessage(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := newSource(t)
	heads, err := s.ScanApplications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byApp := map[string]int{}
	var ids []string
	for _, h := range heads {
		name := h.Name
		if name == "" {
			name = "app-" + hex.EncodeToString([]byte{byte(h.Application)})
		}
		byApp[name]++
		if h.Name == "IDS_MESSAGING" {
			ids = append(ids, hex.EncodeToString(h.RootHash)[:16])
			t.Logf("IDS_MESSAGING tree=%d logSize=%d revision=%d root=%x...",
				h.TreeID, h.LogSize, h.Revision, h.RootHash[:8])
		}
	}
	t.Logf("applications seen in %d leaves: %v", len(heads), byApp)
	if len(ids) == 0 {
		t.Fatal("no IDS_MESSAGING heads found; the scan window may be too small")
	}
}

// The tier-A claim, end to end against production: fetch a head, wait for the
// tree to advance, then prove the new head extends the old one.
func TestLiveConsistency(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := newSource(t)
	ctx := context.Background()

	// An earlier revision gives a genuine gap to prove across without waiting.
	cur, err := s.head(ctx, latestRevision)
	if err != nil {
		t.Fatal(err)
	}
	older, err := s.head(ctx, int64(cur.revision-20))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("proving %d (rev %d) -> %d (rev %d)", older.size, older.revision, cur.size, cur.revision)

	prev := &source.Head{Origin: s.cfg.Origin, Size: int64(older.size), Hash: older.root}
	next := &source.Head{Origin: s.cfg.Origin, Size: int64(cur.size), Hash: cur.root}
	s.latest = cur

	if err := s.VerifyConsistency(ctx, prev, next); err != nil {
		t.Fatalf("a genuine extension should verify: %v", err)
	}
	t.Log("consistency proven: Apple's tree is append-only across these observations")

	// And a root that is not what the proof implies must be refused.
	bogus := *next
	bogus.Hash[0] ^= 0xFF
	if err := s.VerifyConsistency(ctx, prev, &bogus); err == nil {
		t.Fatal("a head the proof does not reach must be rejected")
	}
}
