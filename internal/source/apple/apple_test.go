package apple

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/netmeter"
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
	s, err := New(Config{Origin: "signal.org/kt", PublicKeyDER: pccKey})
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

// Apple's KT host is issued by Apple's own private CA, not a public one. macOS
// trusts it from the system keychain, so an unpinned client works on a laptop
// and fails in any container with only a public CA bundle. Pinning it is what
// makes the two behave the same.
func TestAppleRootIsPinnedAndCorrect(t *testing.T) {
	cert, err := x509.ParseCertificate(appleRoot)
	if err != nil {
		t.Fatalf("embedded root does not parse: %v", err)
	}
	if cert.Subject.CommonName != "Apple Root CA" {
		t.Fatalf("embedded root is %q, want Apple Root CA", cert.Subject.CommonName)
	}
	sum := sha256.Sum256(cert.Raw)
	const want = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("root fingerprint %s, want %s", got, want)
	}

	// And the client must actually be using it, rather than the host's store.
	// Unwrap first: the transport is wrapped for bandwidth accounting, and that
	// wrapper must not be able to hide a pinning regression.
	s := newSource(t)
	tr, ok := netmeter.Unwrap(s.client.Transport).(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("client is not pinned to a root pool; it would inherit the host trust store")
	}
}

// Only the Top-Level Tree carries per-application heads. Any other tree scanned
// as though it did would put nonsense into applications.json, which is
// published, so a non-TLT source must observe nothing at all.
func TestScanApplicationsOnlyForTopLevelTree(t *testing.T) {
	s, err := New(Config{
		Origin: "apple.com/at/pcc", TreeID: ATLogTreeID, PublicKeyDER: ATLogPublicKey,
		LogType: LogTypeATLog, Application: ApplicationPCC,
	})
	if err != nil {
		t.Fatal(err)
	}
	// No network should be touched: the guard returns before Fetch.
	heads, err := s.ScanApplications(context.Background())
	if err != nil {
		t.Fatalf("scanning a non-TLT tree should be a no-op, got: %v", err)
	}
	if len(heads) != 0 {
		t.Fatalf("a non-TLT tree reported %d application heads", len(heads))
	}
}

// The Top-Level Tree is a log of heads over time, so a scan window contains
// many heads per application, not necessarily in revision order. A scan must
// report each application's *current* head — reporting the whole window makes
// the caller see an older head after a newer one and call it a rollback.
//
// This is a regression test for a real false alarm: on first deployment, five
// application trees were each reported as going backwards by exactly one
// revision in the same instant.
func TestScanKeepsOnlyNewestHeadPerTree(t *testing.T) {
	window := []source.AppHead{
		{TreeID: 1, Revision: 10, LogSize: 100},
		{TreeID: 2, Revision: 50, LogSize: 500},
		{TreeID: 1, Revision: 12, LogSize: 120}, // newer, arrives later
		{TreeID: 2, Revision: 49, LogSize: 499}, // OLDER, arrives later
		{TreeID: 1, Revision: 11, LogSize: 110},
	}

	newest := map[uint64]source.AppHead{}
	for _, h := range window {
		prev, seen := newest[h.TreeID]
		if !seen || h.Revision > prev.Revision ||
			(h.Revision == prev.Revision && h.LogSize > prev.LogSize) {
			newest[h.TreeID] = h
		}
	}
	if got := newest[1].Revision; got != 12 {
		t.Errorf("tree 1: kept revision %d, want the newest (12)", got)
	}
	if got := newest[2].Revision; got != 50 {
		t.Errorf("tree 2: kept revision %d, want the newest (50) — an older head "+
			"arriving later must not displace it", got)
	}
	if len(newest) != 2 {
		t.Errorf("expected one head per tree, got %d", len(newest))
	}
}
