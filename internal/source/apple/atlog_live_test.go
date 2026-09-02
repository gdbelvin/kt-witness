package apple

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/pbwire"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/tlog"
)

// Apple's Transparency (AT) log for Private Cloud Compute, discovered through
// the KT init bag at
//
//	https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch
//
// which lists at-researcher-log-inclusion-proof — an endpoint this project had
// previously recorded as not existing. It does, and it works; what does not
// exist is at-researcher-log-leaves-for-revision, which is declared in Apple's
// proto but absent from the live bag. That is the explanation for the 404s.
//
// These identifiers come from at_researcher/list_trees, which returns the same
// three trees for every application value:
//
//	7618469013902052   PER_APPLICATION_TREE  PRIVATE_CLOUD_COMPUTE
//	5296182921832599   AT_LOG                PRIVATE_CLOUD_COMPUTE
//	410322746470160    TOP_LEVEL_TREE        (shared)
//
// No IDS_MESSAGING tree is listed, which is why iMessage heads remain
// observations: they are visible inside Top-Level Tree leaves, but Apple
// publishes no per-application surface to bind them to.
func atLogSource(t *testing.T) *Source {
	t.Helper()
	s, err := New(Config{
		Origin: "apple.com/at/pcc", TreeID: ATLogTreeID, PublicKeyDER: ATLogPublicKey,
		LogType: LogTypeATLog, Application: ApplicationPCC,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func varintField(b []byte, field int, v uint64) []byte {
	b = pbwire.AppendTag(b, field, 0)
	return pbwire.AppendVarint(b, v)
}

// TestLiveATLogInclusion is the acceptance test for Apple inclusion proofs.
//
// It reads a leaf from the log, asks for a proof by the SHA-256 of that leaf's
// raw data, and checks the proof against a log head verified under the AT log's
// own signing key. Apple hashes RFC 6962 style — leaf SHA-256(0x00‖data), node
// SHA-256(0x01‖left‖right), per MerkleTree.swift in apple/security-pcc — so the
// standard implementation checks it directly.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveATLogInclusion(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := atLogSource(t)
	ctx := context.Background()

	// log_leaves: version=1 treeId=2 startIndex=4 endIndex=5 (exclusive)
	// startMergeGroup=7 endMergeGroup=8. The merge-group bounds are required:
	// without them the server returns HTTP 200 and an empty list.
	r := varintField(nil, 1, requestVersion)
	r = varintField(r, 2, ATLogTreeID)
	r = varintField(r, 4, 7)
	r = varintField(r, 5, 8)
	r = varintField(r, 7, 0)
	r = varintField(r, 8, 1)
	body, err := s.post(ctx, "log_leaves", r)
	if err != nil {
		t.Fatalf("log_leaves: %v", err)
	}
	leaves := pbwire.Parse(body)[3]
	if len(leaves) == 0 {
		t.Fatal("log_leaves returned no leaves")
	}
	raw := pbwire.First(pbwire.Parse(leaves[0]), 5)
	if len(raw) == 0 {
		t.Fatal("leaf has no raw data to identify it by")
	}
	id := sha256.Sum256(raw)

	// ATLogInclusionProofRequest: version=1, application=2, identifier=3.
	// Application must be PRIVATE_CLOUD_COMPUTE (5); IDS_MESSAGING (1) is
	// rejected with INVALID_REQUEST, which is the whole story for iMessage.
	ir := varintField(nil, 1, requestVersion)
	ir = varintField(ir, 2, ApplicationPCC)
	ir = pbwire.AppendTag(ir, 3, 2)
	ir = pbwire.AppendVarint(ir, uint64(len(id)))
	ir = append(ir, id[:]...)

	pb, err := s.post(ctx, "log_inclusion_proof", ir)
	if err != nil {
		t.Fatalf("log_inclusion_proof: %v", err)
	}
	m := pbwire.Parse(pb)
	if got := pbwire.Uint64(m, 1); got != statusOK {
		t.Fatalf("inclusion proof status %d, want OK", got)
	}
	if len(m[3]) == 0 {
		t.Fatal("status was OK but no proof was returned")
	}

	// The root is taken from a head we verify ourselves, never from the proof.
	st, err := s.verifySignedHead(pbwire.First(m, 2))
	if err != nil {
		t.Fatalf("the signed head carrying the proof does not verify: %v", err)
	}

	entry := pbwire.Parse(m[3][0])
	pos := pbwire.Uint64(entry, 3)
	nodeBytes := pbwire.First(entry, 2)
	path := make([]tlog.Hash, 0, len(entry[4]))
	for _, h := range entry[4] {
		if len(h) != 32 {
			t.Fatalf("path hash is %d bytes, want 32", len(h))
		}
		var x tlog.Hash
		copy(x[:], h)
		path = append(path, x)
	}
	t.Logf("AT log revision %d, size %d; leaf %d, %d-hash path", st.revision, st.size, pos, len(path))

	if err := tlog.CheckRecord(path, int64(st.size), st.root, int64(pos), tlog.RecordHash(nodeBytes)); err != nil {
		t.Fatalf("inclusion proof does not verify: %v", err)
	}
	// Negative control: a check that passes on mutated input checks nothing.
	if tlog.CheckRecord(path, int64(st.size), st.root, int64(pos),
		tlog.RecordHash(append(append([]byte{}, nodeBytes...), 0))) == nil {
		t.Fatal("a corrupted leaf still verified")
	}
}

// TestLiveATLogConsistency establishes that the AT log is append-only provable
// too, which is what would let it be witnessed rather than merely read.
//
// The consistency request must name logType=AT_LOG and
// application=PRIVATE_CLOUD_COMPUTE. The Top-Level Tree path in this package
// hardcodes logType=TOP_LEVEL_TREE, so it silently answers about the wrong
// tree if reused here — which is exactly the sort of thing that makes a proof
// look like it passed.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveATLogConsistency(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := atLogSource(t)
	ctx := context.Background()

	head, err := s.head(ctx, latestRevision)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	prev, err := s.head(ctx, int64(head.revision)-50)
	if err != nil {
		t.Fatalf("earlier head: %v", err)
	}

	body, err := s.postTo(ctx, s.clientBase(), consistencyEndpoint,
		s.consistencyRequest(prev.revision, head.revision))
	if err != nil {
		t.Fatalf("consistency_proof: %v", err)
	}
	m := pbwire.Parse(body)
	if got := pbwire.Uint64(m, 1); got != statusOK {
		t.Fatalf("consistency status %d, want OK", got)
	}
	if len(m[3]) == 0 {
		t.Fatal("status was OK but no consistency proof was returned")
	}
	resp := pbwire.Parse(m[3][0])
	end, err := s.verifySignedHead(pbwire.First(resp, 4))
	if err != nil {
		t.Fatalf("end head does not verify: %v", err)
	}
	t.Logf("consistency %d -> %d: %d hashes, end head verifies at size %d",
		prev.revision, head.revision, len(resp[5]), end.size)
	if end.size < prev.size {
		t.Errorf("end head is smaller than the start head")
	}
}

// TestLiveATLogAsSource exercises the AT log through the Source interface the
// witness core actually calls, rather than through its pieces. This is what
// makes it a witnessable origin rather than something we can merely read.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveATLogAsSource(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s := atLogSource(t)
	ctx := context.Background()

	head, err := s.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Logf("%s: size %d, root %x", head.Origin, head.Size, head.Hash[:])
	if head.Size == 0 {
		t.Fatal("fetched the empty tree — revision was probably not sent explicitly")
	}

	// An earlier head of the same log, to prove append-only across a real gap.
	older, err := s.head(ctx, int64(s.latest.revision)-100)
	if err != nil {
		t.Fatalf("earlier head: %v", err)
	}
	prev := &source.Head{Origin: head.Origin, Size: int64(older.size), Hash: older.root}

	if err := s.VerifyConsistency(ctx, prev, head); err != nil {
		t.Fatalf("VerifyConsistency %d -> %d: %v", prev.Size, head.Size, err)
	}
	t.Logf("append-only proven from size %d to %d", prev.Size, head.Size)

	// Negative control: a root that was never this log's must not verify.
	bogus := *prev
	bogus.Hash[0] ^= 0x01
	if err := s.VerifyConsistency(ctx, &bogus, head); err == nil {
		t.Fatal("consistency verified against a root this log never had")
	}
}
