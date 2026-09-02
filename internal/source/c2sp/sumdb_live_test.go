package c2sp

import (
	"context"
	"errors"
	"os"
	"testing"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/tlog"
)

// The Go checksum database's well-known verifier key, as shipped in the Go
// toolchain. It is written out here rather than read from the environment
// because a witness that took the key from the thing it is witnessing would be
// witnessing nothing.
const sumGolangOrgKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

// TestLiveSumDB proves the Go checksum database is witnessable through the
// ordinary c2sp adapter once the checkpoint path and the tile layout are
// configured for it.
//
// It matters because sum.golang.org is the single point of trust for the whole
// Go module ecosystem and has few independent witnesses, and because the two
// deviations are exactly the kind that can look configurable on paper and turn
// out not to be: if the older tile scheme were unreadable, every consistency
// proof here would fail rather than quietly weaken.
//
// The earlier size is derived from the tiles of the tree we just fetched, so a
// single observation suffices; the append-only claim still passes through the
// same ProveTree/CheckTree path the witness loop uses. The negative control at
// the end is what gives that teeth — a root the tree never had must be refused.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveSumDB(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	ctx := context.Background()

	s, err := New(Config{
		Origin:         "go.sum database tree",
		BaseURL:        "https://sum.golang.org",
		VKey:           sumGolangOrgKey,
		CheckpointPath: "latest",
		TileLayout:     sumDBLayout,
		// Entry verification is on: over the small window below it is four
		// data tiles, and it is the only part of this test that exercises the
		// sumdb record framing, which differs from tlog-tiles'.
		VerifyEntries: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fetch verifies the signature and the origin line; a checkpoint that
	// failed either would not reach us.
	next, err := s.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("fetch /latest: %v", err)
	}
	if next.Origin != "go.sum database tree" {
		t.Fatalf("origin %q", next.Origin)
	}
	if s.Tier() != source.TierB {
		t.Fatalf("tier %v, want B with entry verification", s.Tier())
	}
	t.Logf("sum.golang.org tree size %d, root %x", next.Size, next.Hash[:])

	// Derive an earlier tree we could have witnessed, from tiles that are
	// themselves bound to the root just signed. TileHashReader validates every
	// tile against next.Hash, so this size/hash pair is one the log has
	// committed to, not one the server merely asserted.
	const window = 1000
	if next.Size <= window {
		t.Fatalf("tree unexpectedly small: %d", next.Size)
	}
	prevSize := next.Size - window
	hr := torchwood.TileHashReaderWithContext(ctx, tlog.Tree{N: next.Size, Hash: next.Hash}, s.fetcher)
	prevHash, err := tlog.TreeHash(prevSize, hr)
	if err != nil {
		t.Fatalf("derive tree hash at %d: %v", prevSize, err)
	}
	prev := &source.Head{Origin: next.Origin, Size: prevSize, Hash: prevHash}

	if err := s.VerifyConsistency(ctx, prev, next); err != nil {
		t.Fatalf("consistency %d->%d: %v", prevSize, next.Size, err)
	}
	t.Logf("append-only %d->%d proven locally from tiles, %d new entries checked against published records",
		prevSize, next.Size, window)

	// Negative control. A check that still passes on mutated input is not
	// checking anything, so demand a refusal for a root the tree never had —
	// and demand it as a ForkError, because a signed root that does not extend
	// a signed root is the accusation this witness exists to make.
	bad := *prev
	bad.Hash[0] ^= 0x01
	err = s.VerifyConsistency(ctx, &bad, next)
	if err == nil {
		t.Fatal("consistency accepted a root the tree never had")
	}
	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("mutated root rejected, but not as a fork: %v", err)
	}
	t.Logf("negative control refused as expected: %v", err)
}
