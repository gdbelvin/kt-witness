// Package c2sp adapts any log that serves c2sp.org/tlog-checkpoint checkpoints
// and c2sp.org/tlog-tiles tiles.
//
// Consistency is proven the strong way: we fetch tiles for the NEW tree and let
// tlog.TileHashReader validate every tile against the new root hash, then
// compute and check a consistency proof from our previously witnessed size. We
// never ask the log to hand us a proof it could have fabricated — the proof is
// computed locally from tile data that is itself bound to the signed root.
package c2sp

import (
	"context"
	"fmt"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Source witnesses one tlog-tiles log.
type Source struct {
	origin   string
	policy   torchwood.Policy
	fetcher  *torchwood.TileFetcher
	verifier note.Verifier
}

// Config describes one log to witness.
type Config struct {
	// Origin is the expected checkpoint origin line. A checkpoint whose origin
	// differs is rejected even if correctly signed.
	Origin string

	// BaseURL serves both "checkpoint" and "tile/...".
	BaseURL string

	// VKey is the log's note verifier key, in name+keyid+base64 form.
	VKey string
}

func New(cfg Config) (*Source, error) {
	v, err := note.NewVerifier(cfg.VKey)
	if err != nil {
		return nil, fmt.Errorf("c2sp: parse vkey for %s: %w", cfg.Origin, err)
	}
	f, err := torchwood.NewTileFetcher(cfg.BaseURL,
		torchwood.WithUserAgent("kt-witness/0.1 (+https://github.com/gdbsecurity/kt-witness)"))
	if err != nil {
		return nil, fmt.Errorf("c2sp: tile fetcher for %s: %w", cfg.Origin, err)
	}
	return &Source{
		origin:   cfg.Origin,
		verifier: v,
		fetcher:  f,
		// Both the origin and the log's own signature must check out.
		policy: torchwood.ThresholdPolicy(2,
			torchwood.OriginPolicy(cfg.Origin),
			torchwood.SingleVerifierPolicy(v),
		),
	}, nil
}

func (s *Source) Origin() string    { return s.origin }
func (s *Source) Tier() source.Tier { return source.TierA }

// DerivedHead is false: the head is carried in a note the log itself signed, so
// a regression or split view is the log contradicting its own signature.
func (s *Source) DerivedHead() bool { return false }

// Fetch ignores prev: a checkpoint is cheap and a consistency proof over any
// gap is computed locally from tiles, so there is no need to step forward.
func (s *Source) Fetch(ctx context.Context, _ *source.Head) (*source.Head, error) {
	raw, err := s.fetcher.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("c2sp: fetch checkpoint: %w", err)
	}
	fetchedAt := time.Now()

	// Verifies the log's own signature and the origin line. Other signatures
	// present (other witnesses' cosignatures) are carried through unverified.
	cp, n, err := torchwood.VerifyCheckpoint(raw, s.policy)
	if err != nil {
		return nil, fmt.Errorf("c2sp: verify checkpoint: %w", err)
	}

	return &source.Head{
		Origin:    cp.Origin,
		Size:      cp.N,
		Hash:      cp.Hash,
		Signed:    raw,
		Note:      n,
		FetchedAt: fetchedAt,
	}, nil
}

func (s *Source) VerifyConsistency(ctx context.Context, prev, next *source.Head) error {
	// TileHashReader validates every tile it returns against next.Hash, so any
	// hash it yields is already bound to the signed root.
	tree := tlog.Tree{N: next.Size, Hash: next.Hash}
	hr := torchwood.TileHashReaderWithContext(ctx, tree, s.fetcher)

	if prev == nil {
		// Trust on first use. We cannot prove anything about history we never
		// saw, but we can confirm the log can actually produce tile data
		// consistent with the root it just signed — which catches a log
		// publishing a root it cannot back with real entries.
		if next.Size == 0 {
			return nil
		}
		if _, err := tlog.TreeHash(next.Size, hr); err != nil {
			return fmt.Errorf("c2sp: first-use tile check failed: %w", err)
		}
		return nil
	}

	proof, err := tlog.ProveTree(next.Size, prev.Size, hr)
	if err != nil {
		// The log could not supply tiles backing its own signed root. That is
		// suspicious but not proof of a fork, so it is a plain error and the
		// cosignature is withheld.
		return fmt.Errorf("c2sp: build consistency proof %d->%d: %w", prev.Size, next.Size, err)
	}

	if err := tlog.CheckTree(proof, next.Size, next.Hash, prev.Size, prev.Hash); err != nil {
		// The log signed a root that is NOT an append-only extension of one it
		// previously signed. That is conclusive.
		return &source.ForkError{
			Origin: s.origin,
			Reason: fmt.Sprintf("consistency proof %d->%d failed: tree at size %d (root %x) does not extend witnessed size %d (root %x): %v",
				prev.Size, next.Size, next.Size, next.Hash[:], prev.Size, prev.Hash[:], err),
			Prev: prev, Next: next,
		}
	}
	return nil
}
