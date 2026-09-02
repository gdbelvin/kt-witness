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
	cfg      Config
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

	// VKey is the log's note verifier key, in name+keyid+base64 form. It is
	// used only when Verifier is nil.
	VKey string

	// Verifier overrides VKey, for logs whose checkpoint signature the note
	// package cannot parse by itself. Static CT logs sign with the RFC 6962
	// tree head signature rather than Ed25519; see internal/staticct.
	Verifier note.Verifier

	// VerifyEntries additionally checks that each newly added leaf is the hash
	// of an entry the log publishes. For an append-only entry log that is the
	// construction check; it costs one data tile read per 256 new entries.
	VerifyEntries bool
}

func New(cfg Config) (*Source, error) {
	v := cfg.Verifier
	if v == nil {
		var err error
		if v, err = note.NewVerifier(cfg.VKey); err != nil {
			return nil, fmt.Errorf("c2sp: parse vkey for %s: %w", cfg.Origin, err)
		}
	}
	if v.Name() != cfg.Origin {
		// The policy checks the origin line and the signature independently, so
		// a verifier named differently from the configured origin would let a
		// correctly signed checkpoint be witnessed under the wrong name.
		return nil, fmt.Errorf("c2sp: verifier is named %q but the origin is %q", v.Name(), cfg.Origin)
	}
	f, err := torchwood.NewTileFetcher(cfg.BaseURL,
		torchwood.WithUserAgent("kt-witness/0.1 (+https://github.com/gdbsecurity/kt-witness)"))
	if err != nil {
		return nil, fmt.Errorf("c2sp: tile fetcher for %s: %w", cfg.Origin, err)
	}
	return &Source{
		cfg:      cfg,
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

func (s *Source) Origin() string { return s.origin }

// Tier is B when entries are verified.
//
// For a mutable directory, tier B means replaying construction proofs. For an
// append-only entry log there is no map to corrupt, so the equivalent claim is
// narrower and fully achieved: the tree grew append-only, and every leaf it grew
// by is the hash of an entry the log publishes. A directory *derived* from those
// entries would be a separate question, and this does not speak to it.
func (s *Source) Tier() source.Tier {
	if s.cfg.VerifyEntries {
		return source.TierB
	}
	return source.TierA
}

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
		if s.cfg.VerifyEntries {
			return s.verifyNewEntries(ctx, 0, next.Size, tree)
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

	// The proof shows the tree grew append-only; this shows what it grew by.
	if s.cfg.VerifyEntries {
		if err := s.verifyNewEntries(ctx, prev.Size, next.Size, tree); err != nil {
			return err
		}
	}
	return nil
}

// --- entry verification ----------------------------------------------------

// verifyNewEntries checks that every leaf added between two snapshots is the
// hash of an entry the log actually publishes.
//
// A consistency proof shows the new tree extends the old one. It says nothing
// about what the added leaves *are* — a log could extend its tree with hashes
// backed by no published entry at all, and every proof would still verify.
// Reading the entries and hashing them closes that gap.
//
// The leaf hashes are read through the tile hash reader, so they arrive already
// bound to the root the log signed. Comparing against tiles fetched directly
// would only prove the server is consistent with itself.
//
// For an append-only entry log this is the construction check: there is no
// mutable map to corrupt, so "the tree is built from the published entries" is
// the whole of it. A directory derived from these entries would be a separate
// question.
func (s *Source) verifyNewEntries(ctx context.Context, from, to int64, tree tlog.Tree) error {
	if to <= from {
		return nil
	}
	hr := torchwood.TileHashReaderWithContext(ctx, tree, s.fetcher)

	const dataTileWidth = torchwood.TileWidth
	for start := from; start < to; {
		tileIdx := start / dataTileWidth
		tileStart := tileIdx * dataTileWidth
		tileEnd := tileStart + dataTileWidth
		if tileEnd > to {
			tileEnd = to
		}

		// Level -1 is the data tile in c2sp.org/tlog-tiles.
		t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: tileIdx, W: int(tileEnd - tileStart)}
		raw, err := s.fetcher.ReadEndpoint(ctx, torchwood.TilePath(t))
		if err != nil {
			return fmt.Errorf("c2sp: read entries tile %d: %w", tileIdx, err)
		}

		entries, err := splitEntries(raw)
		if err != nil {
			return fmt.Errorf("c2sp: entries tile %d: %w", tileIdx, err)
		}
		if int64(len(entries)) < tileEnd-tileStart {
			return fmt.Errorf("c2sp: entries tile %d holds %d entries, need %d",
				tileIdx, len(entries), tileEnd-tileStart)
		}

		// Only the leaves in [start, tileEnd) are new to us.
		var indexes []int64
		for i := start; i < tileEnd; i++ {
			indexes = append(indexes, tlog.StoredHashIndex(0, i))
		}
		want, err := hr.ReadHashes(indexes)
		if err != nil {
			return fmt.Errorf("c2sp: read leaf hashes %d..%d: %w", start, tileEnd, err)
		}

		for i := start; i < tileEnd; i++ {
			got := tlog.RecordHash(entries[i-tileStart])
			if got != want[i-start] {
				// The log published an entry that is not the one its own tree
				// commits to at that position. Conclusive: both sides are bound
				// to a root it signed.
				return &source.ForkError{
					Origin: s.origin,
					Reason: fmt.Sprintf(
						"entry %d does not match the tree: published entry hashes to %x, but the signed tree holds %x",
						i, got[:], want[i-start][:]),
				}
			}
		}
		start = tileEnd
	}
	return nil
}

// splitEntries parses a tlog-tiles data tile: each record is a two-byte
// big-endian length followed by that many bytes.
func splitEntries(raw []byte) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < len(raw); {
		if i+2 > len(raw) {
			return nil, fmt.Errorf("truncated length prefix at offset %d", i)
		}
		n := int(raw[i])<<8 | int(raw[i+1])
		i += 2
		if i+n > len(raw) {
			return nil, fmt.Errorf("entry at offset %d claims %d bytes, past the end", i, n)
		}
		out = append(out, raw[i:i+n])
		i += n
	}
	return out, nil
}
