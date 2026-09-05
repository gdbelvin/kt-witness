// Package c2sp adapts any log that serves c2sp.org/tlog-checkpoint checkpoints
// and tiles, whether laid out per c2sp.org/tlog-tiles or per the older
// go.dev/design/25530-sumdb scheme the Go checksum database still uses.
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
	"log/slog"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
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

	// tilePath and splitEntries follow Config.TileLayout; see New.
	tilePath     func(tlog.Tile) string
	splitEntries func([]byte) ([][]byte, error)
}

// Config describes one log to witness.
type Config struct {
	// Origin is the expected checkpoint origin line. A checkpoint whose origin
	// differs is rejected even if correctly signed.
	Origin string

	// BaseURL serves both the checkpoint (see CheckpointPath) and "tile/...".
	BaseURL string

	// VKey is the log's note verifier key, in name+keyid+base64 form. It is
	// used only when Verifier is nil.
	VKey string

	// Verifier overrides VKey, for logs whose checkpoint signature the note
	// package cannot parse by itself. Static CT logs sign with the RFC 6962
	// tree head signature rather than Ed25519; see internal/staticct.
	Verifier note.Verifier

	// MaxAuditEntries bounds how large a log may be before per-entry audits are
	// refused. Each verified index becomes a stored record, so switching entry
	// verification on for a log with tens of millions of entries would turn the
	// witness database into a copy of the log's index. Defaults to
	// defaultMaxAuditEntries.
	MaxAuditEntries int64

	// Audits, if set, records each entry index whose contents have been checked
	// against the signed tree, so construction coverage can be measured.
	Audits source.AuditRecorder

	// VerifyEntries additionally checks that each newly added leaf is the hash
	// of an entry the log publishes. For an append-only entry log that is the
	// construction check; it costs one data tile read per 256 new entries.
	VerifyEntries bool

	// CheckpointPath is the path under BaseURL that serves the signed
	// checkpoint. It defaults to "checkpoint", which is what
	// c2sp.org/tlog-checkpoint specifies, but predates-the-spec deployments
	// differ: the Go checksum database serves the same signed note at "latest".
	// The endpoint name is transport, not trust — what is fetched is still a
	// note the log signed — so a log that only moved the path needs no other
	// concession.
	CheckpointPath string

	// TileLayout selects how tile coordinates become URLs. The empty string
	// and "tlog-tiles" mean the flat c2sp.org/tlog-tiles scheme; "sumdb" means
	// the older go.dev/design/25530-sumdb scheme, which splits N into "xNNN"
	// path elements and suffixes partial tiles with ".p/<W>". The tree maths is
	// identical either way, so this is purely how the same tiles are addressed.
	TileLayout string
}

// sumDBLayout names the go.dev/design/25530-sumdb tile scheme.
const sumDBLayout = "sumdb"

func New(cfg Config) (*Source, error) {
	if cfg.CheckpointPath == "" {
		cfg.CheckpointPath = "checkpoint"
	}
	v := cfg.Verifier
	if v == nil {
		var err error
		if v, err = note.NewVerifier(cfg.VKey); err != nil {
			return nil, fmt.Errorf("c2sp: parse vkey for %s: %w", cfg.Origin, err)
		}
	}
	// Deliberately no requirement that v.Name() equals cfg.Origin. A checkpoint's
	// origin line and its signer's name are separate things in the note format,
	// and they genuinely differ in the wild: the Go checksum database signs
	// "go.sum database tree" with a key named "sum.golang.org". The policy below
	// pins both independently, which is what actually matters — a checkpoint is
	// accepted only if its origin line is exactly cfg.Origin *and* it carries a
	// signature from v.

	// The tile path function and the data tile framing are two halves of one
	// layout choice, so they are decided together and never mixed: a sumdb data
	// tile parsed with tlog-tiles framing would not fail loudly, it would
	// produce nonsense entries.
	tilePath, splitEntries := torchwood.TilePath, splitTileEntries
	switch cfg.TileLayout {
	case "", "tlog-tiles":
	case sumDBLayout:
		tilePath, splitEntries = tlog.Tile.Path, splitSumDBEntries
	default:
		return nil, fmt.Errorf("c2sp: unknown tile layout %q for %s", cfg.TileLayout, cfg.Origin)
	}
	opts := []torchwood.TileFetcherOption{
		torchwood.WithUserAgent("kt-witness/0.1 (+https://github.com/gdbsecurity/kt-witness)"),
		torchwood.WithTilePath(tilePath),
	}
	f, err := torchwood.NewTileFetcher(cfg.BaseURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("c2sp: tile fetcher for %s: %w", cfg.Origin, err)
	}
	return &Source{
		cfg:          cfg,
		origin:       cfg.Origin,
		tilePath:     tilePath,
		splitEntries: splitEntries,
		verifier:     v,
		fetcher:      f,
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
	raw, err := s.fetcher.ReadEndpoint(ctx, s.cfg.CheckpointPath)
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

		// Level -1 is the data tile in both layouts.
		t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: tileIdx, W: int(tileEnd - tileStart)}
		raw, err := s.fetcher.ReadEndpoint(ctx, s.tilePath(t))
		if err != nil {
			return fmt.Errorf("c2sp: read entries tile %d: %w", tileIdx, err)
		}

		entries, err := s.splitEntries(raw)
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

			// This index is now construction-audited: the entry the log
			// publishes is the one its signed tree commits to at that position.
			// For an append-only entry log that is the whole of the property —
			// there is no mutable map to corrupt.
			if s.cfg.Audits != nil && to <= s.maxAuditEntries() {
				if err := s.cfg.Audits.RecordConstructionAudit(s.origin, i); err != nil {
					return fmt.Errorf("c2sp: recording audit for entry %d: %w", i, err)
				}
				// Counted as a verification like any other, so the rate a
				// dashboard derives covers entry logs rather than silently
				// treating them as idle.
				metrics.Inc("kt_witness_audit_verified_total",
					map[string]string{"origin": s.origin})
			}
		}
		start = tileEnd
	}
	return nil
}

// Backfill publishes the range of history this log has, so coverage has
// something to measure against.
//
// An entry log's published history is simply entries 0..size-1: unlike a
// directory there is no epoch numbering to discover, and nothing to walk. The
// work of actually checking those entries is done by verifyNewEntries.
//
// Only offered when entry verification is switched on. Declaring a range we
// have no intention of auditing would make the coverage denominator real and
// the numerator permanently zero, which reads as a stalled audit rather than an
// absent one.
func (s *Source) Backfill(ctx context.Context, log *slog.Logger) (*source.BackfillResult, error) {
	if !s.cfg.VerifyEntries {
		return nil, fmt.Errorf("c2sp: %s does not verify entries, so it has no construction history to report", s.origin)
	}
	head, err := s.Fetch(ctx, nil)
	if err != nil {
		return nil, err
	}
	if head.Size == 0 {
		return &source.BackfillResult{}, nil
	}
	if lim := s.maxAuditEntries(); head.Size > lim {
		// Declaring a range we will not audit is worse than declaring none: the
		// coverage denominator becomes real while the numerator stays near
		// zero, which reads as a stalled audit rather than an absent one.
		return nil, fmt.Errorf(
			"c2sp: %s has %d entries, above the %d limit for per-entry auditing; "+
				"raise max_audit_entries deliberately if the witness database should hold one record per entry",
			s.origin, head.Size, lim)
	}
	// Verify the whole range now, rather than only declaring it.
	//
	// verifyNewEntries otherwise covers just what arrived since the last
	// observation, so a log we started witnessing at entry 163 would carry a
	// denominator of 163 and a numerator that only ever counted entry 164
	// onward — B+ unreachable not because the history is bad but because nobody
	// ever read it. For an entry log the backwards sweep is simply this.
	if log != nil {
		log.Info("verifying published entries", "origin", s.origin, "entries", head.Size)
	}
	tree := tlog.Tree{N: head.Size, Hash: head.Hash}
	if err := s.verifyNewEntries(ctx, 0, head.Size, tree); err != nil {
		return nil, err
	}
	return &source.BackfillResult{
		From: 0, To: head.Size - 1, Epochs: int(head.Size),
	}, nil
}

// splitSumDBEntries parses a go.dev/design/25530-sumdb data tile, where records
// are newline-terminated blocks separated by a blank line rather than
// length-prefixed. The framing is torchwood's, not ours, so a tile the Go
// checksum database serves and a tile torchwood's own client would accept are
// the same thing by construction.
func splitSumDBEntries(raw []byte) ([][]byte, error) {
	var out [][]byte
	for len(raw) > 0 {
		entry, _, rest, err := torchwood.ReadSumDBEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", len(out), err)
		}
		out = append(out, entry)
		raw = rest
	}
	return out, nil
}

// splitTileEntries parses a tlog-tiles data tile: each record is a two-byte
// big-endian length followed by that many bytes.
func splitTileEntries(raw []byte) ([][]byte, error) {
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

// defaultMaxAuditEntries is the largest log for which per-entry construction
// records are kept by default.
//
// Generous for a key directory and far below a CT log: the 69 CT logs witnessed
// here hold billions of entries between them, and auditing those entry by entry
// is not a tuning question but a different project.
const defaultMaxAuditEntries = 1 << 20

func (s *Source) maxAuditEntries() int64 {
	if s.cfg.MaxAuditEntries > 0 {
		return s.cfg.MaxAuditEntries
	}
	return defaultMaxAuditEntries
}
