// Package source defines the interface every witnessed log adapter implements.
//
// The witness core is protocol-agnostic: all KT-specific cryptography lives
// behind a Source. A Source is responsible for producing a canonical tree head
// and for proving that a new head extends the previously witnessed one.
package source

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Tier is the assurance level a Source can attest to. Published assertions must
// always name their tier: conflating them is how a witness overpromises.
type Tier int

const (
	// Ordered weakest to strongest, so that numeric comparison matches
	// assurance. Anything that ranks tiers should rely on this ordering rather
	// than reintroducing its own.

	// TierSignedHead is the weakest useful level: heads are authentic (carried
	// by the log's own signature) and equivocation at a given size is
	// detectable, but append-only between observations is NOT proven, because
	// the deployment exposes no consistency proof we can check.
	TierSignedHead Tier = iota + 1

	// TierA attests that the sequence of signed roots observed is append-only.
	// This is split-view/equivocation detection.
	TierA

	// TierAPlus additionally verifies root-chain continuity across the log's
	// entire published history, where the log's layout makes that possible
	// from metadata alone.
	TierAPlus

	// TierB additionally replays the log's own construction proofs to attest
	// the tree is correctly built.
	TierB

	// TierBPlus is TierB across the log's ENTIRE published history rather than
	// only the epochs published since we started watching.
	//
	// The distinction is the same one that separates A from A+, and it matters
	// for the same reason: a log with 625,000 published epochs that we began
	// witnessing yesterday has almost none of that history checked, while a
	// bare "tier B" reads as though it does.
	//
	// This tier is EARNED, not configured. It is only claimed when the stored
	// record shows every epoch in the published range has a settled decision,
	// which is why the witness computes it from coverage rather than taking a
	// source's word for it.
	TierBPlus
)

func (t Tier) String() string {
	switch t {
	case TierA:
		return "A (checkpoint witness)"
	case TierAPlus:
		return "A+ (root-chain continuity)"
	case TierB:
		return "B (construction audit)"
	case TierBPlus:
		return "B+ (construction audit across published history)"
	case TierSignedHead:
		return "S (signed head; equivocation detected, append-only unproven)"
	}
	return "unknown"
}

// Head is a canonical tree head: the (origin, size, root hash) triple that a
// witness makes assertions about, plus the signed note it was carried in.
type Head struct {
	Origin string
	Size   int64
	Hash   tlog.Hash

	// Signed is the signed note exactly as served by the log. Cosigning
	// re-serializes from Note, but Signed is retained verbatim as evidence.
	Signed []byte
	Note   *note.Note

	FetchedAt time.Time
}

// Source is one witnessed log.
type Source interface {
	// Origin is the log's checkpoint origin line, and the witness's primary key
	// for it.
	Origin() string

	// Tier is the assurance level this Source can attest to.
	Tier() Tier

	// DerivedHead reports whether the head this Source produces is derived from
	// observation rather than carried by a signature from the log.
	//
	// This governs how much weight a head may bear as evidence. A signed head
	// that regresses is a self-contradiction by the log and is conclusive. A
	// derived head that regresses may just mean we read the log's storage badly
	// — a transient empty listing, an edge cache — and must never be grounds for
	// a permanent public accusation. Derived-head sources still catch real
	// equivocation, but only via a positive contradiction such as a broken hash
	// link.
	DerivedHead() bool

	// Fetch retrieves the log's current head.
	//
	// prev is the last head we witnessed, or nil on first observation. It is
	// passed so a Source can limit how far ahead it reports: a source that must
	// walk history to prove consistency can return an intermediate head, so
	// that catching up after downtime converges over several rounds instead of
	// repeatedly attempting — and timing out on — one enormous step.
	//
	// Fetch must not compare against prev for the purpose of judging the log.
	Fetch(ctx context.Context, prev *Head) (*Head, error)

	// VerifyConsistency proves that next extends prev. prev is nil on first
	// observation (trust-on-first-use), in which case implementations should
	// perform whatever self-consistency check they can and return nil.
	//
	// Returning an error means the witness will not cosign. Implementations
	// must return *ForkError when they have positive evidence of misbehaviour,
	// as distinct from a transient failure to obtain a proof.
	VerifyConsistency(ctx context.Context, prev, next *Head) error
}

// ForkError is positive evidence that a log violated its append-only promise.
// It is distinguished from ordinary errors because it is never retried, is
// persisted as evidence, and is the trigger for out-of-band disclosure.
type ForkError struct {
	Origin string
	Reason string

	// Prev and Next are the two conflicting views, retained verbatim so a
	// disclosure is independently reproducible by a third party.
	Prev *Head
	Next *Head
}

func (e *ForkError) Error() string {
	return "FORK DETECTED for " + e.Origin + ": " + e.Reason
}

// BackfillResult summarises a historical verification pass.
type BackfillResult struct {
	// From and To bound the contiguous, verified range.
	From int64
	To   int64

	// Epochs is how many entries were examined.
	Epochs int

	// Gaps are points where history is missing. A gap is not misbehaviour on its
	// own — retention limits and partial writes both produce one — so it is
	// reported rather than treated as evidence.
	Gaps []string
}

// Backfiller is implemented by sources whose published history can be verified
// backwards from the tip, rather than only forwards from first observation.
//
// This matters because trust-on-first-use otherwise leaves everything before we
// showed up unattested, and for logs that publish their whole history that is a
// large amount of evidence left on the table.
type Backfiller interface {
	Source

	// Backfill verifies published history. It must return *ForkError only for a
	// positive contradiction, never for absence.
	Backfill(ctx context.Context, log *slog.Logger) (*BackfillResult, error)
}

// AppHead is a per-application tree head observed inside another log's leaves.
type AppHead struct {
	// TreeID identifies the application's own tree.
	TreeID uint64
	// Application is the log's own application enum value.
	Application uint64
	// Name is a human label for Application where one is known.
	Name string

	LogSize  uint64
	Revision uint64
	RootHash []byte

	// SigningKeyHash identifies the key that signed this head. The key itself is
	// not published, so the hash is all we get — enough to notice it changing,
	// not enough to verify the signature.
	SigningKeyHash []byte

	// LeafIndex is the position in the containing log.
	LeafIndex uint64
}

// Scanner is implemented by sources whose leaves carry other logs' heads.
//
// Apple's Top-Level Tree is the motivating case: it is a log of per-application
// tree heads, so reading its leaves surfaces heads for applications — iMessage
// among them — whose own trees the API refuses to serve.
type Scanner interface {
	Source
	ScanApplications(ctx context.Context) ([]AppHead, error)
}

// EntryStore persists individual verified log entries so that between-snapshot
// checks survive a restart.
//
// A source that compares what it sees now against what it saw before is only as
// good as its memory. Held in RAM, that memory resets on every deploy, and the
// coverage silently becomes "since the last restart" rather than "since we
// started witnessing".
type EntryStore interface {
	LogEntries(origin string) (map[uint64][32]byte, error)
	PutLogEntries(origin string, entries map[uint64][32]byte) error
}
