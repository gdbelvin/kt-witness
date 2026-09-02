// Package source defines the interface every witnessed log adapter implements.
//
// The witness core is protocol-agnostic: all KT-specific cryptography lives
// behind a Source. A Source is responsible for producing a canonical tree head
// and for proving that a new head extends the previously witnessed one.
package source

import (
	"context"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Tier is the assurance level a Source can attest to. Published assertions must
// always name their tier: conflating them is how a witness overpromises.
type Tier int

const (
	// TierA attests only that the sequence of signed roots observed is
	// append-only. This is split-view/equivocation detection.
	TierA Tier = iota + 1

	// TierAPlus additionally verifies root-chain continuity across the log's
	// entire published history, where the log's layout makes that possible
	// from metadata alone.
	TierAPlus

	// TierB additionally replays the log's own construction proofs to attest
	// the tree is correctly built.
	TierB

	// TierSignedHead is weaker than TierA: heads are authentic (carried by the
	// log's own signature) and equivocation at a given size is detectable, but
	// append-only between observations is NOT proven, because the deployment
	// exposes no consistency proof we can check. Named separately so a
	// published assertion cannot silently claim more than was verified.
	TierSignedHead
)

func (t Tier) String() string {
	switch t {
	case TierA:
		return "A (checkpoint witness)"
	case TierAPlus:
		return "A+ (root-chain continuity)"
	case TierB:
		return "B (construction audit)"
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
