// Package witness implements the protocol-agnostic verify → cosign → publish
// core.
//
// The single rule this package enforces is: never sign speculatively. Every
// path that cannot positively establish append-only consistency returns an
// error and withholds the cosignature. Withholding is the enforcement
// mechanism; there is no alerting protocol.
package witness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/cosig"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

// Witness cosigns tree heads for a set of logs.
type Witness struct {
	Signer *torchwood.CosignatureSigner
	Store  *store.Store
	Log    *slog.Logger

	// MaxSignDelay bounds how stale our own view may be at the moment we sign.
	// A cosignature carries a timestamp, so signing long after fetching would
	// assert freshness we did not observe.
	MaxSignDelay time.Duration

	// RefreshInterval re-cosigns a log that has not advanced, so our published
	// timestamp stays a liveness signal.
	//
	// We poll far more often than this (to detect equivocation quickly), but a
	// quiet log would otherwise carry an indefinitely ageing cosignature, and a
	// monitor could not distinguish "log is quiet" from "witness is dead". Zero
	// disables refreshing.
	RefreshInterval time.Duration

	// Peers verifies other witnesses' cosignatures on the checkpoints we fetch.
	// Optional: nil simply means we do not read them.
	Peers *cosig.Verifier
}

// Outcome describes what happened for one log in one round.
type Outcome struct {
	Origin   string
	Tier     source.Tier
	Size     int64
	Cosigned bool

	// Unchanged is true when the log had not advanced since our last view.
	Unchanged bool

	// Refreshed is true when we re-cosigned an unchanged log to keep our
	// published timestamp fresh.
	Refreshed bool
}

// ErrStale means we took too long between fetching and signing.
var ErrStale = errors.New("witness: view too stale to cosign")

// Process runs one verify-and-cosign round for a single log.
func (w *Witness) Process(ctx context.Context, src source.Source) (*Outcome, error) {
	origin := src.Origin()

	// A fork is permanent. Check before doing anything else: a log that
	// equivocated and then reverted to a consistent view must not silently
	// regain our cosignature, which is exactly what a brief-equivocation
	// attacker would be counting on.
	forked, err := w.Store.IsForked(origin)
	if err != nil {
		return nil, err
	}
	if forked {
		return nil, &source.ForkError{
			Origin: origin,
			Reason: "log previously forked; cosigning is permanently withheld pending human review",
		}
	}

	prevRec, err := w.Store.Get(origin)
	if err != nil {
		return nil, err
	}

	// refresh means we are re-cosigning a tree we have already attested.
	refresh := false

	var prev *source.Head
	if prevRec != nil {
		prev = &source.Head{
			Origin: prevRec.Origin,
			Size:   prevRec.Size,
			Hash:   prevRec.Hash,
			Signed: prevRec.Cosigned,
		}
	}

	next, err := src.Fetch(ctx, prev)
	if err != nil {
		// A Source can reach a conclusive contradiction while fetching — Signal's
		// auditors disagreeing on the derived root, say. That evidence must be
		// persisted here; nothing downstream does it, and an unrecorded fork is
		// the one outcome this design must never produce.
		var fe *source.ForkError
		if errors.As(err, &fe) {
			return nil, w.fork(fe)
		}
		return nil, fmt.Errorf("witness: fetch %s: %w", origin, err)
	}
	// Read any cosignatures other witnesses have already put on this checkpoint.
	// A witness comparing a log only against its own earlier observations cannot
	// see a consistent split view — from where it stands, nothing is
	// inconsistent. Another witness's signed attestation at the same size can,
	// and it costs no extra request because the bytes are already here.
	w.observePeers(origin, next)

	if next.Origin != origin {
		// A source must never hand us a head for a different log; that would
		// let one log's key authenticate another's origin.
		return nil, fmt.Errorf("witness: %s: fetched head has origin %q", origin, next.Origin)
	}

	// Gate 1: monotonicity and same-size agreement.
	//
	// How much these prove depends on where the head came from. A head the log
	// signed is the log's own statement, so contradicting it is conclusive. A
	// head we derived by reading the log's storage carries our observation error
	// too — a transient empty listing looks exactly like a rollback — so for
	// those sources we withhold and retry instead of accusing. Real equivocation
	// still surfaces, as a positive contradiction during the consistency walk.
	if prev != nil {
		derived := src.DerivedHead()
		switch {
		case next.Size < prev.Size:
			msg := fmt.Sprintf("size went backwards: witnessed %d, now served %d", prev.Size, next.Size)
			if derived {
				return nil, fmt.Errorf("witness: %s: %s; head is derived, not signed, so withholding rather than accusing", origin, msg)
			}

			// A smaller signed head is NOT a contradiction on its own.
			//
			// This once accused the Go checksum database of forking. Both
			// checkpoints carried valid sum.golang.org signatures, and the
			// smaller one turned out to be a prefix of the larger: an older
			// head the log had genuinely published, served again by a lagging
			// CDN replica. A log behind many frontends does that routinely.
			//
			// The log contradicts itself only if the smaller tree is NOT a
			// prefix of the larger. So ask exactly that — does the larger tree
			// extend the smaller? — and let the answer decide, rather than
			// inferring equivocation from ordering.
			if err := src.VerifyConsistency(ctx, next, prev); err != nil {
				var fe *source.ForkError
				if errors.As(err, &fe) {
					// The log signed two roots that cannot both be true.
					return nil, w.fork(&source.ForkError{
						Origin: origin,
						Reason: fmt.Sprintf("%s; and the smaller tree is not a prefix of the larger: %s",
							msg, fe.Reason),
						Prev: prev, Next: next,
					})
				}
				// No proof either way. Absence is not evidence: withhold.
				return nil, fmt.Errorf(
					"witness: %s: %s; could not determine whether this is a stale replica or a fork, withholding: %w",
					origin, msg, err)
			}
			// Consistent, so this is an older head we already witnessed past.
			// Withhold — we do not re-sign history — and retry.
			return nil, fmt.Errorf(
				"witness: %s: %s; the smaller tree is a prefix of the one we witnessed, "+
					"so this is a stale replica rather than a fork; withholding until it catches up",
				origin, msg)
		case next.Size == prev.Size && next.Hash != prev.Hash:
			msg := fmt.Sprintf("split view at size %d: witnessed root %x, now served %x", prev.Size, prev.Hash[:], next.Hash[:])
			if derived {
				return nil, fmt.Errorf("witness: %s: %s; head is derived, not signed, so withholding rather than accusing", origin, msg)
			}
			return nil, w.fork(&source.ForkError{
				Origin: origin, Reason: msg, Prev: prev, Next: next,
			})
		case next.Size == prev.Size:
			// Identical tree: same size, and the hash matched above. There is
			// no new history to attest, but we re-cosign periodically so our
			// timestamp remains a liveness signal.
			if w.RefreshInterval <= 0 || time.Since(prevRec.WitnessedAt) < w.RefreshInterval {
				return &Outcome{Origin: origin, Tier: src.Tier(), Size: next.Size, Unchanged: true}, nil
			}
			refresh = true
		}
	}

	// Gate 2: protocol-specific consistency proof. Skipped on a refresh, where
	// the tree is bit-for-bit the one we already proved consistent.
	if !refresh {
		if err := src.VerifyConsistency(ctx, prev, next); err != nil {
			var fe *source.ForkError
			if errors.As(err, &fe) {
				return nil, w.fork(fe)
			}
			// Could not obtain or check a proof. This is not evidence of
			// misbehaviour, but it is equally not grounds to sign.
			return nil, fmt.Errorf("witness: %s: consistency unproven, withholding: %w", origin, err)
		}
	}

	// Gate 3: freshness of our own view.
	if w.MaxSignDelay > 0 && time.Since(next.FetchedAt) > w.MaxSignDelay {
		return nil, fmt.Errorf("witness: %s: %w (fetched %s ago)", origin, ErrStale, time.Since(next.FetchedAt))
	}

	cosigned, err := note.Sign(next.Note, w.Signer)
	if err != nil {
		return nil, fmt.Errorf("witness: %s: cosign: %w", origin, err)
	}

	rec := &store.Record{
		Origin:      origin,
		Size:        next.Size,
		Hash:        next.Hash,
		Cosigned:    cosigned,
		WitnessedAt: time.Now().UTC(),
	}
	if err := w.Store.CompareAndSet(prevRec, rec); err != nil {
		// Including ErrRaced: another round advanced the log between our read
		// and our write, so this cosignature is discarded rather than stored.
		return nil, fmt.Errorf("witness: %s: persist: %w", origin, err)
	}

	w.Log.Info("cosigned",
		"origin", origin, "size", next.Size, "tier", src.Tier().String(), "refresh", refresh)

	return &Outcome{
		Origin: origin, Tier: src.Tier(), Size: next.Size,
		Cosigned: true, Refreshed: refresh,
	}, nil
}

// fork persists evidence and returns the error. Evidence is written before the
// error propagates so that a crash cannot lose the only record of misbehaviour.
func (w *Witness) fork(fe *source.ForkError) error {
	f := &store.Fork{
		Origin:     fe.Origin,
		Reason:     fe.Reason,
		DetectedAt: time.Now().UTC(),
	}
	if fe.Prev != nil {
		f.PrevSigned = fe.Prev.Signed
	}
	if fe.Next != nil {
		f.NextSigned = fe.Next.Signed
	}
	if err := w.Store.RecordFork(f); err != nil {
		w.Log.Error("FAILED TO PERSIST FORK EVIDENCE", "origin", fe.Origin, "err", err)
	}
	w.Log.Error("FORK DETECTED — withholding cosignature permanently",
		"origin", fe.Origin, "reason", fe.Reason)
	return fe
}

// observePeers records what other witnesses attested on this checkpoint and
// escalates a disagreement.
//
// A disagreement is conclusive — a log cannot have two roots at one size — but
// it is reported rather than acted on here. The evidence does not say which
// party was served the false history, and this witness poisoning a log on the
// strength of a signature it merely relayed is a step too far without a human
// reading the two attestations. They are both persisted so that a human can.
func (w *Witness) observePeers(origin string, head *source.Head) {
	if w.Peers == nil || len(head.Signed) == 0 {
		return
	}
	obs, err := w.Peers.Observe(origin, head.Signed)
	if err != nil || len(obs) == 0 {
		return
	}
	for _, o := range obs {
		conflicts, err := w.Store.RecordPeer(&store.PeerAttestation{
			Origin: o.Origin, Witness: o.Witness, Size: o.Size,
			Root: o.Root, Timestamp: o.Timestamp,
		})
		if err != nil {
			if w.Log != nil {
				w.Log.Warn("recording peer attestation", "origin", origin, "err", err)
			}
			continue
		}
		for _, c := range conflicts {
			if w.Log != nil {
				w.Log.Error("SPLIT VIEW BETWEEN WITNESSES — two signed attestations "+
					"disagree at one size; a log cannot have two roots there, so it "+
					"served different histories to different parties",
					"origin", origin, "size", o.Size,
					"witness_a", c.Witness, "root_a", c.Root,
					"witness_b", o.Witness, "root_b", o.Root)
			}
		}
	}
}
