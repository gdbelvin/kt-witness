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
		return nil, fmt.Errorf("witness: fetch %s: %w", origin, err)
	}
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
			return nil, w.fork(&source.ForkError{
				Origin: origin, Reason: msg, Prev: prev, Next: next,
			})
		case next.Size == prev.Size && next.Hash != prev.Hash:
			msg := fmt.Sprintf("split view at size %d: witnessed root %x, now served %x", prev.Size, prev.Hash, next.Hash)
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
