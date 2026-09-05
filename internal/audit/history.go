package audit

import (
	"context"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"time"
)

// Auditing backwards through published history.
//
// # Why this exists
//
// The forward auditor starts where witnessing started. That makes "tier B" mean
// "the epochs published since we showed up are construction audited" — which is
// a real claim, and a much weaker one than it sounds. A log with 625,000 epochs
// of published history that we began watching yesterday has essentially none of
// that history checked, while the published tier says B.
//
// Sweeping backwards closes the gap. A log whose entire published range has a
// settled decision is construction audited across its history, which is the B
// analogue of what tier A+ is to tier A, and this project calls it B+.
//
// # Why history is audited exhaustively rather than sampled
//
// Forward sampling exists because an operator could otherwise predict which
// epochs will be checked and misbehave in the gaps. That argument is about
// epochs not yet published: the beacon is drawn after publication precisely so
// the choice cannot be anticipated.
//
// History is different. Those epochs are already published and their proofs are
// already fixed; an operator cannot retroactively choose what we will look at,
// because whatever they published is what we will replay. Sampling history
// therefore buys nothing in unpredictability and costs coverage directly. So the
// backwards sweep audits every epoch it can afford, and the only reason to
// throttle it is resources.
//
// # Priority
//
// The backwards sweep must never delay the forward one. Equivocation happens at
// the tip, and an operator showing two histories today is a live incident;
// history is a completeness exercise that can wait. The scheduler in cmd runs
// this at a lower cadence and with a smaller per-round budget for that reason.

// HistoryResult reports what one backwards pass accomplished.
type HistoryResult struct {
	Origin    string
	From, To  int64 // the range this pass settled, inclusive
	Verified  int64
	Failed    int64
	Remaining int64 // epochs of published history still unaudited
	Complete  bool
}

// RunHistory audits epochs backwards from wherever the sweep last reached,
// toward the earliest epoch this log has published.
//
// It stops at the first epoch it cannot fetch rather than skipping over it: a
// hole in the swept range would make "audited across published history" false
// while still looking complete, and the whole value of this is that the claim
// is measured rather than asserted. An unfetchable epoch leaves the sweep
// parked, which is visible, and the next pass retries it.
func (a *Auditor) RunHistory(ctx context.Context, r Resolver, budget int64) (*HistoryResult, error) {
	origin := r.Origin()
	res := &HistoryResult{Origin: origin}

	if forked, err := a.Store.IsForked(origin); err != nil {
		return nil, err
	} else if forked {
		return res, nil
	}

	// The earliest epoch this log actually published, as established by
	// backfill. Without it we do not know where history ends and would sweep
	// toward zero forever against a log that starts at 89,395.
	earliest, err := a.earliestPublished(origin)
	if err != nil {
		return nil, err
	}
	if earliest <= 0 {
		return res, nil // nothing backfilled yet; nothing to sweep toward
	}

	cursor, err := a.Store.BackAuditProgress(origin)
	if err != nil {
		return nil, err
	}
	if cursor == 0 {
		// Start just below where the forward auditor began, so the two meet
		// rather than overlap.
		fwd, err := a.Store.AuditProgress(origin)
		if err != nil {
			return nil, err
		}
		if fwd == 0 {
			return res, nil // forward auditing has not established a floor yet
		}
		cursor = fwd
	}
	if cursor <= earliest {
		res.Complete = true
		return res, nil
	}

	if budget <= 0 {
		budget = 1
	}
	res.To = cursor - 1

	// Skip anything already settled, without spending a verification on it.
	//
	// "Settled" includes an epoch we have failed to fetch enough times to stop
	// asking. Without that, one dead blob halts the sweep permanently: every
	// pass walks down to it, fails, re-verifies the epochs below — which
	// RecordAudit overwrites rather than adds — and coverage never moves while
	// the machine looks busy. That is exactly what happened, stuck between
	// epochs 625,350 and 625,501 for hours.
	// The forward sweep meets this one coming the other way, so the overlap is
	// normal rather than exceptional.
	for cursor-1 >= earliest {
		prior, err := a.Store.GetAudit(origin, cursor-1)
		if err != nil {
			return res, err
		}
		if prior == nil {
			break
		}
		if !prior.Verified && prior.Attempts < maxFetchAttempts {
			break
		}
		if err := a.Store.SetBackAuditProgress(origin, cursor-1); err != nil {
			return res, err
		}
		cursor--
		res.From = cursor
	}
	if cursor <= earliest {
		res.Complete = true
		return res, nil
	}

	// Fetch ahead for the whole batch, so the link is filling the cache while
	// the pool works through it.
	a.prefetchAhead(ctx, r, cursor)

	results := a.verifyBatch(ctx, r, cursor, earliest, budget)

	// Advance only over the contiguous run of successes below the cursor.
	//
	// Results arrive out of order, and the sweep must never step past an epoch
	// it has not settled: a hole would make "audited across published history"
	// false while looking complete. Everything beyond the first gap is simply
	// left for the next pass, which is what parking did when this was serial.
	// Record every epoch that verified, then advance the cursor only over the
	// contiguous run.
	//
	// These are two different questions and conflating them threw work away. An
	// audit of epoch N is true whether or not N-1 could be checked, so it is
	// recorded; the CURSOR is what must not step past a hole, because that is
	// the thing claiming "everything below here is settled". Breaking out of the
	// loop on the first gap discarded verifications that had already been paid
	// for, and the next pass redid them — which is why coverage sat still while
	// the sweep was plainly busy.
	blocked := false
	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		br := results[epoch]
		if br == nil {
			blocked = true
			continue
		}
		if br.fatal != nil {
			res.Failed++
			if br.audit != nil {
				_ = a.Store.RecordAudit(br.audit)
			}
			return res, br.fatal
		}
		if br.blocked {
			// Count the attempt. Absence is still not evidence — the record is
			// marked unverified, never as a finding — but an epoch that can
			// never be fetched has to stop consuming every pass.
			attempts := 1
			if prior, err := a.Store.GetAudit(origin, epoch); err == nil && prior != nil {
				attempts = prior.Attempts + 1
			}
			ar := &store.Audit{
				Origin: origin, Epoch: epoch, Sampled: true, Rate: 1,
				Strategy: string(StrategyHistory), Verified: false,
				Attempts: attempts, DecidedAt: time.Now().UTC(),
			}
			_ = a.Store.RecordAudit(ar)
			if !blocked {
				a.Log.Warn("history sweep: epoch could not be checked",
					"origin", origin, "epoch", epoch, "attempt", attempts,
					"gives_up_after", maxFetchAttempts)
			}
			blocked = true
			continue
		}

		// Verified. Worth recording wherever it sits.
		if err := a.Store.RecordAudit(br.audit); err != nil {
			return res, err
		}
		res.Verified++

		// The cursor only moves while nothing below it is outstanding.
		if !blocked {
			if err := a.Store.SetBackAuditProgress(origin, epoch); err != nil {
				return res, err
			}
			res.From = epoch
		}
	}

	res.Remaining = res.From - earliest
	if res.Remaining < 0 {
		res.Remaining = 0
	}
	res.Complete = res.From <= earliest
	return res, nil
}

func (a *Auditor) earliestPublished(origin string) (int64, error) {
	hs, err := a.Store.Histories()
	if err != nil {
		return 0, err
	}
	for _, h := range hs {
		if h.Origin == origin {
			return h.From, nil
		}
	}
	return 0, nil
}

// prefetchAhead starts downloads for the epochs this sweep will reach next.
//
// Fire and forget: a prefetch that fails is not a problem, because the verifier
// falls back to downloading the proof itself. That fallback is what keeps this
// an optimisation rather than a new way for auditing to break.
func (a *Auditor) prefetchAhead(ctx context.Context, r Resolver, epoch int64) {
	if a.Prefetch == nil {
		return
	}
	const lookahead = 8
	origin := r.Origin()
	for i := int64(1); i <= lookahead; i++ {
		next := epoch - i // the backwards sweep walks down
		if next < 1 {
			return
		}
		if a.Prefetch.Path(origin, next) != "" {
			continue
		}
		go func(e int64) {
			ref, err := r.ResolveEpoch(ctx, e)
			if err != nil {
				return // absence is not evidence; the sweep will find out
			}
			_ = a.Prefetch.Fetch(ctx, origin, ref.LogDirectory, e, ref.PrevRoot, ref.CurrRoot)
		}(next)
	}
}

// maxFetchAttempts is how often an unfetchable epoch is retried before the
// sweep stops waiting for it.
//
// Retrying forever is not patience, it is a stall: the sweep re-walks the same
// epochs every pass and coverage stands still while the machine looks fully
// occupied. Three attempts spread across passes is enough to ride out a
// transient refusal or a stale cache entry.
//
// The epoch is recorded unverified, never as a finding. Absence remains
// evidence of nothing — what changes is only that we stop asking.
const maxFetchAttempts = 3
