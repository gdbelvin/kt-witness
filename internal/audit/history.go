package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/store"
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

	for epoch := cursor - 1; epoch >= earliest && budget > 0; epoch-- {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		if prior, err := a.Store.GetAudit(origin, epoch); err != nil {
			return res, err
		} else if prior != nil && prior.Verified {
			// Already settled by an earlier pass or by the forward sweep.
			if err := a.Store.SetBackAuditProgress(origin, epoch); err != nil {
				return res, err
			}
			res.From = epoch
			continue
		}

		ref, err := r.ResolveEpoch(ctx, epoch)
		if err != nil {
			// Absence is not evidence, and a gap would silently falsify the
			// completeness claim. Park here and let the next pass retry.
			a.Log.Warn("history sweep parked: epoch unfetchable",
				"origin", origin, "epoch", epoch, "err", err)
			res.Remaining = epoch - earliest + 1
			return res, nil
		}

		ar := &store.Audit{
			Origin: origin, Epoch: epoch,
			// Sampled, not selected by beacon: history is audited exhaustively
			// because the operator cannot retroactively choose what we replay.
			// Rate 1 is recorded so the published record shows this epoch was
			// checked outright rather than drawn.
			Sampled: true, Rate: 1, Strategy: string(StrategyHistory),
			DecidedAt: time.Now().UTC(), Attempts: 1,
		}

		// Backlog work waits for CPU allowance. Live auditing does not.
		if err := a.Governor.Acquire(ctx); err != nil {
			return res, err
		}
		out, err := a.Sidecar.Verify(ctx, ref.LogDirectory, epoch, ref.PrevRoot, ref.CurrRoot, a.Timeout)
		a.Governor.Release()
		switch {
		case err != nil, out != nil && !out.OK && out.Kind != "verify":
			// Could not check. Not a finding.
			a.Log.Warn("history sweep parked: epoch unverifiable",
				"origin", origin, "epoch", epoch, "err", err)
			res.Remaining = epoch - earliest + 1
			return res, nil

		case out != nil && !out.OK && out.Kind == "verify":
			// A construction proof that fails to verify is conclusive, and just
			// as conclusive in history as at the tip.
			res.Failed++
			ar.Verified = false
			_ = a.Store.RecordAudit(ar)
			return res, fmt.Errorf(
				"audit: %s: historical construction audit failed at epoch %d: %s",
				origin, epoch, out.Error)
		}

		ar.Verified = true
		ar.Bytes = out.Bytes
		ar.DurationMS = out.VerifyMS
		if err := a.Store.RecordAudit(ar); err != nil {
			return res, err
		}
		if err := a.Store.SetBackAuditProgress(origin, epoch); err != nil {
			return res, err
		}

		lbl := map[string]string{"origin": origin}
		metrics.Inc("kt_witness_audit_verified_total", lbl)
		metrics.Add("kt_witness_audit_bytes_total", lbl, float64(out.Bytes))
		netmeter.Add(origin, out.Bytes)

		res.Verified++
		res.From = epoch
		budget--
	}

	if remaining, err := a.Store.BackAuditProgress(origin); err == nil {
		res.Remaining = remaining - earliest
		res.Complete = res.Remaining <= 0
	}
	return res, nil
}

// earliestPublished is the lowest epoch backfill established for this log.
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
