package audit

import (
	"context"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// Revisiting the holes the backwards sweep left behind.
//
// # Why a separate pass
//
// The sweep keeps one cursor and only ever walks down. An epoch it could not
// fetch is recorded, the cursor eventually moves below it, and from that moment
// the sweep can never look at it again — everything above the cursor is behind
// it forever. So without this, every transient refusal becomes a permanent hole.
//
// That matters more than it sounds. The holes sit inside the range tier B+
// claims to have audited, so the cheapest way to lose the strongest assertion
// this witness publishes is to be briefly unlucky with a CDN.
//
// # Why holes are retried rather than written off
//
// Almost every reason a proof cannot be fetched is temporary: CloudFront
// serving a stale negative listing, a 403 that clears a minute later, a diff
// published behind its epoch. Treating that evidence as final is a permanent
// conclusion drawn from a momentary condition.
//
// The backoff is what makes retrying affordable — an hour, then two, doubling
// to a week. A transient failure heals within the hour; a genuinely pruned blob
// costs a handful of requests a week, which is cheap enough to keep paying
// forever rather than declare the epoch beyond reach.

// RepairResult reports what one repair pass accomplished.
type RepairResult struct {
	Origin    string
	Attempted int
	Repaired  int
	// Remaining is how many holes are still open in the swept range.
	Remaining int64
}

// RunRepair retries holes whose backoff has elapsed.
//
// Deliberately given a small budget by the caller: this is a completeness
// exercise competing with the sweep, which is itself competing with the tip.
// Equivocation at the tip is a live incident; a hole is a gap in a historical
// claim, and it has waited an hour already.
func (a *Auditor) RunRepair(ctx context.Context, r Resolver, budget int) (*RepairResult, error) {
	origin := r.Origin()
	res := &RepairResult{Origin: origin}

	if forked, err := a.Store.IsForked(origin); err != nil {
		return nil, err
	} else if forked {
		return res, nil
	}

	// Holes lie ABOVE the cursor, not below it. The sweep starts high and walks
	// down, so the epochs it has already dealt with — and the ones it failed to
	// fetch along the way — are the ones it has passed. Below the cursor is
	// simply the work it has not reached yet, which needs no repair.
	latest, err := a.latestPublished(origin)
	if err != nil {
		return nil, err
	}
	if latest <= 0 {
		return res, nil
	}
	cursor, err := a.Store.BackAuditProgress(origin)
	if err != nil {
		return nil, err
	}
	if cursor <= 0 {
		return res, nil // the sweep has not started, so there is nothing behind it
	}

	if budget <= 0 {
		budget = 1
	}
	now := time.Now().UTC()
	holes, err := a.Store.HolesDue(origin, cursor, latest, now, budget)
	if err != nil {
		return nil, err
	}
	if len(holes) == 0 {
		return res, nil
	}
	res.Attempted = len(holes)

	results := a.verifyEpochs(ctx, r, holes)
	for _, epoch := range holes {
		br := results[epoch]
		if br == nil || br.canceled {
			// We stopped asking. Leave the record exactly as it was, so a
			// shutdown neither counts as an attempt nor pushes the backoff out.
			continue
		}
		if br.fatal != nil {
			// A construction proof that failed to verify is arithmetic, not
			// absence. Record it and stop: this poisons the log.
			if br.audit != nil {
				_ = a.Store.RecordAudit(br.audit)
			}
			return res, br.fatal
		}
		if br.blocked {
			// Still unreachable. Count the attempt and push the next retry
			// further out, so a dead epoch costs progressively less.
			attempts := maxFetchAttempts + 1
			if prior, err := a.Store.GetAudit(origin, epoch); err == nil && prior != nil {
				attempts = prior.Attempts + 1
			}
			_ = a.Store.RecordAudit(&store.Audit{
				Origin: origin, Epoch: epoch, Sampled: true, Rate: 1,
				Strategy: string(StrategyHistory), Verified: false,
				Attempts: attempts, DecidedAt: now,
				RetryAfter: retryAfter(now, attempts),
			})
			continue
		}
		if err := a.Store.RecordAudit(br.audit); err != nil {
			return res, err
		}
		res.Repaired++
		a.Log.Info("hole repaired", "origin", origin, "epoch", epoch)
	}

	// Report what is still open, so the metric reflects the pass that just ran.
	if _, _, holesLeft, err := a.Store.VerifiedRegion(origin, cursor, latest); err == nil {
		res.Remaining = holesLeft
	}
	return res, nil
}
