package audit

import (
	"context"
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
	// `known` rather than a zero test: a log whose published history begins at
	// epoch 0 has a legitimate earliest of 0, and treating that as "nothing
	// backfilled" would silently exclude it from the sweep entirely.
	earliest, known, err := a.earliestPublished(origin)
	if err != nil {
		return nil, err
	}
	if !known {
		return res, nil // nothing backfilled yet; nothing to sweep toward
	}

	cursor, started, err := a.Store.BackAuditProgress(origin)
	if err != nil {
		return nil, err
	}
	if !started {
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
		if !prior.Verified {
			// Not yet out of attempts: take it now.
			if prior.Attempts < maxFetchAttempts {
				break
			}
			// Out of attempts, but the backoff has elapsed: try again. This is
			// what keeps a hole from being permanent — the sweep stops spending
			// every pass on a dead epoch without ever concluding it is dead.
			if !prior.RetryAfter.IsZero() && !time.Now().Before(prior.RetryAfter) {
				break
			}
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

	// Prime the cache before the window opens, so the first workers are not the
	// only ones paying for downloads. The streaming sweep keeps it topped up as
	// the window slides.
	a.prefetchAhead(ctx, r, cursor, a.windowSize()*2)

	// Sliding window rather than a batch-and-barrier. See history_stream.go for
	// why, and for the settlement invariants it must preserve.
	sr := a.sweepStream(ctx, r, cursor, earliest, budget)
	res.Verified = sr.verified
	if sr.from < cursor {
		res.From = sr.from
	}
	if sr.fatal != nil {
		res.Failed++
		return res, sr.fatal
	}

	res.Remaining = res.From - earliest
	if res.Remaining < 0 {
		res.Remaining = 0
	}
	res.Complete = res.From <= earliest
	return res, nil
}

// earliestPublished is the bottom of the backfilled range. The bool reports
// whether a range is recorded at all — epoch 0 is a legitimate floor, and a
// bare zero cannot be told apart from "no history yet".
func (a *Auditor) earliestPublished(origin string) (int64, bool, error) {
	hs, err := a.Store.Histories()
	if err != nil {
		return 0, false, err
	}
	for _, h := range hs {
		if h.Origin == origin {
			return h.From, true, nil
		}
	}
	return 0, false, nil
}

// latestPublished is the top of the backfilled range.
func (a *Auditor) latestPublished(origin string) (int64, bool, error) {
	hs, err := a.Store.Histories()
	if err != nil {
		return 0, false, err
	}
	for _, h := range hs {
		if h.Origin == origin {
			return h.To, true, nil
		}
	}
	return 0, false, nil
}

// prefetchAhead starts downloads for the epochs this sweep will reach next.
//
// Fire and forget: a prefetch that fails is not a problem, because the verifier
// falls back to downloading the proof itself. That fallback is what keeps this
// an optimisation rather than a new way for auditing to break.
func (a *Auditor) prefetchAhead(ctx context.Context, r Resolver, epoch, lookahead int64) {
	if a.Prefetch == nil {
		return
	}
	if lookahead < 1 {
		lookahead = 1
	}
	origin := r.Origin()
	for i := int64(1); i <= lookahead; i++ {
		next := epoch - i // the backwards sweep walks down
		if next < 1 {
			return
		}
		if a.Prefetch.Path(origin, next) != "" {
			continue
		}
		// Stop before resolving once the cache is full. Fetch would decline
		// anyway, but only after the resolve had already been paid for — and
		// with a lookahead of twice the batch that is a burst of listing
		// requests per round against somebody else's CDN, issued purely to
		// discover work there is no room to do.
		if _, held := a.Prefetch.Stats(); held >= a.Prefetch.maxBytes() {
			return
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
// evidence of nothing — what changes is only that we stop asking *for now*.
const maxFetchAttempts = 3

// Backoff for an epoch that has exhausted its attempts.
//
// "Stop asking every pass" and "give up forever" are different, and only the
// first is justified. Nearly every reason a proof cannot be fetched is
// temporary — a CDN serving a stale negative listing, a 403 that clears, a diff
// that lags its epoch — so a permanent verdict on that evidence leaves a hole
// that never heals, in precisely the range tier B+ claims to have covered.
//
// The delay doubles per exhausted round from one hour to a week. A transient
// refusal is picked up within the hour; a genuinely pruned blob settles at a
// handful of requests a week, which is cheap enough to keep paying indefinitely
// rather than close the door on it.
const (
	retryBackoffBase = time.Hour
	retryBackoffMax  = 7 * 24 * time.Hour
)

// retryAfter returns when an epoch with this many attempts may be tried again.
func retryAfter(now time.Time, attempts int) time.Time {
	if attempts < maxFetchAttempts {
		return time.Time{} // not exhausted; the next pass may take it
	}
	d := retryBackoffBase
	for i := maxFetchAttempts; i < attempts && d < retryBackoffMax; i++ {
		d *= 2
	}
	if d > retryBackoffMax {
		d = retryBackoffMax
	}
	return now.Add(d)
}
