package store

import "time"

// When an epoch that could not be fetched may be tried again.
//
// "Stop asking every pass" and "give up forever" are different, and only the
// first is justified. Nearly every reason a proof cannot be fetched is
// temporary — a CDN serving a stale negative listing, a 403 that clears, a diff
// that lags its epoch — so a permanent verdict on that evidence leaves a hole
// that never heals, in precisely the range tier B+ claims to have covered.
//
// This lived in internal/audit beside the backwards sweep and was deleted with
// it, and deleting it was a bug with a visible cost. HolesDue skips any record
// whose RetryAfter is zero, on the reasoning that an epoch which has not
// exhausted its attempts still belongs to the ordinary sweep. With nothing
// setting the field, that condition became universal: HolesDue could not return
// a single epoch, and the only thing left that revisits a hole was the
// generator's backward cursor, which takes about twelve days to cross Meta's
// history. Measured: 7,408 Meta holes, flat to the epoch for five hours, with
// 436 of them sitting immediately above the verified region and capping the
// contiguous run that earns the tier.
//
// It lives here now, next to the field it fills and reachable from both the
// live auditor and the work channel — which are the two paths that record an
// epoch unverified, and which previously disagreed about whether to fill it
// because only one of them could see the helper.
const (
	// MaxFetchAttempts is how many times one pass will try before handing the
	// epoch to the backoff.
	MaxFetchAttempts = 3

	retryBackoffBase = time.Hour
	retryBackoffMax  = 7 * 24 * time.Hour
)

// RetryAt returns when an epoch with this many attempts may be tried again, or
// the zero time while it has attempts left and the ordinary sweep still owns it.
//
// The delay doubles per exhausted round from one hour to a week. A transient
// refusal is picked up within the hour; a genuinely pruned blob settles at a
// handful of requests a week, which is cheap enough to keep paying indefinitely
// rather than close the door on it.
func RetryAt(now time.Time, attempts int) time.Time {
	if attempts < MaxFetchAttempts {
		return time.Time{}
	}
	d := retryBackoffBase
	for i := MaxFetchAttempts; i < attempts && d < retryBackoffMax; i++ {
		d *= 2
	}
	if d > retryBackoffMax {
		d = retryBackoffMax
	}
	return now.Add(d)
}
