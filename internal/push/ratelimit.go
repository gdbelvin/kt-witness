package push

import (
	"math"
	"sync"
	"time"
)

// maxBurst caps how many requests a log may make back to back.
//
// A log legitimately needs two requests for one checkpoint whenever it has to
// learn our size from a 409 first, and a few more after an outage while it
// catches up. Beyond that a burst is only a log (or somebody replaying its
// checkpoints) spending its daily allowance faster than it can have new trees
// to show us.
const maxBurst = 10

// limiter is a per-origin token bucket sized from each log's requests-per-day.
//
// Keyed by origin, and fed the log's QPD on every call rather than when the
// bucket is created, so a list update that changes a log's allowance takes
// effect without anyone having to reach in here.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter {
	return &limiter{buckets: make(map[string]*bucket)}
}

// allow spends one token for origin. When it refuses, it also says how long
// until the next token is due, for a Retry-After header.
func (l *limiter) allow(origin string, qpd int64, now time.Time) (bool, time.Duration) {
	if qpd <= 0 {
		return true, 0 // unlimited: statically configured logs
	}
	burst := float64(min(qpd, maxBurst))
	rate := float64(qpd) / (24 * 60 * 60) // tokens per second

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[origin]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[origin] = b
	}
	if now.After(b.last) {
		b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
		b.last = now
	}
	// A lowered allowance must not leave a bucket holding more than the new
	// burst, or the change would not bite until those tokens were spent.
	b.tokens = math.Min(b.tokens, burst)
	if b.tokens < 1 {
		wait := time.Duration(math.Ceil((1-b.tokens)/rate)) * time.Second
		return false, wait
	}
	b.tokens--
	return true, 0
}
