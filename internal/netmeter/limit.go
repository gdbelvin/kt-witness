package netmeter

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Holding this witness below the line rate.
//
// # Why there is a cap at all
//
// The work generator pulls proofs as fast as the CDN will serve them, which on
// a home connection is all of it. Measured here: 674-899 Mbit/s sustained on a
// link whose total is about 885, leaving 211 for everything else — and a video
// call on the same line was unusable. That is not congestion the call can route
// around. The queue that ruins it is the ISP's downstream buffer, and the only
// way to keep that buffer short is to stop filling it.
//
// # Why not mark the traffic instead
//
// The obvious answer is a DSCP class on our packets. It does nothing here. The
// bytes arriving are sent by CloudFront, and a mark we set on our own outbound
// requests does not govern what comes back — the field is rewritten at the
// ISP's edge, and the downstream queue is upstream of every piece of equipment
// we own. Marking would have looked like a fix and changed nothing measurable.
//
// # How the cap works
//
// By reading slowly. TCP's receive window is the one flow-control lever that
// reaches back to the sender: a consumer that stops reading causes the window
// to close and the sender to stall. So the shaper sits where the bytes are
// counted, delays the reader, and the connection paces itself.
//
// That it is the same place as the counting is the point. There were three
// paths into this process — a wrapped transport, the prefetcher's own client,
// and the verifier's — and two of them counted bytes by calling Add after the
// fact, which auditor.go's comment described as "outside any transport we
// wrap". A cap on one of three is not a cap. Reader is now both the meter and
// the shaper, so the next download path that forgets to come through here is
// visibly missing from the bandwidth graph, which is a thing somebody notices.

// A token bucket, hand-rolled rather than golang.org/x/time/rate.
//
// That package is small, correct, and would be a new module dependency for a
// witness whose whole claim is that you can read it. Forty lines of arithmetic
// against a supply-chain edge in a transparency tool is a bad trade, and this
// project has made the opposite trade before — internal/akdtree exists because
// the same reasoning applied to a Rust verifier.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64 // most that may accumulate while idle
	tokens float64
	last   time.Time

	// Injected so the test can assert the exact pacing instead of sleeping for
	// three seconds and comparing wall clock on a loaded machine.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var limiter atomic.Pointer[bucket]

// SetLimit caps the total rate of everything read through Reader, in bytes per
// second across every log. Zero or negative removes the cap.
//
// One bucket for the whole process, not one per origin: what is being protected
// is a single link, and two logs each politely holding to half of it would
// still fill the queue.
func SetLimit(bytesPerSec float64) {
	if bytesPerSec <= 0 {
		limiter.Store(nil)
		return
	}
	// A fiftieth of a second of accumulation. Big enough that a reader arriving
	// at an idle bucket is not delayed for a normal 32 KB chunk, small enough
	// that an idle spell cannot be cashed in as a burst long enough to refill
	// the queue this exists to keep empty.
	b := &bucket{rate: bytesPerSec, burst: bytesPerSec / 50, now: time.Now, sleep: wait}
	if b.burst < 1<<16 {
		b.burst = 1 << 16
	}
	b.tokens, b.last = b.burst, b.now()
	limiter.Store(b)
}

// Limit reports the configured cap in bytes per second, zero when uncapped.
func Limit() float64 {
	if b := limiter.Load(); b != nil {
		return b.rate
	}
	return 0
}

// take charges n bytes to the bucket and blocks until they were affordable.
//
// The charge happens first and may drive the balance negative; the caller then
// sleeps off exactly its own deficit. That ordering is what keeps thirty-two
// concurrent downloads from becoming a thundering herd — each one has already
// reserved its place, so they wake in the order they arrived rather than all
// waking to contend for the same tokens.
//
// A cancelled context abandons the reservation without refunding it, which
// under-uses the link very slightly after a shutdown. Refunding would mean
// holding the lock across the sleep.
func (b *bucket) take(ctx context.Context, n int) error {
	b.mu.Lock()
	now := b.now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	b.last = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.tokens -= float64(n)
	deficit := -b.tokens
	b.mu.Unlock()

	if deficit <= 0 {
		return nil
	}
	return b.sleep(ctx, time.Duration(deficit/b.rate*float64(time.Second)))
}

// Reader counts every byte read through it against origin and paces it against
// the shared cap. It is the only way bytes should enter this process.
//
// Pacing happens AFTER the read returns, not before: the bytes are already in
// the socket buffer by then, and what the delay controls is when the window
// reopens for the next ones. Delaying first would add latency without changing
// the rate.
func Reader(ctx context.Context, origin string, r io.Reader) io.Reader {
	return &meteredReader{ctx: ctx, origin: origin, r: r}
}

type meteredReader struct {
	ctx    context.Context
	origin string
	r      io.Reader
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		record(m.origin, int64(n), 0, 0)
		if b := limiter.Load(); b != nil {
			if werr := b.take(m.ctx, n); werr != nil && err == nil {
				err = werr
			}
		}
	}
	return n, err
}
