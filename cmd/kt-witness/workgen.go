package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// startWorkGenerator keeps the proof cache stocked with epochs that need
// verifying, so the queue always has downloaded work to hand out.
//
// # Why this is separate from the queue
//
// Verification is not CPU-bound; it is bound on getting the bytes. Measured on
// this fleet: a WhatsApp epoch is ~40 MB, the operators' CDNs give about
// 20 Mbit/s per connection, and hashing one takes about a second. So the shape
// of the system is a slow pipe feeding fast processors, and the only thing that
// makes that go quickly is downloading ahead of the machines that verify.
//
// It was not doing that. The queue handed out whatever the STORE said was
// unverified, and the proof server then fetched each one from the CDN when a
// worker asked for it. Every verification therefore began with a cold WAN fetch
// and the worker sat through it. Both machines showed the same symptom at once:
// a laptop running eight concurrent verifications at under one core of eight,
// and a thirty-two core server at two, neither short of CPU, both waiting.
//
// So: this generates, the cache holds, the queue drains. Three steps with the
// slow one at the front, running ahead.
//
// # What paces it
//
// The cache. Fetch declines when the cache is full or the volume is low, and
// returns without error because a full cache is the system working — it means
// the verifiers are the bottleneck, which is where the bottleneck belongs. When
// they drain it, Release frees room and this fills it again. Nothing here needs
// to know how fast anybody is going.
func startWorkGenerator(ctx context.Context, q *work.Queue, db *store.Store, pf *audit.Prefetcher,
	resolvers []audit.Resolver, origins []string, log *slog.Logger) {
	if pf == nil || pf.Dir == "" {
		log.Warn("no proof cache, so workers will fetch cold from the operator",
			"note", "set audit.prefetch_dir; without it every verification waits "+
				"on a WAN download that starts when the worker asks")
		return
	}
	byOrigin := map[string]audit.Resolver{}
	for _, r := range resolvers {
		byOrigin[r.Origin()] = r
	}
	metrics.Describe("kt_witness_proofs_ready", metrics.Gauge,
		"Downloaded proofs waiting for a verifier, by log")
	metrics.Describe("kt_witness_proofs_target", metrics.Gauge,
		"How many the generator is trying to keep ready, by log")

	for _, origin := range origins {
		r := byOrigin[origin]
		if r == nil {
			continue
		}
		go func(origin string, r audit.Resolver) {
			var c cursors
			for ctx.Err() == nil {
				n := pf.Held(origin)
				want := readyTarget(q, origin)
				metrics.Set("kt_witness_proofs_ready",
					map[string]string{"origin": origin}, float64(n))
				metrics.Set("kt_witness_proofs_target",
					map[string]string{"origin": origin}, float64(want))
				if n >= want {
					// Enough downloaded work is waiting. Sleeping rather than
					// spinning: the next thing to happen is a verifier freeing
					// room, and that is not something to poll hard for.
					sleep(ctx, 2*time.Second)
					continue
				}
				got := fillOnce(ctx, db, pf, r, origin, &c, log)
				if got == 0 {
					// Nothing to fetch from here — either the log is caught up
					// or the cache refused. Either way, wait before asking
					// again; both resolve on their own.
					sleep(ctx, 10*time.Second)
				}
			}
		}(origin, r)
	}
}

// readyFloor is the buffer to keep when nothing is leased yet — enough to
// bootstrap a fleet that has just connected.
const readyFloor = 16

// readyAhead is how many times the fleet's in-flight work to keep downloaded.
//
// A constant target was the mistake. Twenty-five looked generous until the
// fleet's capacity was counted: a single laptop holds sixteen epochs in flight
// and the witness's own worker more, so the buffer was no larger than what was
// already leased. The queue then found every cached epoch spoken for and
// answered ErrNoWork while the cache sat at its target — 23 proofs ready, 20 of
// them leased, seven of eight verifier slots idle waiting out a five-second
// timeout. A buffer the size of the demand is not a buffer.
//
// Three, because the buffer has to cover what is leased now, what will be
// leased while the next download runs, and a margin so the queue always has an
// unleased run to offer. It self-sizes: connect another machine and the target
// rises with the leases it takes.
//
// The cache's own cap is what bounds this from above — Fetch declines when
// there is no room, and declining is the system working.
const readyAhead = 3

// readyTarget is how many downloaded proofs to keep waiting for one log.
func readyTarget(q *work.Queue, origin string) int {
	n := q.LeasedEpochs(origin) * readyAhead
	if n < readyFloor {
		return readyFloor
	}
	return n
}

// fillOnce downloads the next batch of epochs for one origin, and reports how
// many it started.
//
// Two cursors, and neither ever resets. That is the whole of the fix for a
// generator that could not reach a steady state.
//
// The forward cursor chases the tip. It only moves up, so asking "what is the
// lowest unverified epoch from here" costs the size of the gap rather than the
// size of the history — which matters because a log that is caught up has its
// first unverified epoch AT the tip, and the previous version reset to zero and
// walked the entire verified prefix to rediscover that, every ten seconds, per
// log, forever. Measured at 353ms across half a million epochs and growing
// linearly as the log grows. It was not a slow steady state, it was the absence
// of one.
//
// The backward cursor sweeps old history for gaps: epochs that failed, were
// skipped, or were never fetched. It only moves down, and when it reaches the
// bottom it starts again from the forward cursor's floor — a full pass over
// history, but once per pass rather than once per poll.
//
// Tip before gaps, deliberately. A forged binding has to be caught while it can
// still reach somebody; a hole in three-year-old history is a coverage number.
// internal/audit/strategy.go sizes the tip window for the same reason: 256
// epochs is about eight hours of Messenger and two of WhatsApp.
func fillOnce(ctx context.Context, db *store.Store, pf *audit.Prefetcher,
	r audit.Resolver, origin string, c *cursors, log *slog.Logger) int {
	hs, err := db.Histories()
	if err != nil {
		return 0
	}
	var h *store.History
	for _, x := range hs {
		if x.Origin == origin {
			h = x
			break
		}
	}
	if h == nil || h.To <= h.From {
		return 0
	}
	c.init(db, origin, h)

	want := fillBatch
	epochs := c.forward(db, origin, h, want)
	if len(epochs) < want {
		epochs = append(epochs, c.backward(db, origin, h, want-len(epochs))...)
	}
	if len(epochs) == 0 {
		return 0
	}

	// Concurrently, because Fetch BLOCKS: it takes a slot from the prefetcher's
	// semaphore and does the download inline. Called in a loop it downloads one
	// proof at a time, the semaphore is never contended, and prefetch_workers
	// has no effect at all — which is exactly what happened. Outbound
	// connections sat at five however high that number was set.
	var wg sync.WaitGroup
	var started atomic.Int64
	for _, e := range epochs {
		ref, err := r.ResolveEpoch(ctx, e)
		if err != nil {
			continue // an epoch we cannot address is not one we can download
		}
		wg.Add(1)
		go func(e int64, ref *audit.EpochRef) {
			defer wg.Done()
			if err := pf.Fetch(ctx, origin, ref.LogDirectory, e, ref.PrevRoot, ref.CurrRoot); err != nil {
				log.Debug("could not prefetch a proof", "origin", origin, "epoch", e, "err", err)
				return
			}
			started.Add(1)
		}(e, ref)
	}
	wg.Wait()
	return int(started.Load())
}

// cursors is one origin's two positions: how far the tip-chasing pass has
// reached, and how far the history sweep has descended.
type cursors struct {
	fwd   int64
	back  int64
	ready bool

	// at is how far into the current backward window the sweep has reached, so
	// a window bigger than one batch is finished rather than abandoned.
	at int64

	// stride is how much history one backward probe covers. Zero means
	// backStride; a test sets it small so a fixture does not have to be
	// thousands of epochs long to exercise descending.
	stride int64
}

func (c *cursors) strideOr() int64 {
	if c.stride > 0 {
		return c.stride
	}
	return backStride
}

// init seeds both from what the store already recorded, so a restart does not
// re-walk ground the last run covered.
func (c *cursors) init(db *store.Store, origin string, h *store.History) {
	if c.ready {
		return
	}
	c.ready = true
	if p, err := db.AuditProgress(origin); err == nil && p > h.From {
		c.fwd = p
	} else {
		c.fwd = h.From
	}
	if b, ok, err := db.BackAuditProgress(origin); err == nil && ok && b > h.From {
		c.back = b
	} else {
		c.back = c.fwd
	}
}

// forward returns up to n unverified epochs between the tip cursor and the tip.
func (c *cursors) forward(db *store.Store, origin string, h *store.History, n int) []int64 {
	var out []int64
	at := c.fwd
	for len(out) < n && at <= h.To {
		e, ok, err := db.FirstUnverified(origin, at, h.To)
		if err != nil || !ok {
			// Caught up to the tip. The cursor STAYS here; it is where the next
			// published epoch will appear, and resetting it is what made this
			// rescan the whole history.
			c.fwd = h.To
			break
		}
		out = append(out, e)
		at = e + 1
		c.fwd = at
	}
	return out
}

// backward returns up to n unverified epochs below the tip pass.
//
// It descends a window at a time, and collects a RUN inside each window rather
// than a single epoch. The first version took one epoch per stride, which built
// the sparsest cache possible: every cached epoch 512 apart, so Ready could
// never return a contiguous run and every assignment was one epoch long.
// Watched it in production — nineteen of twenty assignments were a single
// epoch and throughput halved.
//
// Ascending within the window, descending between them. An unswept region is
// contiguous unverified epochs, so collecting ascending from the window's floor
// is what produces dense runs where density exists; a region already picked
// over yields scattered ones, which is correct because that is what is left.
func (c *cursors) backward(db *store.Store, origin string, h *store.History, n int) []int64 {
	if n <= 0 {
		return nil
	}
	var out []int64
	for len(out) < n {
		if c.back <= h.From {
			// Bottom reached: start again from the forward pass's floor. One
			// full sweep per pass, not one per poll.
			c.back = c.fwd
			c.at = 0
			if c.back <= h.From {
				return out
			}
		}
		lo := c.back - c.strideOr()
		if lo < h.From {
			lo = h.From
		}
		if c.at < lo || c.at >= c.back {
			c.at = lo
		}
		for len(out) < n {
			e, ok, err := db.FirstUnverified(origin, c.at, c.back-1)
			if err != nil || !ok {
				break
			}
			out = append(out, e)
			c.at = e + 1
		}
		if len(out) == n && c.at < c.back {
			// Budget spent with the window still unfinished. Stay here so the
			// rest of it is taken next pass rather than waiting for a full
			// descent to come round again.
			return out
		}
		c.back = lo
		c.at = 0
	}
	return out
}

// fillBatch is how many epochs one pass fetches. These go out concurrently and
// the prefetcher's own semaphore bounds how many actually run, so this is the
// width of one wave rather than a concurrency limit.
const fillBatch = 24

// backStride is how much history one backward probe covers.
//
// Large enough that descending a long history does not take a poll per epoch,
// small enough that each probe is a bounded scan rather than a walk of
// everything below the cursor.
const backStride = 512

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
