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
func startWorkGenerator(ctx context.Context, db *store.Store, pf *audit.Prefetcher,
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

	for _, origin := range origins {
		r := byOrigin[origin]
		if r == nil {
			continue
		}
		go func(origin string, r audit.Resolver) {
			var cursor int64
			for ctx.Err() == nil {
				n := pf.Held(origin)
				metrics.Set("kt_witness_proofs_ready",
					map[string]string{"origin": origin}, float64(n))
				if n >= readyTarget {
					// Enough downloaded work is waiting. Sleeping rather than
					// spinning: the next thing to happen is a verifier freeing
					// room, and that is not something to poll hard for.
					sleep(ctx, 2*time.Second)
					continue
				}
				got, next := fillOnce(ctx, db, pf, r, origin, cursor, log)
				cursor = next
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

// readyTarget is how many downloaded proofs to keep waiting per log.
//
// Enough to cover the round trip between a verifier finishing and the next
// download completing, and no more: every cached proof is disk the next one
// cannot use. Twenty-five WhatsApp proofs is about a gigabyte; the cache
// default is 64.
const readyTarget = 25

// fillOnce downloads the next batch of unverified epochs for one origin, and
// reports how many it started and where to look next.
func fillOnce(ctx context.Context, db *store.Store, pf *audit.Prefetcher,
	r audit.Resolver, origin string, cursor int64, log *slog.Logger) (int, int64) {
	hs, err := db.Histories()
	if err != nil {
		return 0, cursor
	}
	var h *store.History
	for _, x := range hs {
		if x.Origin == origin {
			h = x
			break
		}
	}
	if h == nil || h.To <= h.From {
		return 0, cursor
	}
	if cursor < h.From {
		cursor = h.From
	}
	at, ok, err := db.FirstUnverified(origin, cursor, h.To)
	if err != nil || !ok {
		// Nothing from here to the tip. Start again from the bottom next pass:
		// the tail being done does not mean the gaps behind it are, and an
		// epoch that failed is exactly the work most likely to be missed.
		return 0, 0
	}

	// Concurrently, because Fetch BLOCKS: it takes a slot from the prefetcher's
	// semaphore and does the download inline. Called in a loop it downloads one
	// proof at a time, the semaphore is never contended, and prefetch_workers
	// has no effect at all — which is exactly what happened. Outbound
	// connections sat at five however high that number was set.
	//
	// The fan-out is the whole point of this stage. p.sem is what bounds it.
	var wg sync.WaitGroup
	var started atomic.Int64
	for e := at; e <= h.To && e < at+int64(fillBatch); e++ {
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
	return int(started.Load()), at + int64(fillBatch)
}

// fillBatch is how many epochs one pass fetches at once.
//
// These go out concurrently and the prefetcher's own semaphore bounds how many
// actually run, so this is the width of one wave rather than a concurrency
// limit. Wide enough that both logs can have several downloads in flight at
// once, since one slow CDN response should not hold up the rest of its batch.
const fillBatch = 24

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
