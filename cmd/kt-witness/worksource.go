package main

import (
	"log/slog"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// storeSource answers the queue's question — what still needs auditing — from
// the store, at the moment somebody asks.
//
// This replaces a feeder that ran on a thirty-second timer and pushed
// fixed-size chunks into a list inside the queue. That feeder kept three pieces
// of state duplicating what the store already knew, and each was wrong at some
// point in one day:
//
//   - a cursor that only ever moved forward, so an epoch that failed was never
//     offered again and 7,877 unverified WhatsApp epochs sat stranded behind it;
//   - a "is this chunk done" probe that sampled one epoch in twenty-five, so a
//     range whose interleaved half had failed was declared finished;
//   - a queue-depth cap counted across every log at once, so a bandwidth-bound
//     log filled it and starved a fast one out entirely, leaving a laptop at 0%
//     CPU with work it could do sitting unqueued.
//
// None of those are possible against a store query. There is also no chunk size
// here: the caller says how many epochs it wants, and that number comes from
// the machine that will do the work.
func storeSource(db *store.Store, log *slog.Logger) work.Source {
	return func(origin string, after int64, n int) (int64, int64, bool) {
		hs, err := db.Histories()
		if err != nil {
			return 0, 0, false
		}
		var h *store.History
		for _, x := range hs {
			if x.Origin == origin {
				h = x
				break
			}
		}
		if h == nil || h.To <= h.From {
			return 0, 0, false
		}
		if after < h.From {
			after = h.From
		}
		from, ok, err := db.FirstUnverified(origin, after, h.To)
		if err != nil {
			if log != nil {
				log.Warn("cannot ask the store what needs auditing",
					"origin", origin, "from", after, "err", err)
			}
			return 0, 0, false
		}
		if !ok {
			return 0, 0, false
		}
		// A contiguous run from there. Handing out more than is actually
		// unverified costs nothing: a worker re-verifying an epoch overwrites
		// the same verdict, and checking each one first would turn a single
		// ordered scan into a query per epoch.
		to := from + int64(n) - 1
		if to > h.To {
			to = h.To
		}
		return from, to, true
	}
}
