package main

import (
	"log/slog"

	"github.com/gdbsecurity/kt-witness/internal/store"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// cacheSource is what the queue hands out: epochs whose proofs are already on
// this machine's disk.
//
// The queue used to ask the STORE what was unverified, which meant a lease
// could name epochs nobody had downloaded. The worker then waited through a
// cold WAN fetch that began only when it asked — and since the operators' CDNs
// give about 20 Mbit/s per connection while hashing an epoch takes about a
// second, the wait was nearly all of it. A laptop ran eight concurrent
// verifications at under one core of eight; a thirty-two core server at two.
// Neither was short of CPU.
//
// Three parts now, with the slow one at the front. The generator reads the
// store and downloads ahead (workgen.go); the cache holds what it fetched; this
// drains it. A lease names only epochs already here, so a worker's first byte
// is a local read.
//
// The store is still the authority on what NEEDS verifying — that is what the
// generator reads. This is the authority on what is READY, which is a different
// question and the only one the queue can usefully answer quickly.
func cacheSource(pf *audit.Prefetcher, log *slog.Logger) work.Source {
	return func(origin string, after int64, n int) (int64, int64, bool) {
		return pf.Ready(origin, after, n)
	}
}

// storeSource is the fallback when there is no cache: what the STORE says needs
// verifying, downloaded by whoever is handed it.
//
// Kept because a witness with no prefetch directory should still work, and
// because it is the honest description of what happens then — the queue names
// epochs nobody has fetched, and each worker pays the WAN cost itself, in
// series with its own verification.
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
		if err != nil || !ok {
			return 0, 0, false
		}
		to := from + int64(n) - 1
		if to > h.To {
			to = h.To
		}
		return from, to, true
	}
}
