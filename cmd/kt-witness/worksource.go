package main

import (
	"fmt"
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

// akdOrigins is the logs whose proofs are cached and handed out as work.
//
// Duplicated from the work channel's own list deliberately: the prefetcher is
// built before that runs, and it needs this at construction — see the comment
// on Prefetcher.Origins for what setting it late cost.
func akdOrigins(cfg *config) []string {
	if len(cfg.Work.Origins) > 0 {
		return cfg.Work.Origins
	}
	var out []string
	for _, l := range cfg.Logs {
		if l.Type == "akd" {
			out = append(out, l.Origin)
		}
	}
	return out
}

// queueOrigins is the logs the queue covers: those named in work.origins, or
// every auditable log when it is unset.
func queueOrigins(cfg *config) []string {
	if len(cfg.Work.Origins) > 0 {
		return cfg.Work.Origins
	}
	return auditableOrigins(cfg)
}

// auditableOrigins is every log whose individual epochs this witness can check.
// Only AKD sources resolve an epoch to the roots the operator published.
func auditableOrigins(cfg *config) []string {
	var out []string
	for _, l := range cfg.Logs {
		if l.Type == "akd" {
			out = append(out, l.Origin)
		}
	}
	return out
}

// checkQueueCoverage refuses a work.origins that leaves an auditable log out.
//
// It used to narrow only the WORK CHANNEL: whatever it omitted was still swept
// by the auditor, so the setting cost dispatch and not coverage. As verification
// moves onto the queue that stops being true — an omitted log simply goes
// unaudited, while the witness goes on publishing a coverage figure that does
// not mention it.
//
// A silent hole in coverage is the one error this witness must not make, so the
// ambiguous configuration is refused rather than interpreted. Naming every
// auditable log, or removing the setting, both say plainly what was meant.
func checkQueueCoverage(cfg *config) error {
	if len(cfg.Work.Origins) == 0 {
		return nil
	}
	named := map[string]bool{}
	for _, o := range cfg.Work.Origins {
		named[o] = true
	}
	var missing []string
	for _, o := range auditableOrigins(cfg) {
		if !named[o] {
			missing = append(missing, o)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("work.origins omits %v, which this witness can audit — "+
			"those logs would go unaudited while coverage was still published for "+
			"them. Name them, or remove work.origins", missing)
	}
	return nil
}
