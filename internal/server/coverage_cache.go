package server

import (
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// Caching the coverage scan.
//
// # Why
//
// Coverage is derived from the audit record rather than maintained
// incrementally, and that is the right call: a figure computed from the
// authoritative record cannot drift from it, while an incrementally maintained
// counter eventually does. This project has already been bitten by a gauge that
// looked healthy while standing still.
//
// The cost is that the derivation is a full scan of one origin's audit history,
// JSON-decoding every record. It ran on every metrics scrape — every fifteen
// seconds — and again on every page load, for every origin. Against a retention
// cap of 750,000 records that is millions of decodes a minute to answer a
// question whose answer changes by a few hundred an hour.
//
// # Why a cache rather than an incremental counter
//
// The cache keeps the property that matters: the number still comes from the
// record, it is simply not recomputed more often than it can meaningfully
// change. A stale-by-a-minute coverage figure is honest; a counter that has
// silently diverged from the audit trail is not.
//
// Entries are refreshed in the background so no request ever waits on a scan,
// and the age of each entry is exported — a cache that quietly stopped
// refreshing would otherwise look exactly like coverage that stopped moving,
// which is precisely the failure this codebase keeps rediscovering.

// coverageTTL is how stale a coverage figure may be before it is recomputed.
//
// Coverage moves by a few hundred epochs an hour, so a minute of staleness is
// invisible in every use — the dashboard, the tier calculation, the page — and
// removes the scan from the request path entirely.
const coverageTTL = time.Minute

type coverageEntry struct {
	cov      store.Coverage
	computed time.Time
	from, to int64
	// pop is the audit population the figure was computed from. Time alone is
	// the wrong freshness test: a log that has just been fully audited would sit
	// at the wrong tier for a whole TTL for no reason but a clock, while a log
	// where nothing has changed would be rescanned on a timer for no reason at
	// all. The population answers "has the record actually changed" directly,
	// and is maintained in memory.
	pop       int
	computing bool
}

type coverageCache struct {
	mu sync.Mutex
	m  map[string]*coverageEntry
	// ttl overrides coverageTTL. Zero means the default; negative means never
	// serve a cached value, which is what a caller wanting an exact figure —
	// a test asserting a tier, or an operator who would rather pay the scan —
	// asks for.
	ttl time.Duration
}

func (c *coverageCache) window() time.Duration {
	if c.ttl != 0 {
		return c.ttl
	}
	return coverageTTL
}

// get returns coverage for an origin, recomputing in the background when stale.
//
// The first call for an origin computes synchronously — there is nothing to
// serve otherwise, and returning zeros would read as "nothing audited", which
// is a far worse answer than a moment's delay.
func (c *coverageCache) get(s *store.Store, origin string, from, to int64) (store.Coverage, error) {
	// Cheap: maintained in memory after the first call.
	pop, err := s.AuditPopulation(origin)
	if err != nil {
		return store.Coverage{}, err
	}

	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]*coverageEntry)
	}
	e, known := c.m[origin]

	// Recompute when the record has actually changed, when the range has moved
	// under us (backfill widening history makes an old figure wrong, not merely
	// stale), or when the entry has simply aged out. The TTL is the backstop
	// that catches changes the population cannot see — an epoch re-recorded at
	// the same key, say, flipping from unverified to verified.
	window := c.window()
	if window > 0 && known && e.pop == pop && e.from == from && e.to == to &&
		time.Since(e.computed) < window {
		cov := e.cov
		c.mu.Unlock()
		return cov, nil
	}

	// Serve the previous value and refresh behind it, so no request waits on a
	// scan. Only when there is nothing at all to serve do we compute inline:
	// returning zeros would read as "nothing audited", which is a far worse
	// answer than a moment's delay.
	if window > 0 && known && !e.computed.IsZero() && e.from == from && e.to == to {
		if !e.computing {
			e.computing = true
			go c.refresh(s, origin, from, to, pop)
		}
		cov := e.cov
		c.mu.Unlock()
		return cov, nil
	}
	c.mu.Unlock()

	cov, err := s.CoverageOf(origin, from, to)
	if err != nil {
		return store.Coverage{}, err
	}
	c.store(origin, from, to, pop, cov)
	return cov, nil
}

func (c *coverageCache) refresh(s *store.Store, origin string, from, to int64, pop int) {
	cov, err := s.CoverageOf(origin, from, to)
	if err != nil {
		c.mu.Lock()
		if e := c.m[origin]; e != nil {
			e.computing = false
		}
		c.mu.Unlock()
		return
	}
	c.store(origin, from, to, pop, cov)
}

func (c *coverageCache) store(origin string, from, to int64, pop int, cov store.Coverage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]*coverageEntry)
	}
	c.m[origin] = &coverageEntry{
		cov: cov, computed: time.Now(), from: from, to: to, pop: pop,
	}
}

// oldest reports the age of the least recently refreshed entry, so a cache that
// has stopped updating is visible rather than being mistaken for flat coverage.
func (c *coverageCache) oldest() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var worst time.Duration
	for _, e := range c.m {
		if e.computed.IsZero() {
			continue
		}
		if d := time.Since(e.computed); d > worst {
			worst = d
		}
	}
	return worst
}
