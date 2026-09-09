package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// feedWork keeps one queue topped up with epochs nobody has audited.
//
// There is no coordination here beyond the queue itself, and that is the point.
// An earlier version fed remote machines from the oldest end while this witness
// swept downward from the newest, so the two would not collide — a coordination
// scheme disguised as distance, which would have failed the day they met.
//
// Every participant leases from this queue, including the witness's own worker.
// The lease is what stops two machines doing the same epoch, and it works the
// same whether the machine is across the room or in this process.
//
// Duplicated work is not harmful even so: an audit record is keyed by
// (origin, epoch), and re-recording one overwrites it with the same verdict.
// The lease saves the effort, not the correctness.
const (
	feedChunk    = 200 // epochs per assignment
	feedInterval = 30 * time.Second
	feedDepth    = 40 // assignments to keep queued ahead of the workers
)

type feeder struct {
	db      *store.Store
	q       *work.Queue
	log     *slog.Logger
	origins []string
	// next is where each origin's feed has reached. In memory: on restart it
	// re-probes from the bottom and skips what is already audited, which costs
	// a few store reads and no duplicated verification.
	next map[string]int64
}

func startWorkFeed(ctx context.Context, db *store.Store, q *work.Queue, origins []string, log *slog.Logger) {
	f := &feeder{db: db, q: q, log: log, origins: origins, next: map[string]int64{}}
	go func() {
		t := time.NewTicker(feedInterval)
		defer t.Stop()
		for {
			f.topUp()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (f *feeder) topUp() {
	pending, leased := f.q.Stats()
	if pending+leased >= feedDepth {
		return // workers are behind; queueing more would only age the leases
	}
	hs, err := f.db.Histories()
	if err != nil {
		return
	}
	byOrigin := map[string]*store.History{}
	for _, h := range hs {
		byOrigin[h.Origin] = h
	}

	for _, origin := range f.origins {
		h := byOrigin[origin]
		if h == nil || h.To <= h.From {
			continue
		}
		limit := h.To
		at, seen := f.next[origin]
		if !seen || at < h.From {
			at = h.From
		}
		for at+feedChunk <= limit {
			if pending, leased = f.q.Stats(); pending+leased >= feedDepth {
				f.next[origin] = at
				return
			}
			to := at + feedChunk - 1
			// A cheap probe rather than a full coverage count: scanning every
			// audit record for an origin costs more than occasionally
			// re-queueing a chunk somebody already did, and a duplicate
			// overwrites itself.
			if a, err := f.db.GetAudit(origin, at); err == nil && a != nil && a.Verified {
				at = to + 1
				continue
			}
			f.q.Add(origin, at, to)
			f.log.Debug("queued work", "origin", origin, "from", at, "to", to)
			at = to + 1
		}
		f.next[origin] = at
	}
}
