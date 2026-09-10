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
	// feedChunk is sized so the slowest participant finishes inside its lease.
	//
	// A lease starts running when the range is handed out, and results arriving
	// after it are refused — so a chunk too large for the machine holding it is
	// work done and thrown away. The witness verifies ~8 epochs at a time at
	// ~37 s each and would clear 200 in a quarter of an hour; a laptop working
	// two at a time would need over an hour against a twenty-minute lease, and
	// would lose everything past epoch sixty.
	//
	// Twenty-five is the slow machine's number: ~8 minutes at laptop speed,
	// ~2 on the witness. The cost of small chunks is queue churn, which is a
	// few map operations; the cost of large ones is other people's electricity.
	// A range is handed out as two interleaved assignments, so a chunk of this
	// many epochs becomes two of half the count — and no worker ever holds two
	// adjacent epochs. See work.Queue.LeasedBy for why that is a security
	// property and not a scheduling one.
	feedChunk    = 25
	feedInterval = 30 * time.Second
	// feedDepth is assignments to keep queued ahead of the workers, PER ORIGIN.
	//
	// Per origin, because measured globally it lets a slow log starve a fast
	// one outright. Meta's proofs are 284 MB and the fetch is bandwidth-bound,
	// so its assignments sit pending; they reach the cap; and the feed then
	// declines to queue anything at all — including WhatsApp, whose proofs are
	// a tenth the size and whose worker is sitting idle. Watched it: 40 Meta
	// pending, zero WhatsApp, 7,877 unverified WhatsApp epochs, and a laptop at
	// 0% CPU that can only do WhatsApp.
	//
	// The round-robin below was written to fix the same shape one level up — a
	// loop that queued Meta until the limit and never reached WhatsApp. It
	// fixed the order within a pass, which is not the same as fixing a limit
	// that is shared.
	feedDepth = 40
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
	hs, err := f.db.Histories()
	if err != nil {
		return
	}
	byOrigin := map[string]*store.History{}
	for _, h := range hs {
		byOrigin[h.Origin] = h
	}

	// One chunk per origin per pass, cycling, rather than filling from the
	// first origin until the queue is full.
	//
	// The straightforward loop starved every origin but the first. It queued
	// Meta until the depth limit and returned, and because the cursor is
	// remembered, the next pass carried on with Meta — so WhatsApp ranges were
	// never offered at all. A laptop that had declared only WhatsApp sat idle
	// with a full queue in front of it, and nothing in either log said why:
	// from the witness's side the queue was busy, and from the worker's side
	// there was simply no work.
	//
	// Interleaving also means a worker that can only do one log is never more
	// than a few chunks from something it can take.
	for {
		queued := 0
		for _, origin := range f.origins {
			// This origin's own depth. A log that cannot keep up holds back
			// only its own queue.
			if pending, leased := f.q.StatsFor(origin); pending+leased >= feedDepth {
				continue
			}
			h := byOrigin[origin]
			if h == nil || h.To <= h.From {
				continue
			}
			at, seen := f.next[origin]
			if !seen || at < h.From {
				at = h.From
			}
			// Skip forward over chunks that are wholly done, then WRAP.
			//
			// The wrap is the part that was missing, and its absence is what
			// left a laptop idle in front of 7,880 unverified WhatsApp epochs
			// with an empty queue. The cursor only ever moved forward; when it
			// reached the end of a history it set itself there and every
			// subsequent pass fell straight through the "nothing left to offer"
			// branch. Anything that had failed, been rescheduled, or been
			// skipped was never offered again — not until the process
			// restarted, which is the only reason this was ever survivable.
			//
			// A one-way sweep is the right shape for the FIRST pass over a
			// history, which is nearly all of the work. It is the wrong shape
			// for what is left afterwards, and what is left afterwards is
			// exactly the epochs something went wrong with.
			at, found := f.nextUnaudited(origin, h, at)
			if !found {
				// Nothing from here to the end; start again from the bottom, so
				// the retries and the gaps get another turn.
				if at, found = f.nextUnaudited(origin, h, h.From); !found {
					// Genuinely complete. Park at the top so the next pass
					// picks up newly published epochs rather than rescanning.
					f.next[origin] = h.To
					continue
				}
			}
			to := at + feedChunk - 1
			if to > h.To {
				to = h.To
			}
			f.q.AddInterleaved(origin, at, to)
			f.log.Debug("queued work", "origin", origin, "from", at, "to", to)
			f.next[origin] = to + 1
			queued++
		}
		if queued == 0 {
			return // nothing anywhere is ready to be queued
		}
	}
}

// nextUnaudited returns the first epoch at or after `from` that this witness has
// not recorded as verified, and whether it found one before the end.
//
// It asks the store for an exact answer rather than sampling. The version this
// replaces probed one epoch per twenty-five and treated a hit as "that whole
// chunk is done", which is cheap and wrong in the case that actually occurs: a
// range is handed out as two interleaved assignments, so when one half succeeds
// and the other fails, some of the chunk is verified and some is not. Whichever
// epoch the probe happened to look at decided the fate of the other
// twenty-four.
func (f *feeder) nextUnaudited(origin string, h *store.History, from int64) (int64, bool) {
	at, found, err := f.db.FirstUnverified(origin, from, h.To)
	if err != nil {
		return h.To, false
	}
	return at, found
}
