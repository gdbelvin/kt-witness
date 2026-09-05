package audit

import (
	"context"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// The history sweep as a staged pipeline.
//
// # The barrier this removes
//
// The batch sweep took `budget` epochs, started one goroutine per epoch, and
// waited for all of them. Every epoch had to finish before any of the next
// batch began, so a round was held by its slowest member. Meta's proofs take
// about thirty-seven seconds and WhatsApp's about seven, and measurement showed
// exactly what that predicts: permits pinned at four while in-flight
// verifications fell to one, then zero, then the next batch began. Capacity the
// governor had already granted went unused.
//
// # Why stages rather than one pool
//
// An epoch passes through three steps that consume three different resources:
// resolving it is a listing request, fetching it is bandwidth and disk, and
// verifying it is CPU. A single pool of workers each doing all three serialises
// them per worker — a worker downloading a proof is a worker not verifying one,
// so the CPU idles behind the network exactly as it did before, just at a finer
// grain.
//
// Giving each stage its own pool, connected by channels, lets each run at its
// own limit: listings at whatever the CDN tolerates, downloads at the
// prefetcher's worker count, verifications at the governor's permit count. The
// channels between them carry backpressure for free — when verification falls
// behind, the fetch stage blocks on a full channel and stops pulling bandwidth,
// and when the disk cache fills the fetch stage blocks on that instead.
//
//	epochs ──▶ resolve ──▶ fetch ──▶ verify ──▶ settle
//	           (listing)   (link)    (CPU)      (ordered)
//
// # What must not change
//
// Settlement is where four separate bugs have lived, so the rules are stated
// rather than assumed:
//
//  1. Every verified epoch is recorded wherever it sits. An audit of epoch N is
//     true whether or not N-1 could be fetched. Conflating this with the cursor
//     threw away completed work once already.
//  2. The cursor advances only over the unbroken run below its start. A
//     pipeline reorders results far more aggressively than batching did, so
//     settlement is strictly ordered regardless of completion order.
//  3. A cancelled epoch records nothing. An attempt not made is not an attempt
//     refused, and charging one lets restarts retire an epoch nobody asked for.
//  4. A blocked epoch records an attempt and a retry backoff.
//  5. A verification failure stops the sweep. That is arithmetic, not absence.

// job carries one epoch through the pipeline, accumulating what each stage
// learned about it.
type job struct {
	epoch  int64
	ref    *EpochRef
	cached string // local path once fetched, "" if the fetch did not land
	result *batchResult
}

// streamResult is what one pipeline pass settled.
type streamResult struct {
	verified int64
	from     int64 // lowest epoch the cursor reached
	blocked  bool
	fatal    error
}

// Stage widths. Each is sized by the resource that stage actually consumes, not
// by the others — that independence is the whole point of separating them.
const (
	// Listings are small and cheap; this only needs to keep the fetch stage fed.
	resolveWorkers = 4

	// Matched to the prefetcher's own worker count: this stage IS the link.
	fetchWorkers = 4

	// More than the governor's permits, deliberately. Permits bound CPU; these
	// workers also spend time handing proofs to the sidecar and releasing cache
	// entries, so a couple of spares keep every permit occupied.
	verifyWorkers = 8
)

// sweepStream verifies up to `budget` epochs below cursor through the pipeline,
// then settles the results in strict epoch order.
func (a *Auditor) sweepStream(ctx context.Context, r Resolver, cursor, earliest, budget int64) streamResult {
	origin := r.Origin()
	res := streamResult{from: cursor}

	epochs := make(chan int64)
	resolved := make(chan *job, fetchWorkers)
	fetched := make(chan *job, verifyWorkers)
	done := make(chan *job, verifyWorkers)

	// Stage 0 — hand out epochs descending from just below the cursor.
	go func() {
		defer close(epochs)
		for i := int64(0); i < budget; i++ {
			epoch := cursor - 1 - i
			if epoch < earliest {
				return
			}
			select {
			case <-ctx.Done():
				return
			case epochs <- epoch:
			}
		}
	}()

	// Stage 1 — resolve. Turns an epoch into the URL of its proof.
	var resolveWG sync.WaitGroup
	for i := 0; i < resolveWorkers; i++ {
		resolveWG.Add(1)
		go func() {
			defer resolveWG.Done()
			for epoch := range epochs {
				j := &job{epoch: epoch}
				ref, err := r.ResolveEpoch(ctx, epoch)
				if err != nil {
					// Absence is not evidence. Route it straight to settlement
					// so the epoch is accounted for rather than dropped.
					j.result = &batchResult{
						epoch: epoch, blocked: true, canceled: ctx.Err() != nil,
					}
					send(ctx, done, j)
					continue
				}
				j.ref = ref
				send(ctx, resolved, j)
			}
		}()
	}
	go func() { resolveWG.Wait(); close(resolved) }()

	// Stage 2 — fetch. Bandwidth and disk, and no CPU permit is held here.
	//
	// This is what keeps the resources independent: a permit exists to bound
	// CPU, and holding one across a download spends the scarcest token in the
	// system on network wait.
	var fetchWG sync.WaitGroup
	for i := 0; i < fetchWorkers; i++ {
		fetchWG.Add(1)
		go func() {
			defer fetchWG.Done()
			for j := range resolved {
				j.cached = a.Prefetch.Path(origin, j.epoch)
				if j.cached == "" && a.Prefetch != nil {
					_ = a.Prefetch.Fetch(ctx, origin, j.ref.LogDirectory, j.epoch,
						j.ref.PrevRoot, j.ref.CurrRoot)
					j.cached = a.Prefetch.Path(origin, j.epoch)
				}
				// A miss is not fatal: the sidecar can still fetch it itself.
				// That path costs a permit, which is why it is the exception.
				send(ctx, fetched, j)
			}
		}()
	}
	go func() { fetchWG.Wait(); close(fetched) }()

	// Stage 3 — verify. CPU, gated by the governor.
	var verifyWG sync.WaitGroup
	for i := 0; i < verifyWorkers; i++ {
		verifyWG.Add(1)
		go func() {
			defer verifyWG.Done()
			for j := range fetched {
				j.result = a.verifyResolved(ctx, origin, j.epoch, j.ref, j.cached)
				send(ctx, done, j)
			}
		}()
	}
	go func() { verifyWG.Wait(); close(done) }()

	// Stage 4 — collect. Settlement itself must be ordered, so results are
	// gathered first and decided afterwards.
	results := make(map[int64]*batchResult, budget)
	for j := range done {
		results[j.epoch] = j.result
	}

	return a.settle(origin, cursor, earliest, budget, results, res)
}

// send delivers to a channel unless the context ends first.
func send(ctx context.Context, ch chan<- *job, j *job) {
	select {
	case <-ctx.Done():
	case ch <- j:
	}
}

// settle applies the results in strict epoch order, independent of the order
// they were produced in.
func (a *Auditor) settle(origin string, cursor, earliest, budget int64,
	results map[int64]*batchResult, res streamResult) streamResult {

	blocked := false
	for epoch := cursor - 1; epoch >= earliest && epoch > cursor-1-budget; epoch-- {
		br := results[epoch]
		if br == nil {
			// Never attempted — the budget ran out or the context ended. Not a
			// decision about the epoch, so nothing is recorded and nothing is
			// claimed below it.
			break
		}
		if br.fatal != nil {
			if br.audit != nil {
				_ = a.Store.RecordAudit(br.audit)
			}
			res.fatal = br.fatal
			return res
		}
		if br.canceled {
			// We stopped asking. Record nothing: an attempt not made is not an
			// attempt refused.
			blocked = true
			continue
		}
		if br.blocked {
			a.recordBlocked(origin, epoch)
			blocked = true
			continue
		}
		if err := a.Store.RecordAudit(br.audit); err != nil {
			res.fatal = err
			return res
		}
		res.verified++
		// The cursor moves only while nothing below it is outstanding.
		if !blocked {
			if err := a.Store.SetBackAuditProgress(origin, epoch); err != nil {
				res.fatal = err
				return res
			}
			res.from = epoch
		}
	}
	res.blocked = blocked
	return res
}

// recordBlocked marks an epoch we could not check, spending one of its attempts
// and setting the backoff once they are exhausted.
func (a *Auditor) recordBlocked(origin string, epoch int64) {
	attempts := 1
	if prior, err := a.Store.GetAudit(origin, epoch); err == nil && prior != nil {
		attempts = prior.Attempts + 1
	}
	now := time.Now().UTC()
	_ = a.Store.RecordAudit(&store.Audit{
		Origin: origin, Epoch: epoch, Sampled: true, Rate: 1,
		Strategy: string(StrategyHistory), Verified: false,
		Attempts: attempts, DecidedAt: now,
		RetryAfter: retryAfter(now, attempts),
	})
}

// windowSize is how many epochs may be in flight across the pipeline, used to
// size the prefetch lookahead.
func (a *Auditor) windowSize() int64 {
	return int64(fetchWorkers + verifyWorkers)
}
