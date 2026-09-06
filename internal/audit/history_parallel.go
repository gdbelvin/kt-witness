package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/store"
)

// Verifying a batch of historical epochs at once.
//
// # Why the sweep was slow while the machine was busy
//
// RunHistory verified one epoch, then the next. The forward pass did the same
// within each origin. That capped concurrency at about three streams — two
// origins plus the sweep — which is why permits sat at 3.4 and the pool had
// capacity nothing could reach. Measured: 50 epochs in twenty minutes, where
// three streams at a twelve-second average should have given fifteen a minute.
// CPU was pinned, not because the work was heavy, but because each stream was
// waiting on its own single verification.
//
// # Why order still matters
//
// The sweep must never advance past an epoch it has not settled: a hole in the
// swept range would make "audited across published history" false while looking
// complete. Results from a parallel batch arrive out of order, so the cursor is
// advanced only over the contiguous run of successes from the top. Anything
// after a hole is simply left for the next pass, exactly as parking did.

// batchResult is one epoch's outcome within a parallel pass.
type batchResult struct {
	epoch    int64
	audit    *store.Audit
	verified bool
	// fatal is a construction proof that failed to verify: conclusive, and it
	// stops the sweep rather than being retried.
	fatal error
	// blocked means we could not check — absence, a refused download, a
	// timeout. Not a finding, and the reason the run stops here.
	blocked bool
	// canceled means WE stopped asking: a shutdown or a cancelled context, not
	// anything the log did.
	//
	// Kept separate from blocked because the two look identical at this layer
	// and must not be counted alike. A blocked epoch spends one of its three
	// fetch attempts; a cancelled one must spend none. Otherwise three deploys
	// landing while the sweep sits near the same epochs exhaust their attempts
	// without a single request having been refused, the skip loop treats them as
	// settled, and the cursor steps over a permanent hole — a gap in "audited
	// across published history" manufactured entirely by restarts.
	canceled bool
}

// verifyBatch verifies up to `budget` epochs below cursor, concurrently.
//
// Returns results keyed by epoch. Concurrency is bounded by the governor, which
// is what keeps this from simply moving the bottleneck onto the CPU.
func (a *Auditor) verifyBatch(ctx context.Context, r Resolver, cursor, earliest, budget int64) map[int64]*batchResult {
	epochs := make([]int64, 0, budget)
	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		epochs = append(epochs, epoch)
	}
	return a.verifyEpochs(ctx, r, epochs)
}

// verifyEpochs verifies an arbitrary set of epochs concurrently.
//
// Separate from verifyBatch because the backwards sweep is not the only thing
// that needs to verify epochs: the repair pass revisits holes scattered above
// the cursor, which is not a contiguous descending run. Both want identical
// per-epoch behaviour — same governor, same prefetch, same accounting — and
// duplicating that is how the two would drift apart.
func (a *Auditor) verifyEpochs(ctx context.Context, r Resolver, epochs []int64) map[int64]*batchResult {
	out := make(map[int64]*batchResult, len(epochs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, epoch := range epochs {
		wg.Add(1)
		go func(epoch int64) {
			defer wg.Done()
			br := a.verifyOne(ctx, r, epoch)
			mu.Lock()
			out[epoch] = br
			mu.Unlock()
		}(epoch)
	}
	wg.Wait()
	return out
}

// verifyOne is the whole of an epoch's verification: resolve it, get its bytes,
// take a CPU permit, replay the proof, and classify the outcome.
//
// Extracted so the batch sweep, the streaming sweep and the repair pass share
// one implementation. Three copies of this would drift, and the parts that
// would drift first are exactly the ones that have already caused bugs: whether
// a cancellation counts as an attempt, and whether a permit is held across a
// download.
func (a *Auditor) verifyOne(ctx context.Context, r Resolver, epoch int64) *batchResult {
	origin := r.Origin()

	ref, err := r.ResolveEpoch(ctx, epoch)
	if err != nil {
		return &batchResult{epoch: epoch, blocked: true, canceled: ctx.Err() != nil}
	}

	// Bytes before permit: a permit bounds CPU, and holding one across a
	// download spends the scarcest token in the system on network wait.
	cached := a.Prefetch.Path(origin, epoch)
	if cached == "" && a.Prefetch != nil {
		_ = a.Prefetch.Fetch(ctx, origin, ref.LogDirectory, epoch,
			ref.PrevRoot, ref.CurrRoot)
		cached = a.Prefetch.Path(origin, epoch)
	}
	return a.verifyResolved(ctx, origin, epoch, ref, cached)
}

// verifyResolved replays one proof that has already been located and, ideally,
// downloaded.
//
// Split from verifyOne so the staged pipeline can run resolution, fetching and
// verification in separate pools while the repair pass — which handles a
// handful of scattered epochs and has no use for a pipeline — still gets
// identical per-epoch behaviour from one implementation.
func (a *Auditor) verifyResolved(ctx context.Context, origin string, epoch int64,
	ref *EpochRef, cached string) *batchResult {

	br := &batchResult{epoch: epoch}
	ar := &store.Audit{
		Origin: origin, Epoch: epoch,
		// Exhaustive, not drawn: the operator cannot retroactively choose what
		// we replay, so rate 1 records that this epoch was checked outright.
		Sampled: true, Rate: 1, Strategy: string(StrategyHistory),
		DecidedAt: time.Now().UTC(), Attempts: 1,
	}
	br.audit = ar

	if err := a.Governor.Acquire(ctx); err != nil {
		// The governor only ever fails because the context ended, so this is us
		// stopping, not the log refusing.
		br.blocked = true
		br.canceled = true
		return br
	}
	res, err := a.Sidecar.VerifyCached(ctx, ref.LogDirectory, epoch,
		ref.PrevRoot, ref.CurrRoot, cached, a.Timeout)
	a.Governor.Release()
	if cached != "" {
		a.Prefetch.Release(origin, epoch)
	}

	switch {
	case err != nil, res != nil && !res.OK && res.Kind != "verify":
		br.blocked = true
		br.canceled = ctx.Err() != nil
	case res != nil && !res.OK && res.Kind == "verify":
		ar.Verified = false
		br.fatal = fmt.Errorf(
			"audit: %s: historical construction audit failed at epoch %d: %s",
			origin, epoch, res.Error)
	default:
		ar.Verified = true
		ar.Bytes = res.Bytes
		ar.DurationMS = res.VerifyMS
		br.verified = true

		lbl := map[string]string{"origin": origin}
		metrics.Inc("kt_witness_audit_verified_total", lbl)
		// The same verification, counted again on its own. The shared counter
		// is incremented by both the live path and this one, so its rate
		// answers "is auditing happening" but not "is the BACKLOG moving" —
		// and those diverge exactly when it matters, because a sweep that has
		// stalled while the tip keeps up looks identical in the total. A
		// separate series rather than a label on the existing one: the rate
		// panels group by origin and take a max, so splitting that counter in
		// two would make them silently report the larger half instead of the
		// sum.
		metrics.Inc("kt_witness_history_verified_total", lbl)
		metrics.Add("kt_witness_audit_bytes_total", lbl, float64(res.Bytes))
		// The sidecar fetches over its own stack, so without this the largest
		// consumer of bandwidth would not appear in the bandwidth metric. A
		// prefetched proof was already counted when it was downloaded.
		if cached == "" {
			netmeter.Add(origin, res.Bytes)
		}
		a.Log.Info("epoch verified", "origin", origin, "epoch", epoch,
			"ms", res.VerifyMS, "mb", res.Bytes>>20, "strategy", "history")
	}
	return br
}
