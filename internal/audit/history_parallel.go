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
	origin := r.Origin()
	out := make(map[int64]*batchResult, budget)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		wg.Add(1)
		go func(epoch int64) {
			defer wg.Done()
			br := &batchResult{epoch: epoch}

			ref, err := r.ResolveEpoch(ctx, epoch)
			if err != nil {
				br.blocked = true
				br.canceled = ctx.Err() != nil
				mu.Lock()
				out[epoch] = br
				mu.Unlock()
				return
			}

			ar := &store.Audit{
				Origin: origin, Epoch: epoch,
				// Exhaustive, not drawn: the operator cannot retroactively
				// choose what we replay, so rate 1 records that this epoch was
				// checked outright.
				Sampled: true, Rate: 1, Strategy: string(StrategyHistory),
				DecidedAt: time.Now().UTC(), Attempts: 1,
			}
			br.audit = ar

			cached := a.Prefetch.Path(origin, epoch)
			if err := a.Governor.Acquire(ctx); err != nil {
				// The governor only ever fails because the context ended, so
				// this is us stopping, not the log refusing.
				br.blocked = true
				br.canceled = true
				mu.Lock()
				out[epoch] = br
				mu.Unlock()
				return
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
				metrics.Add("kt_witness_audit_bytes_total", lbl, float64(res.Bytes))
				// The sidecar fetches over its own stack, so without this the
				// largest consumer of bandwidth would not appear in the
				// bandwidth metric. A prefetched proof was already counted when
				// it was downloaded, so only count it here when it was not.
				if cached == "" {
					netmeter.Add(origin, res.Bytes)
				}
				a.Log.Info("epoch verified", "origin", origin, "epoch", epoch,
					"ms", res.VerifyMS, "mb", res.Bytes>>20, "strategy", "history")
			}
			mu.Lock()
			out[epoch] = br
			mu.Unlock()
		}(epoch)
	}
	wg.Wait()
	return out
}
