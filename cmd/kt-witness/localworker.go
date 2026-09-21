package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/pace"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// startLocalWorkers runs the witness's own verification as a worker on the
// shared queue.
//
// It is an ordinary participant. Nothing here is privileged, nothing bypasses
// the lease, and the code that drives it is the same work.Runner a laptop runs
// — which is the point: one loop with one set of failure modes, rather than a
// local path and a remote path that drift.
//
// One runner, n epochs at a time. n comes from memory rather than from cores:
// an AKD proof replay peaks near 3.7 GB, so the container's limit is what
// actually bounds this machine, and N-2 cores would be an OOM kill dressed up
// as parallelism. That is the one place the witness differs from a laptop, and
// it differs in the parameter rather than in the pattern.
func startLocalWorkers(ctx context.Context, cfg *config, db *store.Store, q *work.Queue,
	g *pace.Governor, verifier audit.Verifier, pf *audit.Prefetcher,
	resolvers []audit.Resolver, timeout time.Duration, n int, log *slog.Logger) {
	if n < 1 {
		n = 1
	}
	byOrigin := map[string]audit.Resolver{}
	for _, r := range resolvers {
		byOrigin[r.Origin()] = r
	}
	if len(byOrigin) == 0 || verifier == nil {
		log.Warn("no local worker: nothing here can verify an epoch",
			"resolvers", len(byOrigin), "verifier", verifier != nil)
		return
	}

	name := "witness"
	r := &work.Runner{
		Name:         name,
		Log:          log.With("worker", name),
		EpochTimeout: timeout,
		// How much of this box to use, asked fresh on every pass of the
		// request loop.
		//
		// This is now the ONLY consumer of the governor on this machine, which
		// is why Spare() is gone: it returned permits less what the backwards
		// sweep had acquired, and with the sweep deleted nothing acquires.
		//
		// A fixed n gated on "wait until there is room for n" was the tempting
		// alternative and would have starved silently: live witnessing does not
		// consult this governor and can hold the machine indefinitely, so
		// permits sit at their floor and the gate would never open. That is
		// also why there is no BeforeNext below, unlike the laptop's.
		//
		// The origin makes no difference here: the verifier's own semaphore is
		// the bound, and the governor is already measuring what the box can
		// afford — so the answer is about the machine rather than the log.
		Parallel: func(string) int {
			w := n
			if g != nil {
				switch p := int(g.Permits()); {
				case p < 1:
					w = 1 // always some progress; one replay is 3.7 GB of 44
				case p > n:
					w = n
				default:
					w = p
				}
			}
			return w
		},
		// The ceiling, which does not move: the verifier's own semaphore is
		// what actually bounds concurrent replays, so a goroutine pool any
		// wider than it buys nothing and one narrower than it wastes the box.
		//
		// It has to be stated separately from Parallel above, and this is the
		// whole reason Pool exists. Parallel reads the governor, and a
		// governor's permits start at their FLOOR — a load sampler cannot say
		// anything until an interval has passed. The Runner used to size its
		// pool from one call to Parallel at startup, so it read that floor:
		// this worker ran ONE epoch at a time, forever, on a thirty-two core
		// machine, while the capacity it reported every thirty seconds climbed
		// to twenty-eight and was believed. Meta went unleased entirely —
		// asking for one epoch, the queue's depth-ordered pick always chose
		// WhatsApp — while its downloaded proofs sat in the cache.
		Pool: n,
		// No request gate here, deliberately: the width above is this host's
		// yielding, and a second brake that can never release would be one
		// silent stall waiting to happen.
		// The witness's own worker pulls from the same queue as the borrowed
		// ones, through a function call instead of a stream. That the two are
		// the same code path is the point: whatever the queue does about
		// leases, retries and adjacency, it does for this machine too.
		Next: func(ctx context.Context, want int) (work.Assignment, error) {
			return q.Lease(name, originsOf(byOrigin), want)
		},
		Verify: func(ctx context.Context, origin string, epoch int64, _ string) (string, string, error) {
			// The proof base is ignored here: this worker shares a process with
			// the thing that would be serving it, so fetching from ourselves to
			// test ourselves proves nothing. The verifier it uses is the same
			// one every remote worker runs, and internal/akdtree's mutation
			// trials and fuzzing are what establish that it rejects a bad
			// proof.
			return verifyEpochHere(ctx, byOrigin[origin], verifier, pf, origin, epoch, timeout)
		},
		Report: func(ctx context.Context, res work.Result) error {
			if err := q.Accept(res); err != nil {
				return err
			}
			return recordWorkerResult(ctx, db, q, nil, pf, resolvers, res, true, log)
		},
	}
	go func() {
		if err := r.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("local worker stopped", "name", name, "err", err)
		}
	}()

	// Report capacity the way a remote worker does, so the witness appears on
	// the same graph as every other participant rather than as a gap in the
	// middle of it.
	//
	// On a timer rather than when a range starts: an idle machine is exactly
	// the interesting case, and a series that stops when there is no work says
	// nothing about whether the worker is well.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			load, budget := g.Observed()
			recordCapacity(name, work.Capacity{
				Parallel: r.Parallel(""), CPUs: runtime.NumCPU(),
				LoadCores: load, BudgetCores: budget,
			})
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	log.Info("local worker leasing from the shared queue", "parallel", n,
		"origins", originsOf(byOrigin))
}

func originsOf(m map[string]audit.Resolver) []string {
	out := make([]string, 0, len(m))
	for o := range m {
		out = append(out, o)
	}
	return out
}

// verifyEpochHere resolves one epoch and replays its proof through the shared
// verifier.
//
// Two things here are load-bearing, and the first version of this file got both
// wrong by calling the verifier directly.
//
// An epoch cannot be verified from its number alone. The verifier needs the log
// directory and the two roots the operator published, and those come from the
// object key in the operator's own listing — which is the point: the proof is
// checked against the roots the log published, not against anything we derived.
// A request without them is refused as malformed, and the worker would have
// reported every epoch "unavailable", writing a real epoch down as unverified.
//
// And it goes through the POOL rather than a fresh process. The pool is what
// bounds concurrent replays against the container's memory limit; a second
// spawner beside it means the bound is the sum of two numbers nobody wrote
// down, and being wrong is an OOM kill of the whole witness rather than a
// slowdown.
func verifyEpochHere(ctx context.Context, r audit.Resolver, v audit.Verifier,
	pf *audit.Prefetcher, origin string, epoch int64, timeout time.Duration) (string, string, error) {
	if r == nil {
		return "", "", fmt.Errorf("no resolver for %s", origin)
	}
	g, ok := v.(*audit.GoVerifier)
	if !ok {
		// Nothing else can answer this question. A verifier that reports a
		// verdict — "here are two roots, do they hold" — has no computed root
		// to hand back, and the caller compares computed against published. The
		// Rust reference was exactly that shape, and rather than say so this
		// function used to return the PUBLISHED current root as both of its
		// computed roots: every successful verification came back as a mismatch
		// on the previous root, was recorded unverified, and was re-queued.
		return "", "", fmt.Errorf("this worker's verifier does not report computed roots")
	}
	ref, err := r.ResolveEpoch(ctx, epoch)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s epoch %d: %w", origin, epoch, err)
	}
	// The roots are computed, not echoed.
	//
	// A machine handed the published roots and answering yes or no has been
	// told the answer; this local worker is held to the same standard as the
	// borrowed ones, so it computes and lets the caller compare.
	//
	// ref.PrevRoot and ref.CurrRoot still go in, and only to address the
	// operator's directory — that is how the proof URL is formed. They take no
	// part in what comes out.
	// From the cache when it is there, which it should be: this worker leases
	// from the same queue as the remote ones, and that queue only hands out
	// epochs the generator has already downloaded. Passing "" here would send
	// this machine to the CDN for bytes sitting on its own disk — the same
	// mistake the proof server was making for every remote worker.
	return g.ComputeRoots(ctx, origin, ref.LogDirectory, epoch,
		ref.PrevRoot, ref.CurrRoot, pf.Path(origin, epoch), timeout)
}
