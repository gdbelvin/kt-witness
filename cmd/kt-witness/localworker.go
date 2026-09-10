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
	g *pace.Governor, sidecar audit.Verifier, resolvers []audit.Resolver, timeout time.Duration,
	n int, log *slog.Logger) {
	if n < 1 {
		n = 1
	}
	byOrigin := map[string]audit.Resolver{}
	for _, r := range resolvers {
		byOrigin[r.Origin()] = r
	}
	if len(byOrigin) == 0 || sidecar == nil {
		log.Warn("no local worker: nothing here can verify an epoch",
			"resolvers", len(byOrigin), "sidecar", sidecar != nil)
		return
	}

	name := "witness"
	r := &work.Runner{
		Name:         name,
		Log:          log.With("worker", name),
		EpochTimeout: timeout,
		// How much of this box to use, asked fresh for each range.
		//
		// Spare, not Permits: the backwards sweep draws on the same allowance
		// and takes permits as it goes, so what is free is the allowance less
		// what it holds. Reading Permits would have both size themselves for
		// the whole budget — two full-width sweeps, sixteen proof replays at
		// 3.7 GB each against a 44 GB limit, which is an OOM kill of the
		// witness rather than a slowdown. It would also have looked fine until
		// the box went quiet enough for both to widen at once.
		//
		// A fixed n gated on "wait until there is room for n" was the tempting
		// alternative and would have starved silently: live witnessing does not
		// consult this governor and can hold the machine indefinitely, so
		// permits sit at their floor and the gate would never open.
		Parallel: func() int {
			w := n
			if g != nil {
				switch p := int(g.Spare()); {
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
		// No request gate here, deliberately: the width above is this host's
		// yielding, and a second brake that can never release would be one
		// silent stall waiting to happen.
		Next: func(ctx context.Context) (work.Assignment, error) {
			return q.Lease(name, originsOf(byOrigin))
		},
		Verify: func(ctx context.Context, origin string, epoch int64, _ string) (string, string, error) {
			// The proof base is ignored here: this worker shares a process with
			// the thing that would be serving it, so fetching from ourselves to
			// test ourselves proves nothing. Its verifier is tested by
			// audit.Canary instead, which corrupts proofs on the way through
			// the sidecar pool where they can be checked directly.
			return verifyEpochHere(ctx, byOrigin[origin], sidecar, origin, epoch, timeout)
		},
		Report: func(ctx context.Context, res work.Result) error {
			if err := q.Accept(res); err != nil {
				return err
			}
			return recordWorkerResult(ctx, db, q, nil, resolvers, res, log)
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
				Parallel: r.Parallel(), CPUs: runtime.NumCPU(),
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
// sidecar pool.
//
// Two things here are load-bearing, and the first version of this file got both
// wrong by spawning the sidecar binary directly.
//
// An epoch cannot be verified from its number alone. The sidecar needs the log
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
func verifyEpochHere(ctx context.Context, r audit.Resolver, sidecar audit.Verifier,
	origin string, epoch int64, timeout time.Duration) (string, string, error) {
	if r == nil {
		return "", "", fmt.Errorf("no resolver for %s", origin)
	}
	ref, err := r.ResolveEpoch(ctx, epoch)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s epoch %d: %w", origin, epoch, err)
	}
	res, err := sidecar.VerifyCached(ctx, ref.LogDirectory, epoch, ref.PrevRoot, ref.CurrRoot, "", timeout)
	if err != nil {
		return "", "", err
	}
	if !res.OK {
		if res.Error != "" {
			return "", "", fmt.Errorf("%s", res.Error)
		}
		// The proof did not reconstruct the published root. Reported as a
		// disagreement — computed root empty against a non-empty published one
		// — never as a finding: what that means is the witness's to decide.
		return "", ref.CurrRoot, nil
	}
	return ref.CurrRoot, ref.CurrRoot, nil
}
