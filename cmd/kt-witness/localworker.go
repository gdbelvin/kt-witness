package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

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
func startLocalWorkers(ctx context.Context, cfg *config, db *store.Store, q *work.Queue, g *pace.Governor, n int, log *slog.Logger) {
	if n < 1 {
		n = 1
	}
	bin := cfg.Audit.SidecarPath
	name := "witness"
	r := &work.Runner{
		Name: name,
		Log:  log.With("worker", name),
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
			if g == nil {
				return n
			}
			p := int(g.Spare())
			switch {
			case p < 1:
				return 1 // always some progress; one replay is 3.7 GB of 44
			case p > n:
				return n
			}
			return p
		},
		Next: func(ctx context.Context) (work.Assignment, error) {
			return q.Lease(name, nil)
		},
		Verify: func(ctx context.Context, origin string, epoch int64) (string, string, error) {
			return akdVerify(ctx, bin, origin, epoch)
		},
		// No request gate here, deliberately: the width above is this host's
		// yielding, and a second brake that can never release would be one
		// silent stall waiting to happen.
		Report: func(ctx context.Context, res work.Result) error {
			if err := q.Accept(res); err != nil {
				return err
			}
			return recordWorkerResult(db, q, res, log)
		},
	}
	go func() {
		if err := r.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("local worker stopped", "name", name, "err", err)
		}
	}()
	log.Info("local worker leasing from the shared queue", "parallel", n)
}

// akdVerify replays one audit proof with the Rust sidecar.
//
// Identical in shape to the verifier a remote worker uses, deliberately: if the
// two diverged, the witness would be checking something subtly different from
// what it asks other machines to check.
func akdVerify(ctx context.Context, bin, origin string, epoch int64) (string, string, error) {
	req, _ := json.Marshal(map[string]any{"origin": origin, "epoch": epoch})
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = strings.NewReader(string(req))
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", bin, err)
	}
	var r struct {
		OK     bool   `json:"ok"`
		Root   string `json:"root"`
		Signed string `json:"signed_root"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", fmt.Errorf("sidecar output was not JSON: %s", strings.TrimSpace(string(out)))
	}
	if !r.OK && r.Error != "" {
		return "", "", fmt.Errorf("%s", r.Error)
	}
	return r.Root, r.Signed, nil
}

var _ = time.Second
