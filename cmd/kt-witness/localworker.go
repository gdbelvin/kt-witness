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

// startLocalWorkers runs the witness's own verification as workers on the
// shared queue.
//
// They are ordinary participants. Nothing here is privileged, nothing bypasses
// the lease, and the code that drives them is the same work.Runner a laptop
// runs — which is the point: one loop with one set of failure modes, rather
// than a local path and a remote path that drift.
//
// Concurrency is the number of sidecar workers the machine is configured for.
// How FAST they go is still the governor's business, upstream of this; what to
// work on is the queue's. That separation is what the queue bought.
func startLocalWorkers(ctx context.Context, cfg *config, db *store.Store, q *work.Queue, g *pace.Governor, n int, log *slog.Logger) {
	if n < 1 {
		n = 1
	}
	bin := cfg.Audit.SidecarPath
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("witness#%d", i)
		r := &work.Runner{
			Name: name,
			Log:  log.With("worker", name),
			Next: func(ctx context.Context) (work.Assignment, error) {
				return q.Lease(name, nil)
			},
			Verify: func(ctx context.Context, origin string, epoch int64) (string, string, error) {
				return akdVerify(ctx, bin, origin, epoch)
			},
			Acquire: func(ctx context.Context) (func(), error) {
				if g == nil {
					return func() {}, nil
				}
				if err := g.Acquire(ctx); err != nil {
					return nil, err
				}
				return g.Release, nil
			},
			Report: func(ctx context.Context, res work.Result) error {
				if err := q.Accept(res); err != nil {
					return err
				}
				return recordWorkerResult(db, res, log)
			},
		}
		go func() {
			if err := r.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("local worker stopped", "name", name, "err", err)
			}
		}()
	}
	log.Info("local workers leasing from the shared queue", "count", n)
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
