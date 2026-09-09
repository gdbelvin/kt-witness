package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
	"github.com/gdbsecurity/kt-witness/internal/workrpc"
)

// startWorkChannel serves verification work to machines on this network.
func startWorkChannel(ctx context.Context, cfg *config, db *store.Store, log *slog.Logger) (func() map[string]time.Time, error) {
	if err := workrpc.CheckListenAddr(cfg.Work.Listen); err != nil {
		return nil, err
	}
	env := cfg.Work.TokenEnv
	if env == "" {
		env = "KT_WORK_TOKEN"
	}
	token := os.Getenv(env)
	if token == "" {
		return nil, fmt.Errorf("work channel: %s is not set; a missing token closes "+
			"the channel rather than opening it", env)
	}

	lease := 10 * time.Minute
	if cfg.Work.Lease != "" {
		d, err := time.ParseDuration(cfg.Work.Lease)
		if err != nil {
			return nil, fmt.Errorf("work.lease: %w", err)
		}
		lease = d
	}

	q := work.NewQueue(lease)
	srv := &workrpc.Server{
		Queue: q,
		Token: token,
		Log:   log,
		OnResult: func(r work.Result) error {
			return recordWorkerResult(db, r, log)
		},
	}

	ln, err := net.Listen("tcp", cfg.Work.Listen)
	if err != nil {
		return nil, err
	}
	g := grpc.NewServer()
	srv.Register(g)
	go func() {
		<-ctx.Done()
		g.GracefulStop()
	}()
	go func() {
		if err := g.Serve(ln); err != nil && ctx.Err() == nil {
			log.Error("work channel stopped", "err", err)
		}
	}()
	// Feed it from the oldest unaudited epochs, which is the end this witness's
	// own downward sweep is furthest from.
	origins := cfg.Work.Origins
	if len(origins) == 0 {
		for _, l := range cfg.Logs {
			if l.Type == "akd" {
				origins = append(origins, l.Origin)
			}
		}
	}
	startWorkFeed(ctx, db, q, origins, log)

	// The witness's own verification, as ordinary participants on the same
	// queue. Nothing here is privileged and nothing bypasses the lease: local
	// work is just the worker with the shortest network path.
	local := cfg.Audit.SidecarWorkers
	if local < 1 {
		local = 4
	}
	startLocalWorkers(ctx, cfg, db, q, local, log)

	log.Info("work channel listening", "addr", cfg.Work.Listen, "lease", lease.String(),
		"origins", origins,
		"note", "local network only; not published through the tunnel")

	return srv.Workers, nil
}

// recordWorkerResult turns a worker's verdict into an audit record.
//
// The session has already established that the result answers work we handed
// out, to that worker, inside its lease. What is decided here is the only thing
// that matters: whether to believe it.
//
// A result is believed when it agrees with itself — the root reported equals
// the signed root reported. That catches corruption and truncation. It does NOT
// catch fabrication, because the operator's signed root is public and a worker
// that did nothing can report it; that is what spot-checking is for, and it is
// not built yet. Until it is, this channel should only be given to machines the
// operator controls, which is also why the listener refuses a public address.
func recordWorkerResult(db *store.Store, r work.Result, log *slog.Logger) error {
	if r.Err != "" {
		// Unavailable, not evidence. Recorded as a settled-but-unverified
		// epoch so coverage reflects the gap rather than hiding it.
		return db.RecordAudit(&store.Audit{
			Origin: r.Origin, Epoch: r.Epoch, Sampled: true, Rate: 1,
			Strategy: "worker:" + r.Worker, Verified: false, Attempts: 1,
			DecidedAt: time.Now().UTC(),
		})
	}
	if r.Verified && (r.Root == "" || r.Root != r.SignedRoot) {
		log.Error("refusing a worker result that claims verified while its own roots differ",
			"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
			"root", r.Root, "signed", r.SignedRoot)
		return fmt.Errorf("result is internally inconsistent")
	}
	if !r.Verified && r.Root != "" && r.SignedRoot != "" {
		// The worker says the construction failed. That is the strongest claim
		// this system makes and a worker does not get to make it: recorded as
		// unverified, shouted about, and left for the witness to re-run.
		log.Error("A WORKER REPORTS A CONSTRUCTION MISMATCH — recorded as unverified; "+
			"this witness must re-run the epoch itself before any finding is made",
			"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
			"worker_root", r.Root, "signed", r.SignedRoot)
	}
	if _, err := hex.DecodeString(r.Root); r.Root != "" && err != nil {
		return fmt.Errorf("root is not hex")
	}
	return db.RecordAudit(&store.Audit{
		Origin: r.Origin, Epoch: r.Epoch, Sampled: true, Rate: 1,
		Strategy: "worker:" + r.Worker, Verified: r.Verified, Attempts: 1,
		DecidedAt: time.Now().UTC(),
	})
}
