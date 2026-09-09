package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/pace"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
	"github.com/gdbsecurity/kt-witness/internal/workrpc"
)

// startWorkChannel serves verification work to machines on this network.
func startWorkChannel(ctx context.Context, cfg *config, db *store.Store, gov *pace.Governor,
	sidecar audit.Verifier, resolvers []audit.Resolver, timeout time.Duration,
	log *slog.Logger) (func() map[string]time.Time, error) {
	note, err := workrpc.CheckListenAddr(cfg.Work.Listen)
	if err != nil {
		return nil, err
	}
	if note != "" {
		// WARN because it is the one thing about this channel this process
		// cannot verify for itself, and a quiet line is how that gets lost.
		log.Warn("work channel confinement is enforced outside this process",
			"listen", cfg.Work.Listen, "note", note)
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
			return recordWorkerResult(db, q, r, log)
		},
		OnCapacity: func(worker string, c work.Capacity) {
			recordCapacity(worker, c)
		},
	}

	ln, err := net.Listen("tcp", cfg.Work.Listen)
	if err != nil {
		return nil, err
	}
	// Match the workers' keepalives, and let a worker probe between
	// assignments — an idle fleet is still a fleet, and a machine that sleeps
	// between ranges is the normal case rather than the exception. Without
	// this the server would treat those probes as abuse and close the session.
	g := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
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
	// The same derivation the sidecar pool uses, not a second guess at it.
	//
	// The config leaves sidecar_workers unset on purpose so the count follows
	// the container's memory limit; a local constant here would have sized the
	// local worker for four while the pool and the governor were sized for
	// eight, and nothing in the logs would have said which number was in force.
	local := cfg.Audit.SidecarWorkers
	if local < 1 {
		local = audit.DefaultWorkers()
	}
	startLocalWorkers(ctx, cfg, db, q, gov, sidecar, resolvers, timeout, local, log)

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
func recordWorkerResult(db *store.Store, q *work.Queue, r work.Result, log *slog.Logger) error {
	if r.Err != "" {
		// Unavailable is an answer, and the worker was right to send it rather
		// than retry on its own. Two things follow from it.
		//
		// It is recorded as a settled-but-unverified epoch, so coverage
		// reflects the gap rather than hiding it — an epoch nobody can fetch is
		// the finding this witness most wants to surface, not an error to
		// swallow. And it goes back to the queue, which may hand it to a
		// different machine; after a few attempts the queue stops, because at
		// that point the answer is the answer.
		attempt, again := q.Reschedule(r.Origin, r.Epoch)
		log.Info("epoch unavailable", "origin", r.Origin, "epoch", r.Epoch,
			"worker", r.Worker, "attempt", attempt, "rescheduled", again,
			"err", r.Err)
		return db.RecordAudit(&store.Audit{
			Origin: r.Origin, Epoch: r.Epoch, Sampled: true, Rate: 1,
			Strategy: "worker:" + r.Worker, Verified: false, Attempts: attempt,
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

var capacityOnce sync.Once

// recordCapacity publishes what a worker says it can currently do.
//
// A gauge per worker, so the shape over time is the fleet's shape: a laptop
// dropping to one at a time in the evening and back to four overnight is the
// governor doing its job, and that is worth being able to see. The witness's
// own worker reports through the same path, so it appears on the same graph as
// everybody else — which is the whole conceit of the queue.
//
// Advisory throughout. Nothing here is checked and nothing here changes what
// the queue hands out; a worker that lies about its capacity is lying to a
// dashboard.
func recordCapacity(worker string, c work.Capacity) {
	capacityOnce.Do(func() {
		metrics.Describe("kt_witness_worker_parallel", metrics.Gauge,
			"Epochs this worker is currently willing to verify at once")
		metrics.Describe("kt_witness_worker_cpus", metrics.Gauge,
			"Logical CPUs the worker may use (on a Mac in background QoS, its efficiency cores)")
		metrics.Describe("kt_witness_worker_load_cores", metrics.Gauge,
			"Cores in use across the worker's whole machine, as the worker measures it")
		metrics.Describe("kt_witness_worker_budget_cores", metrics.Gauge,
			"Cores the worker is holding itself to")
		metrics.Describe("kt_witness_worker_capacity_reported_unix", metrics.Gauge,
			"When this worker last reported its capacity; a stale value is a worker that stopped talking")
	})
	l := map[string]string{"worker": worker}
	metrics.Set("kt_witness_worker_parallel", l, float64(c.Parallel))
	metrics.Set("kt_witness_worker_cpus", l, float64(c.CPUs))
	metrics.Set("kt_witness_worker_load_cores", l, c.LoadCores)
	metrics.Set("kt_witness_worker_budget_cores", l, c.BudgetCores)
	metrics.Set("kt_witness_worker_capacity_reported_unix", l, float64(time.Now().Unix()))
}
