package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
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

	// Every proof a remote worker verifies is fetched from here, and one in a
	// hundred has a bit flipped.
	//
	// Serving all of them is the point. An earlier version served only the
	// corrupted ones, which labelled them: a worker had merely to refuse
	// anything arriving from the witness to score perfectly on every test while
	// verifying nothing. A test the subject can identify is not a test — it is
	// evidence for the wrong conclusion.
	//
	// What the worker still does for itself is resolve the roots, from the
	// operator's own listing. That is what keeps this honest: a proof this
	// witness corrupted cannot rebuild roots the operator published, so serving
	// the bytes lets us test a worker without letting us make one agree.
	var proofs *workrpc.ProofServer
	var proofBase string
	if addr := cfg.Work.ProofListen; addr != "" {
		byOrigin := map[string]audit.Resolver{}
		for _, r := range resolvers {
			byOrigin[r.Origin()] = r
		}
		fetch := func(origin string, epoch int64) (io.ReadCloser, int64, error) {
			r := byOrigin[origin]
			if r == nil {
				return nil, 0, fmt.Errorf("no resolver for %s", origin)
			}
			ref, err := r.ResolveEpoch(ctx, epoch)
			if err != nil {
				return nil, 0, err
			}
			url := fmt.Sprintf("%s/%d/%s/%s", strings.TrimSuffix(ref.LogDirectory, "/"),
				epoch, ref.PrevRoot, ref.CurrRoot)
			resp, err := http.Get(url)
			if err != nil {
				return nil, 0, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return nil, 0, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
			}
			return resp.Body, resp.ContentLength, nil
		}
		ps, bound, err := workrpc.NewProofServer(addr, log, fetch, cfg.Work.CanaryEvery)
		if err != nil {
			return nil, fmt.Errorf("proof server: %w", err)
		}
		proofs = ps
		proofBase = cfg.Work.ProofHost
		if proofBase == "" {
			proofBase = bound
		}
		proofBase = "http://" + proofBase
		log.Info("serving proofs to workers", "addr", bound, "workers_dial", proofBase,
			"canary_every", canaryEvery(cfg.Work.CanaryEvery),
			"note", "one proof in this many has a bit flipped; the worker is not told which")
	} else {
		log.Warn("not serving proofs; remote workers fetch their own and cannot be tested",
			"note", "a worker reporting the published root without verifying cannot be caught this way")
	}

	srv := &workrpc.Server{
		Queue:     q,
		ProofBase: proofBase,
		Token:     token,
		Log:       log,
		OnResult: func(r work.Result) error {
			return recordWorkerResult(db, q, proofs, r, log)
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
	publishQueueDepth(ctx, q)

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
func recordWorkerResult(db *store.Store, q *work.Queue, proofs *workrpc.ProofServer, r work.Result, log *slog.Logger) error {
	// Was this one of the proofs we corrupted?
	//
	// Its verdict is about the worker, not about the log, so it is never
	// recorded as an audit: writing "unverified" against an epoch that verifies
	// perfectly well would put a false hole in the coverage, which is the one
	// number this witness must not get wrong in that direction.
	if proofs != nil && proofs.WasCanary(r.Origin, r.Epoch) {
		if !r.Verified {
			metrics.Inc("kt_witness_worker_canary_caught_total", map[string]string{"worker": r.Worker})
			log.Info("worker rejected a corrupted proof, as it must",
				"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch, "reported", r.Err)
		} else {
			metrics.Inc("kt_witness_worker_canary_missed_total", map[string]string{"worker": r.Worker})
			log.Error("A WORKER PASSED A CORRUPTED PROOF AS VERIFIED — it is not verifying "+
				"anything, and every result it has reported must be treated as unproven. "+
				"Stop giving it work and re-audit what it claimed",
				"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
				"assignment", r.AssignmentID, "root_it_reported", r.Root)
		}
		return nil
	}
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
	if r.Verified {
		// Counted against the machine that did it, so a graph can answer
		// "did adding that box help" — which by origin alone it cannot.
		metrics.Inc(audit.MetricByWorker,
			map[string]string{"worker": r.Worker, "origin": r.Origin})
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
		metrics.Describe(audit.MetricByWorker, metrics.Counter,
			"Epochs verified, by the machine that verified them")
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

// publishQueueDepth exports what the queue holds, per origin.
//
// A worker that is idle because the queue is empty and one that is idle
// because it is broken look identical from every other angle, and the fleet
// graph shows only what workers claim they could do — not whether they were
// offered anything.
func publishQueueDepth(ctx context.Context, q *work.Queue) {
	metrics.Describe("kt_witness_work_queue_pending", metrics.Gauge,
		"Ranges waiting to be handed out, by log")
	metrics.Describe("kt_witness_work_queue_leased", metrics.Gauge,
		"Ranges currently held by a worker, by log")
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			pending, leased := q.Depth()
			// Report a zero for an origin that has drained, rather than
			// leaving its last non-zero value standing: a stale gauge here
			// would say the queue is full when it is empty, which is the exact
			// misreading this exists to prevent.
			for _, o := range knownOrigins(pending, leased) {
				l := map[string]string{"origin": o}
				metrics.Set("kt_witness_work_queue_pending", l, float64(pending[o]))
				metrics.Set("kt_witness_work_queue_leased", l, float64(leased[o]))
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

var seenQueueOrigins = map[string]bool{}

func knownOrigins(maps ...map[string]int) []string {
	for _, m := range maps {
		for o := range m {
			seenQueueOrigins[o] = true
		}
	}
	out := make([]string, 0, len(seenQueueOrigins))
	for o := range seenQueueOrigins {
		out = append(out, o)
	}
	return out
}
