package main

import (
	"context"
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
	verifier audit.Verifier, resolvers []audit.Resolver, timeout time.Duration,
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

	// The MINIMUM lease, not the lease. It used to be the whole answer, fixed at
	// twenty minutes — chosen when twenty-five epochs cost about that much
	// against the Rust subprocess. An epoch now costs a couple of seconds, so an
	// abandoned range was stranded for roughly fifty times longer than the work
	// would have taken, and a queue full of leases nobody is working looks
	// exactly like a queue that is busy. The queue now derives the deadline from
	// what epochs of that log have actually been costing; this floors it.
	lease := 2 * time.Minute
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
		ps.MayRead = q.LeasedBy
		// The environment wins over the config file here, and it is the only
		// setting in this program where that is true.
		//
		// deploy/witness.json is mounted read-only straight from the repository
		// — deliberately, because an earlier copy of it drifted and the witness
		// spent weeks cosigning ten logs out of seventy-seven while reporting
		// nothing wrong. But that makes the tracked file the deployed file, and
		// this particular value is the operator's LAN address, which is not
		// ours to publish. So it lives in .env beside the two Compose needs.
		//
		// Getting this wrong is quiet, which is why it is worth the special
		// case: workers would dial an address that is not the witness, every
		// proof fetch would fail, and the canaries — the only thing that catches
		// a worker reporting the published root without doing the work — would
		// simply never fire.
		proofBase = os.Getenv("KT_PROOF_HOST")
		if proofBase == "" {
			proofBase = cfg.Work.ProofHost
		}
		if proofBase == "" {
			// Falling back to the bound address is only sane when that address
			// is one a worker could dial. It is not: this listens on 0.0.0.0
			// inside a container — deliberately, because the host's LAN address
			// does not exist in that namespace — so the fallback advertises
			// "0.0.0.0:8091", which every worker resolves to its own loopback.
			//
			// The result would be a witness that starts, logs that it is
			// serving proofs, hands out work, and fails every single fetch:
			// each epoch recorded unverified, coverage corrupted in the one
			// direction that matters, and the canaries never firing. That is
			// not a hypothetical failure shape — stale workers wrote 3,300
			// false unverified epochs this way yesterday.
			//
			// So it is only a fallback when it could work, and otherwise this
			// refuses to start. The address now lives in .env rather than the
			// repository, which means "somebody forgot the env file" is a
			// realistic Tuesday and must not be survivable.
			if host, _, err := net.SplitHostPort(bound); err == nil {
				if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
					proofBase = bound
				}
			}
		}
		if proofBase == "" {
			return nil, fmt.Errorf("work.proof_listen is set but no address workers can dial: "+
				"set KT_PROOF_HOST (see deploy/infra.example.env) or work.proof_host. "+
				"The listener is on %s, which a worker would resolve to its own loopback", bound)
		}
		proofBase = "http://" + proofBase + "/proof"
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
		Proofs:    proofs,
		Token:     token,
		Log:       log,
		OnResult: func(r work.Result) error {
			return recordWorkerResult(ctx, db, q, proofs, resolvers, r, log)
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
	// What still needs auditing, asked of the store when somebody wants work.
	// There is no feeder and no queued list — see worksource.go.
	origins := cfg.Work.Origins
	if len(origins) == 0 {
		for _, l := range cfg.Logs {
			if l.Type == "akd" {
				origins = append(origins, l.Origin)
			}
		}
	}
	q.Origins = origins
	q.Source = storeSource(db, log)
	publishQueueDepth(ctx, q)

	// The witness's own verification, as ordinary participants on the same
	// queue. Nothing here is privileged and nothing bypasses the lease: local
	// work is just the worker with the shortest network path.
	// The same number the verifier itself reports, not a second guess at it.
	//
	// This used to be the Rust subprocess pool's size, derived from the
	// container's memory limit because a Rust verification peaked near 3.7 GB.
	// Asking the verifier is what keeps the local worker, the governor and the
	// thing doing the work from ending up with three different answers — which
	// they did: the local worker was sized for four while the pool and the
	// governor were sized for eight, and nothing in the logs said which was in
	// force.
	local := (&audit.GoVerifier{Concurrent: cfg.Audit.GoConcurrent}).Size()
	startLocalWorkers(ctx, cfg, db, q, gov, verifier, resolvers, timeout, local, log)

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
func recordWorkerResult(ctx context.Context, db *store.Store, q *work.Queue,
	proofs *workrpc.ProofServer, resolvers []audit.Resolver, r work.Result, log *slog.Logger) error {
	// Was this one of the proofs we corrupted?
	//
	// Its verdict is about the worker, not about the log, so it is never
	// recorded as an audit: writing "unverified" against an epoch that verifies
	// perfectly well would put a false hole in the coverage, which is the one
	// number this witness must not get wrong in that direction.
	if proofs != nil && proofs.WasCanary(r.Origin, r.Epoch) {
		// Decided on the ROOTS, not on a verdict field.
		//
		// This branch used to read r.Verified, which no worker sets and nothing
		// assigns until sixty lines below — so every canary counted as caught
		// and the alarm was unreachable. That was my regression: the protocol
		// stopped carrying a worker verdict when workers began reporting
		// computed roots, and this check was left reading the field that went
		// away. A detector that cannot fire is worse than none, because it
		// reads as evidence.
		//
		// A corrupted proof cannot rebuild the roots the operator published. So
		// a worker caught it if it reported an error or roots that do not
		// match; it missed it only by reporting the published values, which it
		// could not have computed from what it was given.
		ref, refErr := resolvePublished(ctx, resolvers, r.Origin, r.Epoch)
		caught := r.Err != "" || refErr != nil ||
			r.ComputedPrev != ref.PrevRoot || r.ComputedCurr != ref.CurrRoot
		if caught {
			metrics.Inc("kt_witness_worker_canary_caught_total", map[string]string{"worker": r.Worker})
			log.Info("worker rejected a corrupted proof, as it must",
				"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch, "reported", r.Err)
		} else {
			metrics.Inc("kt_witness_worker_canary_missed_total", map[string]string{"worker": r.Worker})
			log.Error("A WORKER RETURNED THE PUBLISHED ROOTS FOR A CORRUPTED PROOF — it "+
				"cannot have computed them from what it was served, so it is not verifying. "+
				"Every result it has reported must be treated as unproven",
				"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
				"assignment", r.AssignmentID)
		}
		// The epoch itself is still unaudited: this proof was corrupted on
		// purpose, so nobody has checked the real one. Put it back rather than
		// leaving a hole the feeder's cursor has already moved past.
		q.Reschedule(r.Origin, r.Epoch)
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
	// The comparison happens HERE, and only here.
	//
	// The worker sent two roots it rebuilt from the proof and was never told
	// what to expect. This witness resolves what the operator actually
	// published and checks them. That ordering is the whole security argument:
	// a worker that does not know the answer cannot report it without doing the
	// work, so there is no fabricated result to detect — there is no way to
	// produce one.
	ref, refErr := resolvePublished(ctx, resolvers, r.Origin, r.Epoch)
	if refErr != nil {
		// We could not learn what to compare against. That is our problem, not
		// the worker's, and it is emphatically not evidence about the log.
		log.Warn("cannot resolve the published roots for a worker result; re-queueing",
			"origin", r.Origin, "epoch", r.Epoch, "err", refErr)
		q.Reschedule(r.Origin, r.Epoch)
		return nil
	}

	matches := r.ComputedPrev == ref.PrevRoot && r.ComputedCurr == ref.CurrRoot
	if !matches {
		// A mismatch is a question, not a finding. It means one of: the worker
		// is broken, the worker is lying, or the log built its tree wrongly —
		// and those are not distinguishable from here. The strongest claim this
		// system makes belongs to the witness's own verifier, so the epoch is
		// recorded unverified and re-queued for this machine to settle.
		metrics.Inc("kt_witness_worker_mismatch_total", map[string]string{"worker": r.Worker})
		log.Error("A WORKER'S ROOTS DO NOT MATCH THE PUBLISHED ONES — recorded as "+
			"unverified and re-queued. No finding is made against the log until this "+
			"witness has verified the epoch itself",
			"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
			"computed_prev", r.ComputedPrev, "published_prev", ref.PrevRoot,
			"computed_curr", r.ComputedCurr, "published_curr", ref.CurrRoot)
		q.Reschedule(r.Origin, r.Epoch)
		return db.RecordAudit(&store.Audit{
			Origin: r.Origin, Epoch: r.Epoch, Sampled: true, Rate: 1,
			Strategy: "worker:" + r.Worker, Verified: false, Attempts: 1,
			DecidedAt: time.Now().UTC(),
		})
	}

	r.Verified = true
	// Counted against the machine that did it, so a graph can answer "did
	// adding that box help" — which by origin alone it cannot.
	metrics.Inc(audit.MetricByWorker,
		map[string]string{"worker": r.Worker, "origin": r.Origin})
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
	// Renamed, because the old name became a lie. There is no queue of pending
	// ranges any more: what needs auditing lives in the store, and
	// kt_witness_history_unverified_epochs is the number that answers "how much
	// is left". This one counts epochs that FAILED and are serving a backoff —
	// a different and smaller question, and one worth watching on its own.
	//
	// A gauge that keeps its old name while changing its meaning is how a
	// dashboard starts lying quietly. Two panels were doing exactly that
	// earlier today for a different reason.
	metrics.Describe("kt_witness_work_retry_pending", metrics.Gauge,
		"Epochs that failed and are waiting out a retry backoff, by log")
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
				metrics.Set("kt_witness_work_retry_pending", l, float64(pending[o]))
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

// resolvePublished asks the operator what it committed to for one epoch.
//
// The witness's own lookup, never the worker's: this is the value a worker must
// not be able to see, because knowing it is the only way to report it without
// verifying.
func resolvePublished(ctx context.Context, resolvers []audit.Resolver, origin string, epoch int64) (*audit.EpochRef, error) {
	for _, r := range resolvers {
		if r.Origin() == origin {
			return r.ResolveEpoch(ctx, epoch)
		}
	}
	return nil, fmt.Errorf("no resolver for %s", origin)
}
