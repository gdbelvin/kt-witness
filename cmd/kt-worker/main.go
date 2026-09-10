// kt-worker verifies transparency-log epochs on somebody else's machine and
// reports the verdicts back.
//
// # Why this exists
//
// The witness is CPU-bound: 31 of its 32 cores busy while its link runs at 40%
// of capacity. The cheapest cores available are the ones already in the room. A
// laptop with hardware SHA does about nine times the per-core hashing of the
// 2017 Xeon the witness runs on, and spends most of the day idle.
//
// # What it is careful about
//
// It runs in the background quality-of-service class, on the efficiency cores.
// This is not the operator's work — it is a favour the machine is doing — and a
// worker that makes a laptop unpleasant to use will be turned off, which
// verifies nothing at all.
//
// It claims no authority. It reports what it computed and the root the operator
// signed; the witness decides what that means, re-runs a sample itself, and
// treats any disagreement as its own problem to resolve rather than as a
// finding about anybody.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/gdbsecurity/kt-witness/internal/hostmem"
	"github.com/gdbsecurity/kt-witness/internal/pace"
	"github.com/gdbsecurity/kt-witness/internal/work"
	pb "github.com/gdbsecurity/kt-witness/internal/workpb"
	"github.com/gdbsecurity/kt-witness/internal/workrpc"
)

// version is stamped for the Hello message, so the witness's log says which
// build of a worker is talking to it.
const version = "0.1.0"

func main() {
	var (
		// The LAN address the witness publishes the work channel on, not its
		// public name: this is a gRPC channel confined to this network, and the
		// public site does not speak it.
		// No default: the only correct value is one machine on one private
		// network, so a baked-in default is right for exactly one operator and
		// wrong — confusingly, at connect time — for everyone else.
		server     = flag.String("server", "", "the witness to work for, host:port on this LAN (required)")
		name       = flag.String("name", hostname(), "how this worker identifies itself")
		origins    = flag.String("origins", "", "comma-separated origins this worker can verify (default: whatever it is offered)")
		tokenEnv   = flag.String("token-env", "KT_WORK_TOKEN", "environment variable holding the shared token")
		dry        = flag.Bool("dry-run", false, "take assignments and report them unverified, to exercise the channel")
		cpus       = flag.Int("cpus", 0, "logical CPUs this worker may use in total (default: every efficiency core plus two performance cores)")
		eCores     = flag.Bool("efficiency-cores-only", false, "macOS: run in the background QoS class, which confines every thread to the efficiency cores and throttles disk I/O. Uses less of the machine, and is the only setting under which the laptop genuinely does not feel slower")
		akdOrigins = flag.String("akd-origins", "meta.messenger.kt/v1,whatsapp.kt/v2", "AKD logs this worker will verify")
		protonBin  = flag.String("proton-bin", "", "path to kt-proton-gpu")
		protonDir  = flag.String("proton-dir", "", "directory holding the retained Proton tree and manifest")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *server == "" {
		log.Error("no witness to work for", "flag", "-server",
			"note", "give the LAN host:port of the witness's work channel, e.g. -server 192.168.0.10:18090")
		os.Exit(2)
	}

	// Check where this is pointed before the token goes anywhere near it.
	if err := workrpc.CheckDialAddr(*server); err != nil {
		log.Error("refusing to connect", "server", *server, "err", err)
		os.Exit(2)
	}

	token := os.Getenv(*tokenEnv)
	if token == "" {
		log.Error("no token", "env", *tokenEnv,
			"note", "the witness closes the work channel when no token is set, rather than opening it")
		os.Exit(2)
	}

	mode, budget, err := background(*eCores)
	if err != nil {
		// Not fatal. A worker that cannot lower its own priority is merely
		// rude, and refusing to run would trade a real contribution for a
		// preference.
		log.Warn("could not lower this process's priority; continuing at normal priority", "err", err)
		mode = "normal priority"
	}
	if *cpus > 0 {
		// The operator's number wins over anything derived here. This is their
		// machine, and the derived figure is a guess about how they use it.
		budget = *cpus
		runtime.GOMAXPROCS(budget)
		mode += fmt.Sprintf(", overridden to %d CPUs", budget)
	}
	log.Info("kt-worker", "server", *server, "name", *name, "scheduling", mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Split the CPU budget into epochs and threads.
	//
	// One epoch is not one core. The sidecar runs a multi-threaded runtime and
	// takes ~3.7 cores on its own for a WhatsApp proof, so counting epochs as
	// cores would overshoot the budget by nearly four times — the first version
	// of this would have run four epochs at once on a budget of eight and used
	// closer to fifteen.
	//
	// Fewer, wider processes rather than many narrow ones: a proof is held in
	// memory while it is checked (40 MB for WhatsApp, gigabytes for Meta), so
	// concurrency costs memory in a way threads inside one process do not, and
	// finishing an epoch sooner also returns it to the queue sooner.
	// The budget is a HARD ceiling on threads: epochs times threads-per-epoch
	// never exceeds it.
	//
	// An earlier version divided the budget by what an epoch was measured to
	// cost — 2.3 cores against a 4-thread cap — reasoning that a proof spends
	// real time arriving before there is anything to hash, so the threads sit
	// idle for part of it. That measurement was taken on ONE epoch running
	// alone, and it does not survive concurrency: with three in flight, one
	// epoch's download overlaps another's hashing, every thread becomes
	// runnable, and the machine sees the full twelve. Observed on this laptop —
	// two sidecars at 401% and 226% of a core, a load average of 9 on ten
	// cores, and an owner who noticed.
	//
	// An average is the wrong shape for a promise about somebody's laptop. The
	// promise was two cores left free; only a ceiling keeps it.
	epochThreads := 4
	if epochThreads > budget {
		epochThreads = budget
	}
	parallel := budget / epochThreads
	if parallel < 1 {
		parallel = 1
		epochThreads = budget
	}
	// Cap by memory as well as cores.
	//
	// The core budget says nothing about RAM, and a verification is measured in
	// gigabytes: 0.61 GB for a WhatsApp epoch and about 3.7 GB for a Meta one,
	// which is why the estimate follows the origins this worker actually
	// serves. Without this a worker sits inside its core budget while pushing
	// its host into swap — which it did, killing two of the operator's
	// background tasks while reporting itself healthy on two of eight cores.
	//
	// Half of what is available, because the other half belongs to whoever owns
	// the machine. If the figure cannot be read at all the cap is not applied:
	// an unknown is not permission to assume there is room, but neither is it
	// grounds to refuse to work — the CPU budget still bounds this, and the
	// worker says out loud that it is flying blind.
	perEpoch := perEpochMemory(strings.Split(*akdOrigins, ","))
	if avail, ok := hostmem.Available(); ok {
		byMem := int(uint64(float64(avail)*0.5) / perEpoch)
		if byMem < 1 {
			byMem = 1
		}
		if byMem < parallel {
			log.Info("memory is the tighter constraint, not cores",
				"available_gb", float64(avail)/(1<<30),
				"per_epoch_gb", float64(perEpoch)/(1<<30),
				"epochs_by_cpu", parallel, "epochs_by_memory", byMem)
			parallel = byMem
		}
	} else {
		log.Warn("cannot read available memory; pacing on cores alone",
			"note", "a worker within its core budget can still push its host into swap")
	}

	log.Info("cpu budget", "logical_cpus", budget, "epochs_at_once", parallel,
		"threads_per_epoch", epochThreads, "threads_total", parallel*epochThreads,
		"memory_per_epoch_gb", float64(perEpoch)/(1<<30))

	w := &worker{
		parallel:     parallel,
		epochThreads: epochThreads,
		budget:       budget,
		server:       *server,
		name:         *name,
		token:        token,
		dry:          *dry,
		log:          log,
	}
	// Everything this worker needs arrives from the witness: the proof over the
	// LAN, the epoch in the assignment. No log directories, no config file, no
	// internet — and no knowledge of the roots it is expected to produce, which
	// is what makes its answer worth anything.
	w.verifiers = map[string]verifier{}
	for _, o := range strings.Split(*akdOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			w.verifiers[o] = akdVerifier{}
		}
	}
	if *protonBin != "" && *protonDir != "" {
		w.verifiers["proton.me/kt/v1"] = protonGPUVerifier{bin: *protonBin, dir: *protonDir}
	}
	// Declare exactly what we can do. Left empty the witness may hand out
	// anything, and a worker that reports every epoch unavailable is worse than
	// one that never connected.
	if *origins != "" {
		w.origins = strings.Split(*origins, ",")
	} else {
		for o := range w.verifiers {
			w.origins = append(w.origins, o)
		}
	}
	if len(w.origins) == 0 && !*dry {
		log.Error("no verifiers configured", "hint", "set -akd-bin or -proton-bin, or use -dry-run")
		os.Exit(2)
	}

	// Reconnect on any failure. A laptop closes its lid, changes network, and
	// sleeps; none of those should need a human to restart anything, and the
	// witness reclaims an abandoned lease on its own.
	backoff := time.Second
	for ctx.Err() == nil {
		if err := w.run(ctx); err != nil && ctx.Err() == nil {
			log.Warn("disconnected", "err", err, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
	log.Info("stopped", "verified", w.verified.Load())
}

type worker struct {
	server, name, token string
	parallel            int
	epochThreads        int
	budget              int // logical CPUs this worker may use
	origins             []string
	dry                 bool
	log                 *slog.Logger
	// verifiers by origin. A worker declares only the origins it has a
	// verifier for, so it is never handed work it would report as unavailable
	// — which from the witness's side looks exactly like the log being down.
	verifiers map[string]verifier

	verified atomic.Int64
}

// run opens one session and works it with the same loop the witness runs.
//
// The assignment stream and the result stream are the two ends of one
// bidirectional RPC; work.Runner does not know that. It asks for an assignment
// and reports a verdict, and whether those cross a network or a function call
// is the only difference between this worker and the ones inside the witness.
func (w *worker) run(ctx context.Context) error {
	// How many epochs at once, decided in main from this machine's CPU budget:
	// every efficiency core plus two performance cores, split into processes
	// wide enough that one epoch actually uses the threads it is given.
	par := w.parallel

	creds := insecure.NewCredentials() // the channel is confined to this LAN

	// Keepalives, because a dead session and a quiet one look identical.
	//
	// This worker reconnects on any failure — a lid closing, a network
	// changing, the witness restarting — but only once it LEARNS the session
	// is gone. Without keepalives it does not: a half-open connection leaves
	// Recv blocked forever, and that is not hypothetical. This laptop sat in a
	// session it believed was open across two restarts of the witness, doing
	// nothing, reporting nothing, and logging nothing, while its reconnect loop
	// waited for an error that was never going to arrive.
	//
	// PermitWithoutStream keeps the probe running between assignments, which is
	// most of the time on an idle fleet and exactly when a machine is most
	// likely to sleep.
	ka := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.NewClient(w.server,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(ka))
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+w.token)
	stream, err := pb.NewWorkClient(conn).Session(ctx)
	if err != nil {
		return err
	}

	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{Hello: &pb.Hello{
		Name:    w.name,
		Origins: w.origins,
		// Declare what will actually be done, not what the machine has. The
		// witness sizes assignments from this, and an overstated figure only
		// buys ranges that miss their deadline.
		Parallel: int32(par),
		Version:  version,
		Protocol: work.ProtocolVersion,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}}}); err != nil {
		return err
	}
	w.log.Info("session open", "server", w.server, "origins", w.origins)

	// Assignments arrive on the stream; the runner consumes them from here.
	// Acks are read in the same place and surfaced, because a worker that is
	// being refused should say so in its OWN log rather than only the
	// witness's.
	assignments := make(chan work.Assignment, 4)
	recvErr := make(chan error, 1)
	go func() {
		defer close(assignments)
		for {
			msg, err := stream.Recv()
			if err != nil {
				// Logged here rather than only handed to the runner: the
				// runner may be paced back and not asking, in which case
				// nothing would ever read this and the session would die in
				// silence.
				if ctx.Err() == nil {
					w.log.Warn("session ended", "err", err)
				}
				recvErr <- err
				return
			}
			switch m := msg.Msg.(type) {
			case *pb.WitnessMessage_Assignment:
				a := m.Assignment
				assignments <- work.Assignment{
					ID: a.Id, Origin: a.Origin, From: a.From, To: a.To,
					Nonce: a.Nonce, Deadline: time.Unix(a.DeadlineUnix, 0),
					ProofBase: a.ProofBase,
					Step:      int64(a.Step), Block: a.Block,
				}
			case *pb.WitnessMessage_Ack:
				if !m.Ack.Accepted {
					w.log.Warn("result refused", "assignment", m.Ack.AssignmentId,
						"epoch", m.Ack.Epoch, "reason", m.Ack.Reason)
				}
			}
		}
	}()

	// This worker's own governor, measuring THIS machine.
	//
	// The background QoS class decides WHERE threads run; this decides whether
	// to take on more work at all. They are different questions: a laptop
	// pinned to its efficiency cores can still make itself unpleasant if it
	// keeps several sidecar processes resident while somebody is using it.
	//
	// The budget is machine-wide, and deliberately generous about everybody
	// else: half the laptop's logical cores, measured across all of them rather
	// than across the E-cores this worker is confined to. Budgeting against
	// GOMAXPROCS instead would compare a machine-wide measurement against a
	// four-core ceiling and conclude the laptop was overloaded the moment its
	// owner opened anything.
	//
	// This is a favour the machine is doing. A worker that gets switched off
	// because it made a laptop hot verifies nothing at all.
	gov := &pace.Governor{
		// The budget this worker was given, not a fraction of the machine: the
		// operator said which cores may be used, and a second, smaller number
		// derived here would quietly overrule that. On this laptop the derived
		// figure was five of ten, below the eight actually offered, so the gate
		// below never opened and the worker sat idle without saying why.
		TargetCores: float64(w.budget),
		// Room above the parallelism actually used, so "permits >= par" means
		// the machine has headroom rather than that the controller happens to
		// be sitting exactly at its ceiling.
		MaxConcurrent: par * 2,
		MinPermits:    1,
		Log:           w.log,
	}
	go gov.Run(ctx)

	// Say what this machine can currently do, unprompted, every half minute.
	//
	// The witness cannot work this out from the outside: a laptop that has been
	// closed, one whose owner is compiling something, and one that has crashed
	// all look identical from there — results simply stop. Reported, they are
	// three different pictures, and only one of them is a problem.
	//
	// Nothing is checked and nothing changes what the queue hands out. It is
	// for the operator to look at.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			load, budget := gov.Observed()
			if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Capacity{
				Capacity: &pb.Capacity{
					Parallel: int32(par), Cpus: int32(runtime.GOMAXPROCS(0)),
					LoadCores: load, BudgetCores: budget,
				}}}); err != nil {
				w.log.Debug("capacity report failed; the session is going away", "err", err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	r := &work.Runner{
		Name:     w.name,
		Log:      w.log,
		Parallel: work.Fixed(par),
		// The governor's whole remaining job: decide when to ask for more.
		//
		// It asks whether the machine can support the parallelism this worker
		// is about to use, so a laptop that somebody has started using simply
		// stops taking on ranges — while finishing the one it holds, because
		// abandoning that would strand a lease for no gain.
		BeforeNext: func(ctx context.Context) error {
			if !gov.Ready(float64(par)) {
				load, budget := gov.Observed()
				return fmt.Errorf("machine is using %.1f of %.1f cores allowed", load, budget)
			}
			return nil
		},
		Next: func(ctx context.Context) (work.Assignment, error) {
			select {
			case <-ctx.Done():
				return work.Assignment{}, ctx.Err()
			case a, ok := <-assignments:
				if !ok {
					return work.Assignment{}, <-recvErr
				}
				return a, nil
			}
		},
		Verify: func(ctx context.Context, origin string, epoch int64, proofBase string) (string, string, error) {
			v, ok := w.verifiers[origin]
			if !ok {
				return "", "", fmt.Errorf("no verifier configured for %s", origin)
			}
			return v.verify(ctx, origin, epoch, proofBase)
		},
		Report: func(ctx context.Context, res work.Result) error {
			if res.Err == "" {
				w.verified.Add(1)
			}
			return stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Result{Result: &pb.Result{
				AssignmentId: res.AssignmentID, Nonce: res.Nonce, Origin: res.Origin,
				Epoch:            res.Epoch,
				ComputedPrevRoot: res.ComputedPrev,
				ComputedCurrRoot: res.ComputedCurr,
				Worker:           res.Worker,
				DurationMs:       res.DurationMS, Error: res.Err,
			}}})
		},
	}
	return r.Run(ctx)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "worker"
	}
	return h
}

// perEpochMemory estimates the peak RSS of one verification, from the logs this
// worker is configured for.
//
// Measured rather than assumed: a WhatsApp epoch peaked at 0.61 GB on an M4,
// and a Meta epoch at about 3.7 GB on the witness — the difference tracks proof
// size, 50 MB against 279 MB. A single constant would either strand a
// WhatsApp-only worker at one epoch or let a Meta worker take six and swap.
//
// The larger estimate wins when a worker serves both, because it is the one
// that has to fit.
func perEpochMemory(origins []string) uint64 {
	const (
		whatsappPeak = 1 << 30               // 0.61 GB measured, rounded up
		metaPeak     = uint64(4) * (1 << 30) // 3.7 GB measured, rounded up
	)
	var peak uint64 = whatsappPeak
	for _, o := range origins {
		if strings.Contains(strings.TrimSpace(o), "meta") {
			peak = metaPeak
		}
	}
	return peak
}
