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
	"net"
	"net/http"
	_ "net/http/pprof"
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
		pprofAddr  = flag.String("pprof", "", "serve pprof on this address, e.g. 127.0.0.1:6060 (loopback only)")
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

	// pprof, when asked for, and on loopback only.
	//
	// This worker is mostly WAITING rather than computing — on a proof arriving,
	// on room in its own pool, on the witness answering a request — and a CPU
	// profile of a process that is idle says almost nothing. What answers "why
	// is this machine at one core of eight" is the goroutine dump: it shows
	// where the pool's goroutines actually are, and whether they are hashing or
	// blocked on a read.
	//
	//	go tool pprof -http=: http://127.0.0.1:6060/debug/pprof/profile?seconds=30
	//	curl -s 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1'
	//
	// Loopback is checked rather than documented: this endpoint exposes stack
	// traces and, through /debug/pprof/cmdline, the flags this process was
	// started with. On a borrowed machine that is somebody else's business.
	if *pprofAddr != "" {
		host, _, err := net.SplitHostPort(*pprofAddr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			log.Error("refusing to serve pprof off loopback", "addr", *pprofAddr,
				"note", "it exposes stack traces and this process's command line")
			os.Exit(2)
		}
		go func() {
			log.Info("pprof listening", "addr", *pprofAddr)
			srv := &http.Server{Addr: *pprofAddr, ReadHeaderTimeout: 5 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				log.Warn("pprof server stopped", "err", err)
			}
		}()
	}

	// Split the CPU budget into concurrent epochs.
	//
	// One epoch is one core, and the arithmetic is that simple because the
	// verifier is internal/akdtree: no goroutine anywhere in the package, so a
	// verification occupies exactly one. The width is asked of the verifier
	// rather than assumed — see epochsAtOnce — so if that ever stops being true
	// the division follows it.
	//
	// It was not always this simple, and the history is worth keeping because
	// every version of it was wrong in a way that only showed up on somebody's
	// laptop. Verification used to be a Rust subprocess with a multi-threaded
	// runtime that took ~3.7 cores of its own for a WhatsApp proof, so counting
	// epochs as cores overshot the budget nearly fourfold: four epochs on a
	// budget of eight used closer to fifteen.
	//
	// Then the budget was divided by what an epoch was MEASURED to cost — 2.3
	// cores against a 4-thread cap — reasoning that a proof spends real time
	// arriving before there is anything to hash, so the threads sit idle for
	// part of it. That measurement was taken on ONE epoch running alone and
	// does not survive concurrency: with three in flight, one epoch's download
	// overlaps another's hashing, every thread becomes runnable, and the
	// machine sees the full twelve. Observed on this laptop — two verifier
	// processes at 401% and 226% of a core, a load average of 9 on ten cores,
	// and an owner who noticed.
	//
	// The budget is a HARD ceiling: epochs times cores-per-epoch never exceeds
	// it.
	//
	// An average is the wrong shape for a promise about somebody's laptop. The
	// promise was two cores left free; only a ceiling keeps it.
	w := &worker{
		budget: budget,
		server: *server,
		name:   *name,
		token:  token,
		dry:    *dry,
		log:    log,
	}
	// Everything this worker needs arrives from the witness: the proof over the
	// LAN, the epoch in the assignment. No log directories, no config file, no
	// internet — and no knowledge of the roots it is expected to produce, which
	// is what makes its answer worth anything.
	// One verifier shared across origins, so what it learns about proof sizes
	// applies to the budget as a whole rather than per log.
	akdv := &akdVerifier{}
	w.verifiers = map[string]verifier{}
	for _, o := range strings.Split(*akdOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			w.verifiers[o] = akdv
		}
	}
	if *protonBin != "" && *protonDir != "" {
		w.verifiers["proton.me/kt/v1"] = protonGPUVerifier{bin: *protonBin, dir: *protonDir}
	}
	epochWidth, parallel := epochsAtOnce(budget, w.verifiers)

	// The memory cap is applied per assignment rather than once at startup,
	// because what a verification costs is not known until one has been done.
	// See parallelNow below.
	w.parallel = parallel
	log.Info("cpu budget", "logical_cpus", budget, "epochs_at_once", parallel,
		"cores_per_epoch", epochWidth,
		"note", "the verifier declares its own width; memory narrows this per assignment")

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
		log.Error("no verifiers configured",
			"hint", "set -akd-origins (verification is in this binary), or -proton-bin, or use -dry-run")
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
	budget              int // logical CPUs this worker may use
	origins             []string
	dry                 bool
	log                 *slog.Logger
	// verifiers by origin. A worker declares only the origins it has a
	// verifier for, so it is never handed work it would report as unavailable
	// — which from the witness's side looks exactly like the log being down.
	verifiers map[string]verifier

	verified atomic.Int64

	// gov paces this host. Built in run, read by width, which both the Runner
	// and the capacity report consult.
	gov pacer

	// lastWidth is what width reported last time, so it can say when the
	// number moves rather than on every capacity tick.
	lastWidth atomic.Int64
}

// pacer is what this worker needs from the governor, which is only ever
// questions. An interface so a test can put the controller in a state — no
// room at all, or nothing measured yet — that takes eighty samples and a
// simulated busy machine to reach for real, without reaching into
// internal/pace to do it.
type pacer interface {
	// Measured reports whether a usable sample exists yet.
	Measured() bool
	// Spare is how many more epochs this machine can currently afford.
	Spare() float64
	// Ready reports whether there is room for want concurrent verifications.
	Ready(want float64) bool
	// Observed is the last measured load and the ceiling, for saying so.
	Observed() (load, budget float64)
}

// epochsAtOnce splits a CPU budget into concurrent verifications, asking the
// things that do the work how wide each one is.
//
// This was a literal 4, measured against a Rust subprocess this worker no
// longer runs, and it divided the budget — so every machine in the fleet ran
// at a quarter of its width until somebody noticed a laptop sitting idle.
// internal/akdtree is single-threaded, so the answer is now one, and asking
// rather than assuming means it changes with the implementation instead of
// going stale beside it.
//
// The widest verifier sets the divisor. A narrower one then runs more copies
// than it strictly needs to keep the machine busy, which costs nothing; the
// other way round oversubscribes the CPU, which is what the promise about
// leaving cores free exists to prevent.
func epochsAtOnce(budget int, vs map[string]verifier) (width, parallel int) {
	width = 1
	for _, v := range vs {
		if n := v.width(); n > width {
			width = n
		}
	}
	if width > budget {
		width = budget
	}
	if width < 1 {
		width = 1
	}
	parallel = budget / width
	if parallel < 1 {
		parallel = 1
	}
	return width, parallel
}

// parallelNow is how many epochs to take on right now: the CPU budget decided
// at startup, narrowed by what the machine currently has spare.
//
// Two things move under this worker, and each is measured rather than assumed.
// Free memory changes because somebody opened a browser. What a verification
// costs changes because the proofs got bigger — a WhatsApp epoch is a few
// megabytes and a Meta one is nearly three hundred, and the same worker takes
// both. So the cost comes from the verifier, which knows the largest proof it
// has actually decoded, and until one has been decoded there is no cap at all:
// guessing high would idle the machine and guessing low would swap it.
//
// Half of free memory, because this is a background job on somebody's machine
// and the other half is theirs.
func (w *worker) parallelNow(origin string) int {
	par := w.parallel
	free, ok := hostmem.Available()
	if !ok {
		return par // unmeasurable; the CPU budget stands alone
	}
	var per uint64
	if v, ok := w.verifiers[origin]; ok && origin != "" {
		per = v.memoryPerEpoch(origin)
	} else {
		// No origin in hand — the capacity report and the gate before asking
		// for work, neither of which knows what it is about to be given. The
		// worst case across the logs this worker serves, because promising the
		// width of the smallest and being handed the largest is how a machine
		// swaps.
		for o, v := range w.verifiers {
			if n := v.memoryPerEpoch(o); n > per {
				per = n
			}
		}
	}
	if per == 0 {
		return par // nothing verified yet, so nothing to size against
	}
	fits := int(free / 2 / per)
	if fits < 1 {
		fits = 1 // one at a time still makes progress, and refusing does not
	}
	if fits < par {
		w.log.Debug("memory narrowed the epoch budget", "origin", origin,
			"cpu_allows", par, "memory_allows", fits,
			"free_bytes", free, "bytes_per_epoch", per)
		return fits
	}
	return par
}

// run opens one session and works it with the same loop the witness runs.
//
// The assignment stream and the result stream are the two ends of one
// bidirectional RPC; work.Runner does not know that. It asks for an assignment
// and reports a verdict, and whether those cross a network or a function call
// is the only difference between this worker and the ones inside the witness.
// width is what this worker will actually run for one assignment: the static
// figure narrowed by what the governor currently says the machine can afford.
//
// A method rather than a closure because two callers need the same answer. The
// capacity report used the static figure while the Runner used this one, so the
// graph the operator watches would have said eight while the machine ran four —
// a monitoring surface disagreeing with the thing it monitors, which is worse
// than no graph.
//
// The floor is one, not zero. By the time this is asked the range is already
// leased; declining to work it strands the lease without freeing anything,
// and one epoch at a time still makes progress. Refusing to take a range at all
// is a decision made earlier, in BeforeNext, while it is still free to make.
func (w *worker) width(origin string) int {
	n := w.parallelNow(origin)
	if !w.gov.Measured() {
		// Nothing seen yet — a cpuload sample needs an interval to exist. The
		// static figure is what the operator said this machine may use, and
		// narrowing below it is a claim that needs evidence.
		return n
	}
	spare := int(w.gov.Spare())
	if spare >= n {
		return n
	}
	if spare < 1 {
		spare = 1
	}
	// Only when the answer moves. The capacity report asks this every thirty
	// seconds, so an unconditional line here says the same thing a hundred and
	// twenty times an hour and buries the moment it actually changed.
	if w.lastWidth.Swap(int64(spare)) != int64(spare) {
		w.log.Info("the machine is busy; narrowing rather than stopping",
			"origin", origin, "would_run", n, "will_run", spare)
	}
	return spare
}

func (w *worker) run(ctx context.Context) error {
	// How many epochs at once, decided in main from this machine's CPU budget:
	// every efficiency core plus two performance cores, split into processes
	// wide enough that one epoch actually uses the threads it is given.
	par := w.parallelNow("")

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
	// holds several hundred-megabyte proofs resident while somebody is using
	// it.
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
		// The cap is the width itself, not double it.
		//
		// Doubling made sense while the gate asked "permits >= par", where the
		// extra room was what stopped the controller sitting on its own
		// threshold. Permits are now the width directly, and a cap above what
		// can be used is just integrator wind-up: on an idle box permits would
		// climb to sixteen, and the owner starting a compile would then need
		// six ticks — a minute and a half — before the number came back down
		// far enough to narrow anything. Capped at the width, it narrows within
		// two.
		MaxConcurrent: par,
		MinPermits:    1,
		Log:           w.log,
	}
	w.gov = gov
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
			load, budget := w.gov.Observed()
			if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Capacity{
				Capacity: &pb.Capacity{
					// The same answer the Runner gets, so the graph and the
					// machine agree.
					Parallel: int32(w.width("")), Cpus: int32(runtime.GOMAXPROCS(0)),
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
		Name: w.name,
		Log:  w.log,
		// The governor narrows the work rather than refusing it.
		//
		// This used to be the static figure, with the gate below asking whether
		// the machine could afford the FULL width. On a laptop those are the
		// same number — the budget is eight cores and eight epochs is eight
		// cores — so the controller sat exactly on its own threshold: it
		// reached eight permits only while idle, and running the work it had
		// just been allowed pushed it back under. The gate would then close,
		// the machine would go quiet, permits would climb, and it would open
		// again. Half a duty cycle spent waiting for a number to come back.
		//
		// Narrowing is also the better answer to the case the gate was written
		// for. Somebody starts a compile: the honest response is to verify two
		// epochs instead of eight, not to stop. Stopping altogether is reserved
		// for the machine genuinely belonging to someone else, which is what
		// permits falling to zero means and what the gate below now tests.
		Parallel: w.parallelNow,
		// The ceiling: this machine's CPU budget divided by what one epoch
		// costs, narrowed by memory. Both move slowly or not at all.
		//
		// Deliberately NOT w.width, which narrows further on measured load.
		// Until now that narrowing reached the Runner exactly once, at startup,
		// before the sampler had measured anything — so on this laptop it has
		// never actually limited anything, and the paragraph above describing
		// it as the pacing mechanism has been aspirational the whole time. What
		// does the pacing here is BeforeNext, and it demonstrably fires.
		//
		// Now that the Runner re-reads Parallel, passing width would make that
		// narrowing real for the first time: the water marks would follow a
		// one-minute load average that includes this worker's own bursts, on
		// the machine currently doing two thirds of the fleet's epochs. That is
		// a change in how hard somebody's laptop works, which is theirs to
		// make, not a side effect of fixing the witness. width still sets the
		// capacity report and still gates through the governor.
		Pool: par,
		// So the gate is now only the extreme case: is there room for anything
		// at all. Permits reach zero when everything else on the box already
		// exceeds this worker's whole budget — the owner is using their laptop
		// — and then the right thing is to take no new range, while finishing
		// the one in hand, because abandoning that strands a lease for no gain.
		BeforeNext: func(ctx context.Context) error {
			if !w.gov.Ready(1) {
				load, budget := w.gov.Observed()
				return fmt.Errorf("machine is using %.1f of %.1f cores allowed", load, budget)
			}
			return nil
		},
		// Ask, then wait for the answer. This is the pull.
		//
		// `want` is what the Runner has room for right now — slots free in its
		// pool plus the queue behind it — so a machine that has just finished
		// eight epochs asks for eight, and one whose owner came back asks for
		// two. The witness may answer with fewer or with nothing.
		//
		// A deadline on the wait, because "no work" arrives as silence: the
		// witness does not hold a request open, so an empty queue looks
		// identical to a slow one. Timing out and asking again costs a message
		// and keeps the two distinguishable from here.
		Next: func(ctx context.Context, want int) (work.Assignment, error) {
			if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Want{
				Want: &pb.Want{Epochs: int32(want)},
			}}); err != nil {
				return work.Assignment{}, err
			}
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			select {
			case <-wait.Done():
				if ctx.Err() != nil {
					return work.Assignment{}, ctx.Err()
				}
				return work.Assignment{}, work.ErrNoWork
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
