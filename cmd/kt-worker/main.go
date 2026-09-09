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
	"google.golang.org/grpc/metadata"

	"github.com/gdbsecurity/kt-witness/internal/pace"
	"github.com/gdbsecurity/kt-witness/internal/work"
	pb "github.com/gdbsecurity/kt-witness/internal/workpb"
)

// version is stamped for the Hello message, so the witness's log says which
// build of a worker is talking to it.
const version = "0.1.0"

func main() {
	var (
		server     = flag.String("server", "https://witness.gdbsecurity.com", "the witness to work for")
		name       = flag.String("name", hostname(), "how this worker identifies itself")
		origins    = flag.String("origins", "", "comma-separated origins this worker can verify (default: whatever it is offered)")
		tokenEnv   = flag.String("token-env", "KT_WORK_TOKEN", "environment variable holding the shared token")
		dry        = flag.Bool("dry-run", false, "take assignments and report them unverified, to exercise the channel")
		akdBin     = flag.String("akd-bin", "", "path to kt-akd-verify")
		akdOrigins = flag.String("akd-origins", "meta.messenger.kt/v1,whatsapp.kt/v2", "origins the AKD sidecar can verify")
		protonBin  = flag.String("proton-bin", "", "path to kt-proton-gpu")
		protonDir  = flag.String("proton-dir", "", "directory holding the retained Proton tree and manifest")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	token := os.Getenv(*tokenEnv)
	if token == "" {
		log.Error("no token", "env", *tokenEnv,
			"note", "the witness closes the work channel when no token is set, rather than opening it")
		os.Exit(2)
	}

	mode, err := background()
	if err != nil {
		// Not fatal. A worker that cannot lower its own priority is merely
		// rude, and refusing to run would trade a real contribution for a
		// preference.
		log.Warn("could not enter background scheduling; continuing at normal priority", "err", err)
		mode = "normal priority"
	}
	log.Info("kt-worker", "server", *server, "name", *name, "scheduling", mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w := &worker{
		server: *server,
		name:   *name,
		token:  token,
		dry:    *dry,
		log:    log,
	}
	w.verifiers = map[string]verifier{}
	if *akdBin != "" {
		for _, o := range strings.Split(*akdOrigins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				w.verifiers[o] = akdVerifier{bin: *akdBin}
			}
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
	// Parallelism is N-2: use the machine, and leave two.
	//
	// N here is GOMAXPROCS, which on a Mac is already the efficiency-core count
	// — so this is two spare of the cores this worker is allowed at all, not
	// two of the whole laptop. On a four-E-core machine that is two epochs at a
	// time, which is the intent: visible progress, invisible to whoever is
	// using the laptop.
	par := work.DefaultParallel()

	creds := insecure.NewCredentials() // the channel is confined to this LAN
	conn, err := grpc.NewClient(w.server, grpc.WithTransportCredentials(creds))
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
				recvErr <- err
				return
			}
			switch m := msg.Msg.(type) {
			case *pb.WitnessMessage_Assignment:
				a := m.Assignment
				assignments <- work.Assignment{
					ID: a.Id, Origin: a.Origin, From: a.From, To: a.To,
					Nonce: a.Nonce, Deadline: time.Unix(a.DeadlineUnix, 0),
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
		TargetCores: float64(runtime.NumCPU()) * 0.5,
		// Room above the parallelism actually used, so "permits >= par" means
		// the machine has headroom rather than that the controller happens to
		// be sitting exactly at its ceiling.
		MaxConcurrent: par * 2,
		MinPermits:    1,
		Log:           w.log,
	}
	go gov.Run(ctx)

	r := &work.Runner{
		Name:     w.name,
		Log:      w.log,
		Parallel: par,
		// The governor's whole remaining job: decide when to ask for more.
		//
		// It asks whether the machine can support the parallelism this worker
		// is about to use, so a laptop that somebody has started using simply
		// stops taking on ranges — while finishing the one it holds, because
		// abandoning that would strand a lease for no gain.
		BeforeNext: func(ctx context.Context) error {
			return gov.WaitForWork(ctx, float64(par))
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
		Verify: func(ctx context.Context, origin string, epoch int64) (string, string, error) {
			v, ok := w.verifiers[origin]
			if !ok {
				return "", "", fmt.Errorf("no verifier configured for %s", origin)
			}
			return v.verify(ctx, origin, epoch)
		},
		Report: func(ctx context.Context, res work.Result) error {
			if res.Verified {
				w.verified.Add(1)
			}
			return stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Result{Result: &pb.Result{
				AssignmentId: res.AssignmentID, Nonce: res.Nonce, Origin: res.Origin,
				Epoch: res.Epoch, Verified: res.Verified, Root: res.Root,
				SignedRoot: res.SignedRoot, Worker: res.Worker,
				DurationMs: res.DurationMS, Error: res.Err,
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
