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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

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

// run opens one session and works it until the stream ends.
//
// The session is bidirectional: assignments arrive as the witness frees them,
// results go back as they are produced, and both directions share one
// connection. A worker that vanishes is visible immediately — the stream closes
// — rather than only when its lease ages out.
func (w *worker) run(ctx context.Context) error {
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
		Name:     w.name,
		Origins:  w.origins,
		Parallel: int32(runtime.GOMAXPROCS(0)),
		Version:  version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}}}); err != nil {
		return err
	}
	w.log.Info("session open", "server", w.server, "origins", w.origins)

	// Acks arrive interleaved with assignments; read them off so the stream
	// does not stall, and surface a refusal because a worker that is being
	// refused should say so in its OWN log rather than only in the witness's.
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *pb.WitnessMessage_Assignment:
			w.do(ctx, stream, m.Assignment)
		case *pb.WitnessMessage_Ack:
			if !m.Ack.Accepted {
				w.log.Warn("result refused", "assignment", m.Ack.AssignmentId,
					"epoch", m.Ack.Epoch, "reason", m.Ack.Reason)
			}
		}
	}
}

// do works one assignment, streaming each verdict back as it is reached.
//
// Results go one at a time rather than in a batch at the end: an assignment can
// take many minutes, and a witness that learns nothing until the last epoch
// cannot tell a slow worker from a dead one.
func (w *worker) do(ctx context.Context, stream pb.Work_SessionClient, a *pb.Assignment) {
	deadline := time.Unix(a.DeadlineUnix, 0)
	w.log.Info("assignment", "id", a.Id, "origin", a.Origin, "from", a.From, "to", a.To,
		"lease", time.Until(deadline).Round(time.Second).String())

	for e := a.From; e <= a.To; e++ {
		if ctx.Err() != nil {
			return
		}
		// Past the deadline the witness refuses whatever we send and the range
		// may already belong to somebody else. Stopping is both the polite
		// thing and the only useful one.
		if time.Now().After(deadline) {
			w.log.Warn("lease expired mid-assignment; stopping", "id", a.Id, "reached", e)
			return
		}
		start := time.Now()
		res := &pb.Result{
			AssignmentId: a.Id, Nonce: a.Nonce, Origin: a.Origin,
			Epoch: e, Worker: w.name,
		}
		switch v, ok := w.verifiers[a.Origin]; {
		case w.dry:
			res.Error = "dry run"
		case !ok:
			res.Error = "no verifier configured for " + a.Origin
		default:
			ec, cancel := context.WithTimeout(ctx, epochTimeout)
			root, signed, err := v.verify(ec, a.Origin, e)
			cancel()
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Root, res.SignedRoot = root, signed
				// The worker states what it computed and what the operator
				// signed. It does not decide what a disagreement means: that is
				// a claim about an operator's conduct, and it belongs to the
				// witness, which re-runs the epoch before believing it.
				res.Verified = root != "" && root == signed
			}
		}
		res.DurationMs = time.Since(start).Milliseconds()
		if res.Verified {
			w.verified.Add(1)
		}
		if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Result{Result: res}}); err != nil {
			w.log.Warn("sending result", "epoch", e, "err", err)
			return
		}
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "worker"
	}
	return h
}
