package workrpc

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/gdbsecurity/kt-witness/internal/work"
	pb "github.com/gdbsecurity/kt-witness/internal/workpb"
)

// Server implements the Work service.
//
// One goroutine per session pushes assignments; the calling goroutine reads
// results. gRPC streams are safe for one concurrent sender and one receiver,
// which is exactly this shape, so no lock is needed on the stream itself.
type Server struct {
	pb.UnimplementedWorkServer

	Queue *work.Queue
	// OnResult records a result the session has already established is
	// answerable — right assignment, right nonce, inside the lease and the
	// range. Whether the EPOCH verified is this function's judgement, not the
	// worker's and not the session's.
	OnResult func(work.Result) error
	// OnCapacity records what a worker says it can currently do. Advisory:
	// nothing is checked and nothing changes what the queue hands out. It
	// exists so the operator can see a fleet yielding correctly, which from the
	// witness's own side is indistinguishable from a fleet that has broken.
	OnCapacity func(worker string, c work.Capacity)
	Token      string
	Log        *slog.Logger

	// ProofBase is where workers fetch proofs, put on every assignment so that
	// none of them is distinguishable by carrying it.
	ProofBase string

	// Proofs, when set, issues a per-session token and authorises reads against
	// the leases this queue has granted. Without it a worker could fetch any
	// epoch, including the neighbour that lets it skip the append-only check.
	Proofs *ProofServer

	// Idle is how long to wait before asking the queue again when it had
	// nothing. Short enough that a freed range is picked up promptly, long
	// enough that an idle fleet is not a busy loop.
	Idle time.Duration

	mu       sync.Mutex
	sessions map[string]time.Time
}

// Session is one worker's whole conversation.
func (s *Server) Session(stream pb.Work_SessionServer) error {
	if err := s.authorize(stream.Context()); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || hello.Name == "" {
		return status.Error(codes.InvalidArgument,
			"the first message must be a Hello naming the worker")
	}
	// A worker speaking a different protocol is refused rather than served.
	//
	// Silence is the danger here, not failure. Protobuf fields are positional,
	// so an old build's verdict arrives in the field now called
	// computed_prev_root, the roots do not match, and the witness records that
	// as a fact about the log — a false hole in the coverage, written
	// confidently. Two stale workers did exactly that.
	if hello.Protocol != work.ProtocolVersion {
		if s.Log != nil {
			s.Log.Error("refusing a worker that speaks a different protocol; rebuild it",
				"worker", hello.Name, "worker_protocol", hello.Protocol,
				"witness_protocol", work.ProtocolVersion, "worker_version", hello.Version)
		}
		return status.Errorf(codes.FailedPrecondition,
			"this witness speaks protocol %d and you sent %d — rebuild the worker",
			work.ProtocolVersion, hello.Protocol)
	}

	s.track(hello.Name, true)
	defer s.track(hello.Name, false)

	// One token per session, carried in the proof URLs this session is given.
	// A worker authenticates by using the URL it was handed, and the token dies
	// with the stream so a disconnected worker stops being able to read.
	proofBase := s.ProofBase
	if s.Proofs != nil && proofBase != "" {
		token, err := s.Proofs.Session(hello.Name)
		if err != nil {
			return status.Error(codes.Internal, "cannot issue a proof session")
		}
		defer s.Proofs.EndSession(token)
		proofBase = strings.TrimSuffix(proofBase, "/") + "/" + token
	}
	if s.Log != nil {
		s.Log.Info("worker connected", "name", hello.Name, "origins", hello.Origins,
			"parallel", hello.Parallel, "platform", hello.Platform)
	}

	ctx := stream.Context()
	errc := make(chan error, 1)

	// Requests for work, from the read loop below to the dispatcher.
	//
	// Buffered and non-blocking on send: a worker that asks faster than the
	// queue can answer should have its extra requests dropped, not queued.
	// Every Want carries the CURRENT room, so the newest one is the only true
	// number and a backlog of stale ones would hand out work against capacity
	// that no longer exists.
	wants := make(chan int, 1)

	// Hello's parallel is the opening request. Without it a worker would sit
	// silent until its own first Want, which costs a round of idle time on
	// every reconnect — and reconnects are routine: a lid closing, a network
	// changing, this witness restarting.
	//
	// A worker that declares nothing is given one epoch rather than none, and
	// told so. Nothing is the literal reading and it is the wrong failure: the
	// worker connects, is authorised, reports capacity, and silently never
	// receives work — which looks from every angle like an empty queue. One
	// epoch makes the misconfiguration visible in its own throughput instead.
	opening := int(hello.Parallel)
	if opening < 1 {
		opening = 1
		if s.Log != nil {
			s.Log.Warn("worker declared no parallelism; giving it one epoch at a time",
				"worker", hello.Name,
				"note", "set Hello.parallel, or send a Want — this worker will be very slow")
		}
	}
	wants <- opening

	// Answer requests until the worker goes away.
	go func() { errc <- s.dispatch(ctx, stream, hello, proofBase, wants) }()

	// Read results until the worker stops sending.
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if s.Log != nil {
				s.Log.Info("worker finished", "name", hello.Name)
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *pb.WorkerMessage_Result:
			s.handleResult(stream, hello.Name, m.Result)
		case *pb.WorkerMessage_Want:
			// Newest wins. A full buffer means an earlier request is still
			// unanswered, and this one supersedes it: both describe the same
			// worker's room, and only the later one is current.
			select {
			case wants <- int(m.Want.Epochs):
			default:
				select {
				case <-wants:
				default:
				}
				select {
				case wants <- int(m.Want.Epochs):
				default:
				}
			}
		case *pb.WorkerMessage_Capacity:
			if s.OnCapacity != nil {
				c := m.Capacity
				s.OnCapacity(hello.Name, work.Capacity{
					Parallel: int(c.Parallel), CPUs: int(c.Cpus),
					LoadCores: c.LoadCores, BudgetCores: c.BudgetCores,
				})
			}
		case *pb.WorkerMessage_Progress:
			// Nothing to do yet. Kept in the protocol because a slow worker and
			// a dead one are indistinguishable without it, and the difference
			// decides whether to reissue a range.
		case *pb.WorkerMessage_Hello:
			return status.Error(codes.InvalidArgument, "Hello may only be sent once")
		}
		select {
		case err := <-errc:
			return err
		default:
		}
	}
}

// dispatch answers requests for work. It does not decide when to send.
//
// It used to: lease a range, push it, then block until that range came back in
// full before leasing another. Every worker held exactly one range whatever its
// size — a forty-core box and a laptop got the same thing — and the pipeline
// drained at every boundary while the last epoch finished and an ack
// round-tripped. Before that it did the opposite and pushed forty ranges at
// whichever worker connected first, every one counting down a deadline it could
// not meet, while every other machine was told there was no work. One
// assignment at a time was the correction to that, and it was the other error.
//
// The worker knows its own capacity, has always reported it, and for a long
// time this only logged it. Now it asks and this answers.
func (s *Server) dispatch(ctx context.Context, stream pb.Work_SessionServer, hello *pb.Hello, proofBase string, wants <-chan int) error {
	for {
		var want int
		select {
		case <-ctx.Done():
			return nil
		case want = <-wants:
		}
		if want < 1 {
			continue
		}
		a, err := s.Queue.Lease(hello.Name, hello.Origins, want)
		if errors.Is(err, work.ErrNoWork) {
			// Nothing to give. The worker asks again on its own schedule
			// rather than this holding the request open, so a queue that fills
			// a moment later does not wait on a timer here.
			continue
		}
		if err != nil {
			return err
		}
		send := &pb.WitnessMessage{Msg: &pb.WitnessMessage_Assignment{
			Assignment: &pb.Assignment{
				Id: a.ID, Origin: a.Origin, From: a.From, To: a.To,
				Nonce: a.Nonce, DeadlineUnix: a.Deadline.Unix(),
				ProofBase: proofBase,
			}}}
		if err := stream.Send(send); err != nil {
			return err
		}
	}
}

func (s *Server) handleResult(stream pb.Work_SessionServer, worker string, r *pb.Result) {
	res := work.Result{
		AssignmentID: r.AssignmentId, Nonce: r.Nonce, Origin: r.Origin, Epoch: r.Epoch,
		ComputedPrev: r.ComputedPrevRoot, ComputedCurr: r.ComputedCurrRoot,
		Worker: worker, DurationMS: r.DurationMs, Err: r.Error,
	}
	ack := &pb.Ack{AssignmentId: r.AssignmentId, Epoch: r.Epoch, Accepted: true}

	// Does it answer work we handed out, to this worker, inside the lease? This
	// says nothing about whether the epoch verified.
	if err := s.Queue.Accept(res); err != nil {
		ack.Accepted, ack.Reason = false, err.Error()
	} else if s.OnResult != nil {
		if err := s.OnResult(res); err != nil {
			ack.Accepted, ack.Reason = false, err.Error()
		}
	}
	if !ack.Accepted && s.Log != nil {
		s.Log.Warn("refusing a worker result", "worker", worker,
			"assignment", r.AssignmentId, "epoch", r.Epoch, "reason", ack.Reason)
	}
	// Best effort: a worker that has gone away does not need to be told.
	_ = stream.Send(&pb.WitnessMessage{Msg: &pb.WitnessMessage_Ack{Ack: ack}})
}

// authorize checks the shared token in constant time.
//
// The listener is already confined to this network, so this is defence in
// depth rather than the boundary. It matters anyway: a LAN is not a trust
// domain, and the thing being protected is a published number.
func (s *Server) authorize(ctx context.Context) error {
	if s.Token == "" {
		return status.Error(codes.Unavailable,
			"the work channel is closed: no token is configured")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	var got string
	if v := md.Get("authorization"); len(v) > 0 {
		got = v[0]
	}
	want := "Bearer " + s.Token
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return status.Error(codes.Unauthenticated, "bad or missing token")
	}
	return nil
}

func (s *Server) track(name string, up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]time.Time{}
	}
	if up {
		s.sessions[name] = time.Now()
	} else {
		delete(s.sessions, name)
	}
}

// Workers lists the names currently connected, for the status page.
func (s *Server) Workers() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]time.Time, len(s.sessions))
	for k, v := range s.sessions {
		out[k] = v
	}
	return out
}

// Register installs the service on a gRPC server.
func (s *Server) Register(g *grpc.Server) { pb.RegisterWorkServer(g, s) }
