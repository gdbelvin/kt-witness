package workrpc

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
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
	Token    string
	Log      *slog.Logger

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
	s.track(hello.Name, true)
	defer s.track(hello.Name, false)
	if s.Log != nil {
		s.Log.Info("worker connected", "name", hello.Name, "origins", hello.Origins,
			"parallel", hello.Parallel, "platform", hello.Platform)
	}

	ctx := stream.Context()
	errc := make(chan error, 1)

	// Push assignments until the worker goes away.
	go func() { errc <- s.dispatch(ctx, stream, hello) }()

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

func (s *Server) dispatch(ctx context.Context, stream pb.Work_SessionServer, hello *pb.Hello) error {
	idle := s.Idle
	if idle <= 0 {
		idle = 2 * time.Second
	}
	t := time.NewTimer(idle)
	defer t.Stop()
	for {
		a, err := s.Queue.Lease(hello.Name, hello.Origins)
		if err == nil {
			send := &pb.WitnessMessage{Msg: &pb.WitnessMessage_Assignment{
				Assignment: &pb.Assignment{
					Id: a.ID, Origin: a.Origin, From: a.From, To: a.To,
					Nonce: a.Nonce, DeadlineUnix: a.Deadline.Unix(),
				}}}
			if err := stream.Send(send); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, work.ErrNoWork) {
			return err
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(idle)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (s *Server) handleResult(stream pb.Work_SessionServer, worker string, r *pb.Result) {
	res := work.Result{
		AssignmentID: r.AssignmentId, Nonce: r.Nonce, Origin: r.Origin, Epoch: r.Epoch,
		Verified: r.Verified, Root: r.Root, SignedRoot: r.SignedRoot,
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
