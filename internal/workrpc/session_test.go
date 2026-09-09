package workrpc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/gdbsecurity/kt-witness/internal/work"
	pb "github.com/gdbsecurity/kt-witness/internal/workpb"
)

func dial(t *testing.T, s *Server) pb.WorkClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	s.Register(g)
	go g.Serve(lis)
	t.Cleanup(g.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewWorkClient(conn)
}

func authed(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// TestAWorkerIsDispatchedAndItsResultRecorded walks the whole conversation:
// connect, be given a range, report on it, be acknowledged.
func TestAWorkerIsDispatchedAndItsResultRecorded(t *testing.T) {
	q := work.NewQueue(time.Minute)
	q.Add("m/kt", 10, 12)

	var mu sync.Mutex
	var got []work.Result
	s := &Server{Queue: q, Token: "s3cret", Idle: 20 * time.Millisecond,
		OnResult: func(r work.Result) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, r)
			return nil
		}}

	ctx, cancel := context.WithTimeout(authed(context.Background(), "s3cret"), 5*time.Second)
	defer cancel()
	stream, err := dial(t, s).Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{
		Hello: &pb.Hello{Name: "laptop", Origins: []string{"m/kt"}}}}); err != nil {
		t.Fatal(err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	a := msg.GetAssignment()
	if a == nil || a.Origin != "m/kt" || a.From != 10 || a.To != 12 {
		t.Fatalf("unexpected first message: %+v", msg)
	}
	if a.Nonce == "" {
		t.Fatal("assignment carried no nonce")
	}

	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Result{Result: &pb.Result{
		AssignmentId: a.Id, Nonce: a.Nonce, Origin: a.Origin, Epoch: 11,
		Verified: true, Root: "aa", SignedRoot: "aa"}}}); err != nil {
		t.Fatal(err)
	}

	// The ack may be preceded by further assignments; find it.
	deadline := time.Now().Add(3 * time.Second)
	var ack *pb.Ack
	for ack == nil && time.Now().Before(deadline) {
		m, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		ack = m.GetAck()
	}
	if ack == nil || !ack.Accepted {
		t.Fatalf("result was not acknowledged: %+v", ack)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Epoch != 11 || got[0].Worker != "laptop" {
		t.Fatalf("recorded %+v", got)
	}
}

// A result with somebody else's nonce is refused, and the refusal is explained
// on the stream so the worker's own log shows why.
func TestAReplayedNonceIsRefusedAndExplained(t *testing.T) {
	q := work.NewQueue(time.Minute)
	q.Add("m/kt", 1, 3)
	s := &Server{Queue: q, Token: "t", Idle: 20 * time.Millisecond,
		OnResult: func(work.Result) error { return nil }}

	ctx, cancel := context.WithTimeout(authed(context.Background(), "t"), 5*time.Second)
	defer cancel()
	stream, _ := dial(t, s).Session(ctx)
	stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{Hello: &pb.Hello{Name: "w"}}})
	m, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	a := m.GetAssignment()

	stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Result{Result: &pb.Result{
		AssignmentId: a.Id, Nonce: "not-the-nonce", Epoch: 2}}})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if ack := msg.GetAck(); ack != nil {
			if ack.Accepted {
				t.Fatal("a replayed nonce was accepted")
			}
			if ack.Reason == "" {
				t.Error("refusal carried no reason for the worker's own log")
			}
			return
		}
	}
	t.Fatal("no ack for the refused result")
}

// The channel is closed when no token is configured, and a wrong token is
// refused. A missing secret must never read as "no secret needed".
func TestTheChannelIsClosedWithoutATokenAndRefusesAWrongOne(t *testing.T) {
	q := work.NewQueue(time.Minute)

	closed := &Server{Queue: q, Idle: time.Millisecond} // no token
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, _ := dial(t, closed).Session(authed(ctx, "anything"))
	st.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{Hello: &pb.Hello{Name: "w"}}})
	if _, err := st.Recv(); err == nil {
		t.Error("a witness with no token configured served work")
	}

	open := &Server{Queue: q, Token: "right", Idle: time.Millisecond}
	st2, _ := dial(t, open).Session(authed(ctx, "wrong"))
	st2.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{Hello: &pb.Hello{Name: "w"}}})
	if _, err := st2.Recv(); err == nil {
		t.Error("a wrong token was accepted")
	}
}
