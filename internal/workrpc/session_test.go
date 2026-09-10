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

// offer installs a Source over a range, so a queue has work without a feeder.
//
// The queue no longer holds a list of pending assignments: it asks a Source at
// the moment somebody wants work, and in production that Source reads the
// store. Here it is a range.
func offer(q *work.Queue, origin string, from, to int64) {
	q.Origins = append(q.Origins, origin)
	prev := q.Source
	q.Source = func(o string, after int64, n int) (int64, int64, bool) {
		if o != origin {
			if prev != nil {
				return prev(o, after, n)
			}
			return 0, 0, false
		}
		if after < from {
			after = from
		}
		if after > to {
			return 0, 0, false
		}
		last := after + int64(n) - 1
		if last > to {
			last = to
		}
		return after, last, true
	}
}

// TestAWorkerIsDispatchedAndItsResultRecorded walks the whole conversation:
// connect, be given a range, report on it, be acknowledged.
func TestAWorkerIsDispatchedAndItsResultRecorded(t *testing.T) {
	q := work.NewQueue(time.Minute)
	offer(q, "m/kt", 10, 12)

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
		Hello: &pb.Hello{Name: "laptop", Origins: []string{"m/kt"},
			Parallel: 3, Protocol: work.ProtocolVersion}}}); err != nil {
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
		ComputedPrevRoot: "aa", ComputedCurrRoot: "bb"}}}); err != nil {
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
	offer(q, "m/kt", 1, 3)
	s := &Server{Queue: q, Token: "t", Idle: 20 * time.Millisecond,
		OnResult: func(work.Result) error { return nil }}

	ctx, cancel := context.WithTimeout(authed(context.Background(), "t"), 5*time.Second)
	defer cancel()
	stream, _ := dial(t, s).Session(ctx)
	stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{Hello: &pb.Hello{Name: "w", Parallel: 3, Protocol: work.ProtocolVersion}}})
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

// A worker is given what it asks for, and no more.
//
// This test used to assert the opposite arrangement — one range at a time,
// nothing further until the last was fully reported. That was itself a
// correction: before it, the dispatcher leased and sent in a tight loop and
// handed the whole queue to whichever worker connected first, every range
// counting down its own lease inside one stream's buffer, unworkable, while
// every other machine was told there was no work. Nothing looked broken; the
// coverage rate was simply a fraction of the hardware.
//
// One-at-a-time fixed that and was the other error. A forty-core box and a
// laptop got the same thing, and the pipeline drained at every boundary —
// twenty-three seconds between ranges of twelve epochs on a machine that could
// work eight at once.
//
// The number was never the witness's to choose. The worker knows its own
// capacity, has always reported it, and now asks with it.
func TestAWorkerIsGivenWhatItAsksForAndNoMore(t *testing.T) {
	q := work.NewQueue(time.Minute)
	offer(q, "m/kt", 1, 500)

	s := &Server{Queue: q, Token: "s3cret", Idle: 10 * time.Millisecond,
		OnResult: func(work.Result) error { return nil }}

	ctx, cancel := context.WithTimeout(authed(context.Background(), "s3cret"), 5*time.Second)
	defer cancel()
	stream, err := dial(t, s).Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Hello's parallel is the opening request, so this one asks for 4.
	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{
		Hello: &pb.Hello{Name: "laptop", Origins: []string{"m/kt"},
			Parallel: 4, Protocol: work.ProtocolVersion}}}); err != nil {
		t.Fatal(err)
	}

	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	a := first.GetAssignment()
	if a == nil {
		t.Fatalf("expected an assignment, got %+v", first)
	}
	if n := a.To - a.From + 1; n != 4 {
		t.Errorf("asked for 4 epochs in Hello, was given %d (%d..%d)", n, a.From, a.To)
	}

	// One reader for the rest of the test. A gRPC stream has a single receiver
	// — a second goroutine calling Recv would steal the message the assertion
	// below is waiting for, which is a test bug that looks exactly like a
	// dispatcher that never sent anything.
	msgs := make(chan *pb.WitnessMessage, 8)
	go func() {
		defer close(msgs)
		for {
			m, err := stream.Recv()
			if err != nil {
				return
			}
			msgs <- m
		}
	}()

	// Nothing more arrives unasked. The witness does not decide when to send.
	select {
	case m := <-msgs:
		if b := m.GetAssignment(); b != nil {
			t.Fatalf("a second range (%s) was pushed without being asked for", b.Id)
		}
	case <-time.After(300 * time.Millisecond):
	}

	// Ask again, larger, and get a larger range — without having finished the
	// first. That is the whole point: the pipeline does not drain.
	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Want{
		Want: &pb.Want{Epochs: 16}}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no second range after asking for one")
		case m, ok := <-msgs:
			if !ok {
				t.Fatal("the stream closed before a second range arrived")
			}
			b := m.GetAssignment()
			if b == nil {
				continue
			}
			if b.Id == a.Id {
				t.Fatalf("the same range was handed out twice: %s", b.Id)
			}
			if n := b.To - b.From + 1; n != 16 {
				t.Errorf("asked for 16 epochs, was given %d", n)
			}
			if b.From <= a.To {
				t.Errorf("second range %d..%d overlaps the first %d..%d, which is still out",
					b.From, b.To, a.From, a.To)
			}
			return
		}
	}
}

// A worker on the wrong protocol is refused, not served.
//
// This is the check that was missing when two workers ran a build one commit
// old and wrote roughly 3,300 false "unverified" epochs. Protobuf fields are
// positional, so a stale worker does not fail — its old verdict lands in the
// field now called computed_prev_root, the roots do not match, and the witness
// records that as a fact about the LOG. A false hole in the coverage is the one
// error this witness must not make in that direction, and it was making it
// silently.
func TestAWorkerOnTheWrongProtocolIsRefused(t *testing.T) {
	q := work.NewQueue(time.Minute)
	offer(q, "m/kt", 1, 1)
	s := &Server{Queue: q, Token: "s3cret", Idle: 10 * time.Millisecond,
		OnResult: func(work.Result) error { return nil }}

	ctx, cancel := context.WithTimeout(authed(context.Background(), "s3cret"), 5*time.Second)
	defer cancel()
	stream, err := dial(t, s).Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// An older build: no protocol field at all, which arrives as zero.
	if err := stream.Send(&pb.WorkerMessage{Msg: &pb.WorkerMessage_Hello{
		Hello: &pb.Hello{Name: "stale-laptop", Origins: []string{"m/kt"}, Version: "0.1.0"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("a worker on protocol 0 was given work; it would report roots that mean something else")
	}

	// And the work it was refused is still there for a worker that can do it.
	// Checked by leasing rather than by counting: "pending" no longer means a
	// queued list — the Source is the truth about what needs auditing.
	if _, err := q.Lease("good", []string{"m/kt"}, 1); err != nil {
		t.Errorf("refusing a stale worker consumed the work: %v", err)
	}
}
