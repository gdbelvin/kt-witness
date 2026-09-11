package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/store"
)

func genStore(t *testing.T, origin string, from, to int64) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.RecordHistory(&store.History{Origin: origin, From: from, To: to,
		Epochs: int(to - from + 1), VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return db
}

// markVerified writes the fixture.
//
// Kept small on purpose: RecordAudit takes its own transaction per call, so a
// ten-thousand-epoch fixture is ten thousand fsyncs and the test looks like a
// hang. None of these properties needs a long history to hold — they are about
// which direction a cursor moves, not how far.
func markVerified(t *testing.T, db *store.Store, origin string, from, to int64) {
	t.Helper()
	now := time.Now().UTC()
	for e := from; e <= to; e++ {
		if err := db.RecordAudit(&store.Audit{Origin: origin, Epoch: e,
			Verified: true, Sampled: true, DecidedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTheForwardCursorDoesNotRewind is the property that lets a steady state
// exist at all.
//
// The previous generator reset its cursor to zero whenever it found nothing
// from where it was. A log that is caught up has its first unverified epoch at
// the TIP, so that reset made every poll walk the entire verified history to
// rediscover it — 353ms across half a million epochs, every ten seconds, per
// log, growing linearly for as long as the log lives. That is not a slow steady
// state; it is the absence of one.
func TestTheForwardCursorDoesNotRewind(t *testing.T) {
	const o = "whatsapp.kt/v2"
	db := genStore(t, o, 1, 260)
	h := &store.History{Origin: o, From: 1, To: 260}
	markVerified(t, db, o, 1, 200)

	var c cursors
	c.init(db, o, h)

	// First pass finds the unverified region above the verified prefix.
	got := c.forward(db, o, h, 4)
	if len(got) != 4 || got[0] != 201 {
		t.Fatalf("first pass returned %v, want four epochs from 201", got)
	}
	after := c.fwd
	if after <= 200 {
		t.Fatalf("cursor at %d after finding work at 201", after)
	}

	// Everything verified: the cursor must PARK at the tip, not rewind.
	markVerified(t, db, o, 201, 260)
	if got := c.forward(db, o, h, 4); len(got) != 0 {
		t.Errorf("returned %v for a fully verified history", got)
	}
	if c.fwd < 200 {
		t.Errorf("cursor rewound to %d; the next published epoch appears at the "+
			"tip and this is what makes finding it cheap", c.fwd)
	}

	// A newly published epoch is found without re-walking anything.
	h.To = 261
	if got := c.forward(db, o, h, 4); len(got) != 1 || got[0] != 261 {
		t.Errorf("new epoch at the tip: got %v, want [261]", got)
	}
}

// TestTheBackwardCursorDescendsAndWraps. The history sweep is what finds gaps
// the forward pass went past — epochs that failed, or were never fetched. It
// must descend rather than sit, and must start over rather than stop.
func TestTheBackwardCursorDescendsAndWraps(t *testing.T) {
	const o = "m/kt"
	db := genStore(t, o, 1, 300)
	h := &store.History{Origin: o, From: 1, To: 300}
	markVerified(t, db, o, 1, 300)

	// One hole, well below the tip.
	if err := db.RecordAudit(&store.Audit{Origin: o, Epoch: 100,
		Verified: false, Sampled: true, DecidedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	var c cursors
	c.init(db, o, h)
	c.fwd, c.back = 300, 300
	c.stride = 32 // so the fixture need not be thousands of epochs long

	// Descending, it must reach the hole within a bounded number of probes
	// rather than needing one poll per epoch.
	found := false
	start := c.back
	for i := 0; i < 20 && !found; i++ {
		for _, e := range c.backward(db, o, h, 4) {
			if e == 100 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the sweep did not reach the gap at 100 (cursor %d -> %d)", start, c.back)
	}
	if c.back >= start {
		t.Errorf("the backward cursor did not descend: %d -> %d", start, c.back)
	}
}

// TestCursorsSurviveARestart. Both are seeded from what the store already
// recorded, so a restart does not re-cover ground the last run covered — which
// on a half-million-epoch history is the difference between resuming and
// starting again.
func TestCursorsSurviveARestart(t *testing.T) {
	const o = "m/kt"
	db := genStore(t, o, 1, 100000)
	h := &store.History{Origin: o, From: 1, To: 100000} // no records written; only the watermarks matter
	if err := db.SetAuditProgress(o, 60000); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBackAuditProgress(o, 40000); err != nil {
		t.Skipf("no back-progress accessor to seed: %v", err)
	}

	var c cursors
	c.init(db, o, h)
	if c.fwd != 60000 {
		t.Errorf("forward cursor %d, want the recorded progress 60000", c.fwd)
	}
	if c.back != 40000 {
		t.Errorf("backward cursor %d, want the recorded back progress 40000", c.back)
	}
}

// TestTheBackwardSweepReturnsRunsNotSinglets.
//
// The first version took one epoch per stride, so every cached epoch was 512
// apart and Ready could never return a contiguous run. Nineteen of twenty
// assignments in production were a single epoch and throughput halved: the
// queue hands out what the cache holds, so a scattered cache is scattered work.
func TestTheBackwardSweepReturnsRunsNotSinglets(t *testing.T) {
	const o = "m/kt"
	db := genStore(t, o, 1, 300)
	h := &store.History{Origin: o, From: 1, To: 300}
	// Everything verified except a contiguous unswept block.
	markVerified(t, db, o, 1, 199)
	markVerified(t, db, o, 220, 300)

	var c cursors
	c.init(db, o, h)
	c.fwd, c.back = 300, 300
	c.stride = 64

	var got []int64
	for i := 0; i < 8 && len(got) < 8; i++ {
		got = append(got, c.backward(db, o, h, 8-len(got))...)
	}
	if len(got) < 4 {
		t.Fatalf("the sweep returned %v; the block at 200..219 is unverified", got)
	}
	// Consecutive, because the region is: that is what makes a run.
	runs := 1
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1]+1 {
			runs++
		}
	}
	if runs > 2 {
		t.Errorf("got %v — %d separate runs. A contiguous unverified region "+
			"should come back contiguous, or the queue can only hand out singlets",
			got, runs)
	}
}

// slowFetch is a proof server that never finishes, so a caller that waits for
// its downloads is a caller that hangs.
type slowFetch struct{ started chan struct{} }

func (s *slowFetch) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-r.Context().Done()
	return nil, r.Context().Err()
}

type genResolver struct{ origin string }

func (g genResolver) Origin() string { return g.origin }
func (g genResolver) ResolveEpoch(_ context.Context, e int64) (*audit.EpochRef, error) {
	return &audit.EpochRef{LogDirectory: "http://proofs.invalid", PrevRoot: "aa", CurrRoot: "bb"}, nil
}

// TestTheGeneratorDoesNotWaitForItsDownloads is the ceiling nobody could find.
//
// Each pass used to fire a wave of twenty-four fetches and block on wg.Wait()
// until the slowest returned. A Meta proof is 284 MB against WhatsApp's 40, so
// twenty-three slots idled while one straggler finished, and the pool was empty
// between waves. The visible symptom was that prefetch_workers did nothing:
// raising it from 32 to 96 on a 2 Gbit line moved the sustained rate from
// 746-764 to 717-751 Mbit/s, which is to say not at all. The knob was real, the
// generator just never asked for more than one wave.
//
// So the property is about RETURNING, not about rate: fillMore starts downloads
// and hands control back while they run. With a fetcher that never completes,
// the old code cannot return at all.
func TestTheGeneratorDoesNotWaitForItsDownloads(t *testing.T) {
	const origin = "whatsapp.kt/v2"
	db := genStore(t, origin, 1, 500)

	sf := &slowFetch{started: make(chan struct{}, 1)}
	pf := &audit.Prefetcher{
		Dir:     t.TempDir(),
		Origins: []string{origin},
		Workers: 8,
		Client:  &http.Client{Transport: sf},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var c cursors
	var inFlight atomic.Int64

	done := make(chan int, 1)
	go func() {
		done <- fillMore(ctx, db, pf, genResolver{origin}, origin, &c, 8, &inFlight, slog.New(
			slog.NewTextHandler(io.Discard, nil)))
	}()

	select {
	case n := <-done:
		if n == 0 {
			t.Fatal("nothing was started; the fixture is wrong, not the code")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fillMore did not return while downloads were in flight; " +
			"it is waiting for them, which is the barrier this removed")
	}

	// And they really are still running — otherwise the return proves nothing.
	select {
	case <-sf.started:
	case <-time.After(5 * time.Second):
		t.Error("no download ever started")
	}
	if n := inFlight.Load(); n == 0 {
		t.Error("in-flight count is zero after returning; the caller cannot pace itself")
	}
}
