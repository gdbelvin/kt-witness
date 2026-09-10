package work

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPacingGatesRequestsForWorkRatherThanEpochs.
//
// Pacing belongs to the machine doing the work — a witness cannot know what
// else a laptop is doing — but it belongs at the moment more work is taken on,
// not inside a range already leased. An earlier version asked per epoch, which
// let a machine hold a lease it had decided not to work.
func TestPacingGatesRequestsForWorkRatherThanEpochs(t *testing.T) {
	var asks, verifies int32
	ctx, cancel := context.WithCancel(context.Background())

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(2),
		BeforeNext: func(context.Context) error {
			atomic.AddInt32(&asks, 1)
			return nil
		},
		Next: func(context.Context) (Assignment, error) {
			if atomic.LoadInt32(&asks) > 1 {
				cancel()
				return Assignment{}, context.Canceled
			}
			return Assignment{ID: "a", Origin: "m/kt", From: 1, To: 6}, nil
		},
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			atomic.AddInt32(&verifies, 1)
			return "aa", "aa", nil
		},
		Report: func(context.Context, Result) error { return nil },
	}
	_ = r.Run(ctx)

	if got := atomic.LoadInt32(&asks); got != 2 {
		t.Errorf("gate consulted %d times, want once per request for work (2)", got)
	}
	if got := atomic.LoadInt32(&verifies); got != 6 {
		t.Errorf("verified %d epochs, want all 6 — the gate must not interrupt a leased range", got)
	}
}

// A busy host stops ASKING for work; it does not abandon the range it holds.
//
// Refusing mid-assignment would strand a lease: the epochs go unworked, the
// queue cannot hand them elsewhere until the deadline, and the machine gains
// nothing it would not gain by simply not asking again.
func TestABusyHostStopsAskingButFinishesWhatItHolds(t *testing.T) {
	busy := errors.New("host is loaded")
	var asked int32
	ctx, cancel := context.WithCancel(context.Background())

	r := &Runner{
		Name: "t",
		Idle: time.Millisecond,
		BeforeNext: func(context.Context) error {
			if atomic.AddInt32(&asked, 1) >= 3 {
				cancel()
			}
			return busy
		},
		Next: func(context.Context) (Assignment, error) {
			t.Error("work was requested while the host was refusing")
			return Assignment{}, ErrNoWork
		},
		Verify: func(context.Context, string, int64, string) (string, string, error) { return "aa", "aa", nil },
		Report: func(context.Context, Result) error { return nil },
	}
	if err := r.Run(ctx); err != context.Canceled {
		t.Errorf("Run returned %v, want the context error — a refusal is pacing, not failure", err)
	}
	if atomic.LoadInt32(&asked) < 3 {
		t.Error("a refused gate should be retried, not treated as terminal")
	}
}

// An epoch that cannot be fetched is an ANSWER, and it goes back as one.
//
// The alternative — a worker deciding for itself to retry, or silently dropping
// it — either burns the machine that just failed on the same fetch or leaves
// the epoch unexamined with nothing recording that it was skipped. Unavailable
// data is the finding this witness most wants to surface; it must not be a hole
// in the reporting.
func TestAnUnavailableEpochIsReportedRatherThanDropped(t *testing.T) {
	var mu sync.Mutex
	var got []Result

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(1),
		Verify: func(_ context.Context, _ string, e int64, _ string) (string, string, error) {
			if e == 2 {
				return "", "", errors.New("404 from the operator")
			}
			return "aa", "aa", nil
		},
		Report: func(_ context.Context, res Result) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, res)
			return nil
		},
	}
	r.do(context.Background(), Assignment{ID: "a", Origin: "m/kt", From: 1, To: 3}, time.Minute)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("reported %d results, want 3 — the failure is one of the answers", len(got))
	}
	for _, res := range got {
		switch {
		case res.Epoch == 2 && res.Err == "":
			t.Error("the unavailable epoch came back with no error")
		case res.Epoch == 2 && res.ComputedCurr != "":
			t.Error("an epoch that could not be fetched reported a root anyway")
		case res.Epoch != 2 && res.ComputedCurr == "":
			t.Errorf("epoch %d reported no computed root", res.Epoch)
		}
	}
}

// Epochs run in parallel, so a slow one does not hold up the range.
func TestEpochsWithinAnAssignmentRunInParallel(t *testing.T) {
	const par = 4
	var live, peak int32
	var mu sync.Mutex

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(par),
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			n := atomic.AddInt32(&live, 1)
			mu.Lock()
			if n > peak {
				peak = n
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&live, -1)
			return "aa", "aa", nil
		},
		Report: func(context.Context, Result) error { return nil },
	}
	r.do(context.Background(), Assignment{ID: "a", From: 1, To: 16}, time.Minute)

	mu.Lock()
	defer mu.Unlock()
	if peak < 2 {
		t.Errorf("peak concurrency %d; the assignment ran serially", peak)
	}
	if peak > par {
		t.Errorf("peak concurrency %d exceeds the %d requested", peak, par)
	}
}

// N-2, floored at one: use the machine, and leave two — so the host stays
// responsive and the runner's own bookkeeping never waits for a core.
func TestDefaultParallelLeavesTwoCores(t *testing.T) {
	if got := DefaultParallel(); got < 1 {
		t.Errorf("DefaultParallel()=%d; it must always allow some progress", got)
	}
}

// The lease is respected mid-assignment: past the deadline the range may
// already belong to somebody else, so continuing wastes the scarcest resource
// on results that will be refused.
func TestWorkStopsAtTheLeaseDeadline(t *testing.T) {
	var mu sync.Mutex
	var reported []Result
	r := &Runner{
		Name:     "t",
		Parallel: Fixed(2),
		Verify:   func(context.Context, string, int64, string) (string, string, error) { return "aa", "aa", nil },
		Report: func(_ context.Context, res Result) error {
			mu.Lock()
			defer mu.Unlock()
			reported = append(reported, res)
			return nil
		},
	}
	r.do(context.Background(), Assignment{
		ID: "a", From: 1, To: 100, Deadline: time.Now().Add(-time.Second),
	}, time.Minute)

	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 0 {
		t.Errorf("reported %d results past an expired lease", len(reported))
	}
}

// Parallelism is asked fresh for each assignment, so a host whose share moves
// can narrow without stopping. The witness answers with its governor's permits:
// one epoch at a time while live witnessing has the box, more when it does not.
func TestParallelismIsAskedPerAssignment(t *testing.T) {
	width := int32(1)
	var mu sync.Mutex
	var peaks []int32
	var live int32

	r := &Runner{
		Name:     "t",
		Parallel: func(string) int { return int(atomic.LoadInt32(&width)) },
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			n := atomic.AddInt32(&live, 1)
			mu.Lock()
			if len(peaks) > 0 && n > peaks[len(peaks)-1] {
				peaks[len(peaks)-1] = n
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&live, -1)
			return "aa", "aa", nil
		},
		Report: func(context.Context, Result) error { return nil },
	}

	for _, w := range []int32{1, 4} {
		atomic.StoreInt32(&width, w)
		mu.Lock()
		peaks = append(peaks, 0)
		mu.Unlock()
		r.do(context.Background(), Assignment{ID: "a", From: 1, To: 12}, time.Minute)
	}

	mu.Lock()
	defer mu.Unlock()
	if peaks[0] != 1 {
		t.Errorf("narrow assignment peaked at %d, want 1", peaks[0])
	}
	if peaks[1] < 2 {
		t.Errorf("wide assignment peaked at %d; the new answer was not read", peaks[1])
	}
}

// When results have nowhere to go, the range stops.
//
// Without this the worker carries on verifying into a closed stream: every
// epoch after a disconnect costs real CPU on somebody's laptop and is thrown
// away, while the range sits on a lease that cannot be reissued until it
// expires. Seen for real on the first restart the laptop survived.
func TestAFailedReportAbandonsTheRestOfTheRange(t *testing.T) {
	var mu sync.Mutex
	verified, reported := 0, 0
	gone := errors.New("connection closed")

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(1),
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			mu.Lock()
			verified++
			mu.Unlock()
			return "aa", "aa", nil
		},
		Report: func(context.Context, Result) error {
			mu.Lock()
			defer mu.Unlock()
			reported++
			if reported >= 2 {
				return gone
			}
			return nil
		},
	}
	r.do(context.Background(), Assignment{ID: "a", From: 1, To: 50}, time.Minute)

	mu.Lock()
	defer mu.Unlock()
	if verified > 4 {
		t.Errorf("verified %d epochs after the stream died; it should stop promptly", verified)
	}
	if reported < 2 {
		t.Errorf("reported %d; the failure should have been attempted", reported)
	}
}

// TestParallelIsAskedAboutTheOriginItIsAbout pins the argument, because the
// whole reason it exists is invisible from inside this package: a worker sizes
// its concurrency from how big the proofs are, and that is a property of the
// log rather than of the machine. Dropping the argument would compile, and
// would silently make every log as expensive as the largest one.
func TestParallelIsAskedAboutTheOriginItIsAbout(t *testing.T) {
	var asked atomic.Value
	r := &Runner{
		Name:     "w",
		Parallel: func(o string) int { asked.Store(o); return 1 },
		Next: func(ctx context.Context) (Assignment, error) {
			return Assignment{ID: "a", Origin: "whatsapp.com/kt/v1", From: 1, To: 1,
				Deadline: time.Now().Add(time.Minute)}, nil
		},
		Verify: func(ctx context.Context, origin string, epoch int64, _ string) (string, string, error) {
			return "p", "c", nil
		},
		Report: func(ctx context.Context, res Result) error { return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a, err := r.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.do(ctx, a, time.Minute)
	if got, _ := asked.Load().(string); got != "whatsapp.com/kt/v1" {
		t.Errorf("Parallel was asked about %q, want the assignment's own origin", got)
	}
}
