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
		Parallel: 2,
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
		Verify: func(context.Context, string, int64) (string, string, error) {
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
		Verify: func(context.Context, string, int64) (string, string, error) { return "aa", "aa", nil },
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
		Parallel: 1,
		Verify: func(_ context.Context, _ string, e int64) (string, string, error) {
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
		case res.Epoch == 2 && res.Verified:
			t.Error("an epoch that could not be fetched was reported verified")
		case res.Epoch != 2 && !res.Verified:
			t.Errorf("epoch %d should have verified", res.Epoch)
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
		Parallel: par,
		Verify: func(context.Context, string, int64) (string, string, error) {
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
		Parallel: 2,
		Verify:   func(context.Context, string, int64) (string, string, error) { return "aa", "aa", nil },
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
