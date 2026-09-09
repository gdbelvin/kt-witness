package work

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestTheHostGateIsAskedBeforeEveryEpoch.
//
// Pacing belongs to the machine doing the work, not to the one handing it out.
// A witness cannot know what else a laptop is doing, so the gate is consulted
// per epoch and its refusal is respected rather than worked around.
func TestTheHostGateIsAskedBeforeEveryEpoch(t *testing.T) {
	var mu sync.Mutex
	acquired, released := 0, 0

	r := &Runner{
		Name: "t",
		Acquire: func(ctx context.Context) (func(), error) {
			mu.Lock()
			acquired++
			mu.Unlock()
			return func() { mu.Lock(); released++; mu.Unlock() }, nil
		},
		Verify: func(context.Context, string, int64) (string, string, error) {
			return "aa", "aa", nil
		},
	}
	var got []Result
	r.Report = func(_ context.Context, res Result) error { got = append(got, res); return nil }

	r.do(context.Background(), Assignment{ID: "a", Origin: "m/kt", From: 1, To: 3}, time.Minute)

	mu.Lock()
	defer mu.Unlock()
	if acquired != 3 || released != 3 {
		t.Errorf("acquired=%d released=%d, want 3 and 3 — every epoch asks, and every one gives it back",
			acquired, released)
	}
	if len(got) != 3 {
		t.Errorf("reported %d results, want 3", len(got))
	}
}

// A host that says it is too busy stops the assignment rather than reporting
// epochs unverified. "This machine was busy" is not a fact about the log, and
// recording it as one would put a false hole in the coverage.
func TestARefusedGateStopsRatherThanReportingFailure(t *testing.T) {
	busy := errors.New("host is loaded")
	var reported []Result

	r := &Runner{
		Name:    "t",
		Acquire: func(context.Context) (func(), error) { return nil, busy },
		Verify: func(context.Context, string, int64) (string, string, error) {
			t.Fatal("verification ran despite the gate refusing")
			return "", "", nil
		},
		Report: func(_ context.Context, res Result) error { reported = append(reported, res); return nil },
	}
	r.do(context.Background(), Assignment{ID: "a", From: 1, To: 5}, time.Minute)

	if len(reported) != 0 {
		t.Errorf("a busy host reported %d results; it should report none", len(reported))
	}
}

// The lease is respected mid-assignment: past the deadline the range may
// already belong to somebody else, so continuing wastes the scarcest resource
// on results that will be refused.
func TestWorkStopsAtTheLeaseDeadline(t *testing.T) {
	var reported []Result
	r := &Runner{
		Name:   "t",
		Verify: func(context.Context, string, int64) (string, string, error) { return "aa", "aa", nil },
		Report: func(_ context.Context, res Result) error { reported = append(reported, res); return nil },
	}
	r.do(context.Background(), Assignment{
		ID: "a", From: 1, To: 100, Deadline: time.Now().Add(-time.Second),
	}, time.Minute)

	if len(reported) != 0 {
		t.Errorf("reported %d results past an expired lease", len(reported))
	}
}
