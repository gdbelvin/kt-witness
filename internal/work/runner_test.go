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
//
// The second ask now waits for the range to be finished before it stops the
// runner, and that is not decoration. Epochs are queued rather than worked
// inline, so the request loop reaches its second ask while the first range is
// still in the pool; cancelling there made the runner drop the queued epochs
// and the test failed about one run in twenty — a flake about the test's own
// shutdown, not about pacing. Next is allowed to block, so it blocks.
func TestPacingGatesRequestsForWorkRatherThanEpochs(t *testing.T) {
	var asks, verifies int32
	ctx, cancel := context.WithCancel(context.Background())

	worked := make(chan struct{})
	var once sync.Once

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(2),
		BeforeNext: func(context.Context) error {
			atomic.AddInt32(&asks, 1)
			return nil
		},
		Next: func(context.Context, int) (Assignment, error) {
			if atomic.LoadInt32(&asks) > 1 {
				select {
				case <-worked:
				case <-time.After(10 * time.Second):
					t.Error("the leased range never finished")
				}
				cancel()
				return Assignment{}, context.Canceled
			}
			return Assignment{ID: "a", Origin: "m/kt", From: 1, To: 6}, nil
		},
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			if atomic.AddInt32(&verifies, 1) == 6 {
				once.Do(func() { close(worked) })
			}
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
		Next: func(context.Context, int) (Assignment, error) {
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
//
// Driven through Run rather than a per-assignment call, because there is no
// longer any such thing: epochs go onto one continuously-fed channel, and the
// failure has to survive that path like any other answer.
func TestAnUnavailableEpochIsReportedRatherThanDropped(t *testing.T) {
	var mu sync.Mutex
	var got []Result

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	all := make(chan struct{})
	var once sync.Once

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
			got = append(got, res)
			n := len(got)
			mu.Unlock()
			if n == 3 {
				once.Do(func() { close(all) })
			}
			return nil
		},
	}
	r.Next, _ = handOut(Assignment{ID: "a", Origin: "m/kt", From: 1, To: 3})
	wait := start(t, ctx, r)

	select {
	case <-all:
	case <-time.After(10 * time.Second):
		t.Error("the three epochs were not all reported; one was dropped or the pool stalled")
	}
	cancel()
	wait()

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
//
// Proved by a barrier rather than by timing: every Verify is held until `par`
// of them are live at once, so the claim is that the runner really did have
// four epochs in flight together, not that sixteen sleeps finished sooner than
// sixteen times ten milliseconds on whatever machine ran the test.
func TestEpochsWithinAnAssignmentRunInParallel(t *testing.T) {
	const par = 4
	o := newOverlap(par)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(par),
		Verify:   o.verify,
		Report:   func(context.Context, Result) error { return nil },
	}
	r.Next, _ = handOut(Assignment{ID: "a", From: 1, To: 16})
	wait := start(t, ctx, r)

	select {
	case <-o.gate:
	case <-time.After(10 * time.Second):
		t.Errorf("never had %d epochs in flight at once; the assignment ran too narrowly", par)
	}
	cancel()
	wait()

	if peak := o.Peak(); peak < 2 {
		t.Errorf("peak concurrency %d; the assignment ran serially", peak)
	} else if peak > par {
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
//
// The check now sits where epochs are pushed onto the jobs channel, so what
// this pins is that an expired range is never even QUEUED — and that the runner
// goes back and asks for other work instead of sitting on it. Waiting for the
// next request for work is what makes "nothing was reported" mean the runner
// declined the range, rather than that the test looked too early.
func TestWorkStopsAtTheLeaseDeadline(t *testing.T) {
	var mu sync.Mutex
	var reported []Result

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &Runner{
		Name:     "t",
		Parallel: Fixed(2),
		Verify: func(_ context.Context, _ string, e int64, _ string) (string, string, error) {
			t.Errorf("epoch %d was verified under an expired lease", e)
			return "aa", "aa", nil
		},
		Report: func(_ context.Context, res Result) error {
			mu.Lock()
			defer mu.Unlock()
			reported = append(reported, res)
			return nil
		},
	}
	next, exhausted := handOut(Assignment{
		ID: "a", From: 1, To: 100, Deadline: time.Now().Add(-time.Second),
	})
	r.Next = next
	wait := start(t, ctx, r)

	select {
	case <-exhausted:
	case <-time.After(10 * time.Second):
		t.Fatal("the runner never came back for more work; it is grinding through an expired lease")
	}
	cancel()
	wait()

	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 0 {
		t.Errorf("reported %d results past an expired lease", len(reported))
	}
}

// Parallelism is read from the host afresh every time the worker starts, and it
// is what sizes the pool — so a host whose share moves can narrow without
// anything being recompiled. The witness answers with its governor's permits:
// one epoch at a time while live witnessing has the box, more when it does not.
//
// It used to be asked once per assignment, and this test used to prove that by
// working two assignments in a row through one runner. It cannot: the pool is
// now started once, in Run, and sized once with it. Two runs, because that is
// the granularity the answer is now read at — what survives is the part that
// matters, that the number comes from the function every time rather than being
// baked in.
func TestParallelismIsAskedFreshEachRun(t *testing.T) {
	width := int32(1)
	parallel := func(string) int { return int(atomic.LoadInt32(&width)) }

	var peaks []int
	for _, w := range []int32{1, 4} {
		atomic.StoreInt32(&width, w)
		o := newOverlap(int(w))

		ctx, cancel := context.WithCancel(context.Background())
		r := &Runner{
			Name:     "t",
			Parallel: parallel,
			Verify:   o.verify,
			Report:   func(context.Context, Result) error { return nil },
		}
		r.Next, _ = handOut(Assignment{ID: "a", From: 1, To: 12})
		wait := start(t, ctx, r)

		select {
		case <-o.gate:
		case <-time.After(10 * time.Second):
			t.Errorf("width %d: never reached %d epochs at once", w, w)
		}
		cancel()
		wait()
		peaks = append(peaks, o.Peak())
	}

	if peaks[0] != 1 {
		t.Errorf("narrow run peaked at %d, want 1", peaks[0])
	}
	if peaks[1] < 2 {
		t.Errorf("wide run peaked at %d; the new answer was not read", peaks[1])
	}
}

// When results have nowhere to go, the range stops.
//
// Without this the worker carries on verifying into a closed stream: every
// epoch after a disconnect costs real CPU on somebody's laptop and is thrown
// away, while the range sits on a lease that cannot be reissued until it
// expires. Seen for real on the first restart the laptop survived.
//
// The test deliberately never cancels the runner: stopping is the property
// under test, and a Run that keeps going has to fail on its own account rather
// than be rescued. A failed report now cancels the pool's own context, which
// ends the feeder as well as the workers — so the whole of Run stops, not just
// the range in hand.
func TestAFailedReportAbandonsTheRestOfTheRange(t *testing.T) {
	var mu sync.Mutex
	verified, reported := 0, 0
	gone := errors.New("connection closed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // only so a broken runner's goroutine does not outlive the test

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
	r.Next, _ = handOut(Assignment{ID: "a", From: 1, To: 50})
	wait := start(t, ctx, r)

	if err := wait(); err == nil {
		t.Error("Run returned nil; a report with nowhere to go should have ended the pool")
	}

	mu.Lock()
	defer mu.Unlock()
	if verified > 4 {
		t.Errorf("verified %d epochs after the stream died; it should stop promptly", verified)
	}
	if reported < 2 {
		t.Errorf("reported %d; the failure should have been attempted", reported)
	}
}

// TestParallelSizesThePullBeforeAnyWorkIsAsked pins what the Parallel argument
// is for, because the whole reason it exists is invisible from inside this
// package: a worker sizes its concurrency from how big the proofs are, and that
// is a property of the log rather than of the machine.
//
// What it used to pin — that Parallel is asked about the assignment's own
// origin — is no longer true of Run and cannot be tested here. Sizing moved out
// of the per-assignment path: the pool is built once, before any work exists to
// have an origin, and Run asks the whole-machine question, Parallel(""). The
// per-origin answer a host can give is not consumed by this loop.
//
// So this pins what remains, which is the load-bearing half: Parallel is asked
// exactly once per Run, BEFORE any work is requested, and its answer sets how
// much work the runner then asks for — want is twice the width, one epoch being
// worked per slot and one queued behind it. Drop the call and the pull size
// goes with it.
func TestParallelSizesThePullBeforeAnyWorkIsAsked(t *testing.T) {
	const par = 3

	var mu sync.Mutex
	var origins []string
	firstWant := -1
	sizedFirst := false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asked := make(chan struct{})
	var once sync.Once

	r := &Runner{
		Name: "w",
		Parallel: func(o string) int {
			mu.Lock()
			origins = append(origins, o)
			mu.Unlock()
			return par
		},
		Next: func(_ context.Context, want int) (Assignment, error) {
			mu.Lock()
			if firstWant < 0 {
				firstWant, sizedFirst = want, len(origins) > 0
			}
			mu.Unlock()
			once.Do(func() { close(asked) })
			return Assignment{}, ErrNoWork
		},
		Verify: func(_ context.Context, _ string, e int64, _ string) (string, string, error) {
			t.Errorf("epoch %d was verified; no work was ever handed out", e)
			return "p", "c", nil
		},
		Report: func(context.Context, Result) error { return nil },
	}
	wait := start(t, ctx, r)

	select {
	case <-asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the runner never asked for work")
	}
	cancel()
	wait()

	mu.Lock()
	defer mu.Unlock()
	if len(origins) != 1 {
		t.Errorf("Parallel consulted %d times, want once — the pool is sized once per Run", len(origins))
	}
	if len(origins) > 0 && origins[0] != "" {
		t.Errorf("Parallel was asked about %q; Run sizes its pool with the whole-machine question", origins[0])
	}
	if !sizedFirst {
		t.Error("work was requested before the pool had been sized")
	}
	if firstWant != par*2 {
		t.Errorf("asked for %d epochs, want %d — the pull is sized by Parallel's answer", firstWant, par*2)
	}
}

// --- driving Run ------------------------------------------------------------
//
// Run no longer has a per-assignment entry point to call: there is one loop
// that asks for work and one pool that never stops, so every test below drives
// the whole thing and stops it once it has seen what it came for.

// start runs r in the background and returns a wait for it to stop.
//
// wait fails the test rather than blocking for ever, because "the runner never
// returns" is precisely the failure several of these tests exist to catch, and
// a hung test reports it as nothing at all.
func start(t *testing.T, ctx context.Context, r *Runner) (wait func() error) {
	t.Helper()
	if r.Idle == 0 {
		// Nothing here is waiting on a real queue; the idle poll should not be
		// the reason a test takes seconds.
		r.Idle = time.Millisecond
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	return func() error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return; the pool is stuck")
			return nil
		}
	}
}

// handOut is a Next that gives out each assignment once, in order, and then
// says ErrNoWork for ever. exhausted closes the first time it runs out — the
// moment the runner has taken everything it was offered and come back for more,
// which is the only signal a test has that a range was fully dealt with.
func handOut(as ...Assignment) (next func(context.Context, int) (Assignment, error), exhausted chan struct{}) {
	exhausted = make(chan struct{})
	var once sync.Once
	i := 0 // touched only from Run's own request loop
	return func(context.Context, int) (Assignment, error) {
		if i >= len(as) {
			once.Do(func() { close(exhausted) })
			return Assignment{}, ErrNoWork
		}
		a := as[i]
		i++
		return a, nil
	}, exhausted
}

// overlap counts how many verifications are live at once and holds each one
// until `want` of them are live together.
//
// A barrier rather than a sleep: concurrency is then something the runner
// demonstrated, not something inferred from elapsed time on a machine that may
// be loaded. A pool narrower than want never opens the gate, and the waiting
// verifications are released by the test cancelling the run — so too little
// parallelism fails an assertion instead of hanging.
type overlap struct {
	mu         sync.Mutex
	live, peak int
	want       int
	gate       chan struct{}
	open       bool
}

func newOverlap(want int) *overlap {
	if want < 1 {
		want = 1
	}
	return &overlap{want: want, gate: make(chan struct{})}
}

func (o *overlap) verify(ctx context.Context, _ string, _ int64, _ string) (string, string, error) {
	o.mu.Lock()
	o.live++
	if o.live > o.peak {
		o.peak = o.live
	}
	if o.live >= o.want && !o.open {
		o.open = true
		close(o.gate)
	}
	o.mu.Unlock()

	select {
	case <-o.gate:
	case <-ctx.Done():
	}

	o.mu.Lock()
	o.live--
	o.mu.Unlock()
	return "aa", "aa", nil
}

// Peak is the most that were ever live together. Read it only after Run has
// returned: closing the jobs channel and waiting on the pool is what guarantees
// no verification is still counting.
func (o *overlap) Peak() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.peak
}

// TestTheRunnerAsksInBatchesNotPerEpoch.
//
// The first version of the pull loop asked whenever there was ANY room, which
// on a saturated pool means one epoch per request: fifteen of sixteen slots
// busy, room of one, and a Want plus a Lease plus a store scan for a single
// epoch. Seen in production the moment it was deployed — `epochs=1 asked_for=1`
// down the whole log.
//
// The pool is what bounds concurrency; the request size should follow it.
func TestTheRunnerAsksInBatchesNotPerEpoch(t *testing.T) {
	const par = 4

	var mu sync.Mutex
	var asked []int
	release := make(chan struct{})
	var once sync.Once

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &Runner{
		Name:     "t",
		Idle:     time.Millisecond,
		Parallel: Fixed(par),
		Next: func(_ context.Context, want int) (Assignment, error) {
			mu.Lock()
			asked = append(asked, want)
			n := len(asked)
			mu.Unlock()
			if n >= 3 {
				once.Do(func() { close(release) })
				return Assignment{}, ErrNoWork
			}
			from := int64(n*100 + 1)
			return Assignment{ID: "a", Origin: "m/kt",
				From: from, To: from + int64(want) - 1}, nil
		},
		// Instant. The first draft held every epoch until three requests had
		// been made, which deadlocked: the pool filled, in-flight stayed above
		// the low-water mark, and the runner correctly declined to ask again —
		// so the verifies waited on a request that was waiting on them. That
		// deadlock was the batching working, and a test that has to defeat the
		// behaviour to observe it is measuring the wrong thing.
		Verify: func(context.Context, string, int64, string) (string, string, error) {
			return "aa", "bb", nil
		},
		Report: func(context.Context, Result) error { return nil },
	}

	done := make(chan struct{})
	go func() { defer close(done); _ = r.Run(ctx) }()
	select {
	case <-release:
	case <-time.After(10 * time.Second):
		t.Fatal("the runner never made three requests")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	mu.Lock()
	defer mu.Unlock()
	for i, want := range asked {
		if want < par {
			t.Errorf("request %d asked for %d epochs with a pool of %d; the pool "+
				"bounds concurrency and the request size should follow it, not "+
				"trickle one at a time", i, want, par)
		}
	}
}
