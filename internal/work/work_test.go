package work

import (
	"fmt"
	"testing"
	"time"
)

func fixedQueue(t *testing.T, lease time.Duration) (*Queue, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	q := NewQueue(lease)
	q.now = func() time.Time { return now }
	// A lease that does not move under the test. leaseForLocked normally
	// derives it from what epochs have been costing, which is the right
	// behaviour and the wrong thing to have varying inside an assertion about
	// something else.
	q.minLease = lease
	q.perEpoch = map[string]time.Duration{}
	return q, &now
}

// offer installs a Source that always has work for one origin over a range.
//
// Most of these tests are about the lease, the nonce and the range check, not
// about which epochs are outstanding — so the simplest Source that keeps
// answering is the one that does not get in the way. Tests that care about
// completion install their own.
func offer(q *Queue, origin string, from, to int64) {
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

// TestNonceTiesAResultToOneDispatch.
//
// The operator's signed root is public, so a worker that did nothing can still
// report the correct answer. The nonce is what stops the cheapest version of
// that — replaying an earlier honest result as evidence of new work.
func TestNonceTiesAResultToOneDispatch(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "meta.messenger.kt/v1", 100, 110)

	a, err := q.Lease("laptop", nil, 11)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nonce == "" {
		t.Fatal("assignment handed out without a nonce")
	}

	good := Result{AssignmentID: a.ID, Nonce: a.Nonce, Epoch: 105}
	if err := q.Accept(good); err != nil {
		t.Errorf("a correctly answered assignment was refused: %v", err)
	}
	stale := Result{AssignmentID: a.ID, Nonce: "0000", Epoch: 105}
	if err := q.Accept(stale); err != ErrBadNonce {
		t.Errorf("a replayed nonce was accepted: %v", err)
	}
}

// A worker cannot report on epochs it was never given. Without this a single
// lease would let a worker claim the whole log.
func TestResultsMustFallInsideTheAssignedRange(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 100, 110)
	a, _ := q.Lease("laptop", nil, 11)

	for _, e := range []int64{99, 111, 5_000_000} {
		if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Epoch: e}); err == nil {
			t.Errorf("epoch %d outside %d..%d was accepted", e, a.From, a.To)
		}
	}
}

// TestExpiredLeasesReturnToTheQueue: a laptop that closes its lid must not
// strand a range forever, and its late results must not be accepted either —
// by then the work may have been handed to somebody else.
func TestExpiredLeasesReturnToTheQueue(t *testing.T) {
	q, now := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 1, 10)

	a, _ := q.Lease("laptop", nil, 11)
	if p, l := q.Stats(); p != 0 || l != 1 {
		t.Fatalf("after leasing: pending=%d leased=%d, want 0 and 1", p, l)
	}

	*now = now.Add(2 * time.Minute) // the lid closed

	if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Epoch: 5}); err != ErrLeaseExpired {
		t.Errorf("a result past its deadline was accepted: %v", err)
	}
	// The lease is gone. Nothing is put back on a list, because there is no
	// list: the Source still reports those epochs as needing audit, which is
	// what makes them available again.
	if _, l := q.Stats(); l != 0 {
		t.Fatalf("after expiry: leased=%d, want 0", l)
	}
	// And it is handed out again, with a fresh nonce so the abandoned worker's
	// late reply cannot answer the new dispatch.
	b, err := q.Lease("other", nil, 11)
	if err != nil {
		t.Fatal(err)
	}
	if b.Nonce == a.Nonce {
		t.Error("the reissued assignment reused the abandoned nonce")
	}
}

// A worker is only given work it says it can do. A worker with no AKD verifier
// handed AKD epochs would report every one of them unavailable, which from the
// witness's side looks exactly like the log being down.
func TestWorkersOnlyGetOriginsTheyDeclared(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "meta.messenger.kt/v1", 1, 10)
	offer(q, "proton.me/kt/v1", 1, 10)

	a, err := q.Lease("gpu-box", []string{"proton.me/kt/v1"}, 11)
	if err != nil {
		t.Fatal(err)
	}
	if a.Origin != "proton.me/kt/v1" {
		t.Errorf("got %s, want the only origin this worker declared", a.Origin)
	}
	if _, err := q.Lease("gpu-box", []string{"signal.org/kt"}, 11); err != ErrNoWork {
		t.Errorf("work was handed out for an origin nobody declared: %v", err)
	}
}

// An unavailable epoch goes back on the queue, and then stops.
//
// Retrying is worth doing because the failure may belong to the machine rather
// than the log — a laptop that lost its network is not evidence about anyone's
// tree. Retrying forever is not, because the failure this witness most often
// finds is data that has aged out permanently, and re-asking for it burns the
// scarce resource on a fact already recorded.
func TestAnUnavailableEpochIsRetriedAndThenAccepted(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }

	if n, again := q.Reschedule("m/kt", 42); !again || n != 1 {
		t.Fatalf("first failure: attempt=%d requeued=%v, want 1 and true", n, again)
	}

	// Held back by the backoff: handing it straight to the next worker would be
	// the same request into the same broken thing.
	if _, err := q.Lease("w", nil, 11); err != ErrNoWork {
		t.Errorf("a retry was leased before its backoff elapsed (%v)", err)
	}
	now = now.Add(2 * retryBase)
	a, err := q.Lease("w", nil, 11)
	if err != nil {
		t.Fatalf("after the backoff the retry should be available: %v", err)
	}
	if a.From != 42 || a.To != 42 {
		t.Errorf("retry covers %d..%d, want just epoch 42", a.From, a.To)
	}

	if n, again := q.Reschedule("m/kt", 42); !again || n != 2 {
		t.Fatalf("second failure: attempt=%d requeued=%v, want 2 and true", n, again)
	}
	if n, again := q.Reschedule("m/kt", 42); again {
		t.Errorf("attempt %d was requeued; after %d the answer is the answer", n, maxAttempts)
	}
}

// A finished range is released rather than left to time out.
//
// Nothing used to release one, and the symptom was invisible: the lease expired
// ten minutes later, reclaimLocked put the range back as though it had been
// abandoned, and every assignment was verified twice — halving a coverage rate
// with no error anywhere to explain it.
func TestAFinishedAssignmentIsReleasedRatherThanReclaimed(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }

	// A Source that stops offering what has been done — which is what the real
	// one does, since it asks the store and the store records each verdict.
	q.Origins = []string{"m/kt"}
	done := map[int64]bool{}
	q.Source = func(o string, after int64, n int) (int64, int64, bool) {
		for e := after; e <= 3; e++ {
			if e < 1 {
				e = 1
			}
			if !done[e] {
				last := e + int64(n) - 1
				if last > 3 {
					last = 3
				}
				return e, last, true
			}
		}
		return 0, 0, false
	}

	a, err := q.Lease("w", nil, 11)
	if err != nil {
		t.Fatal(err)
	}
	for e := a.From; e <= a.To; e++ {
		if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: e}); err != nil {
			t.Fatalf("epoch %d: %v", e, err)
		}
		done[e] = true
	}
	if pending, leased := q.Stats(); pending != 0 || leased != 0 {
		t.Errorf("after a complete range: pending=%d leased=%d, want 0 and 0", pending, leased)
	}

	now = now.Add(2 * time.Minute) // past what would have been the deadline
	if _, err := q.Lease("w", nil, 11); err != ErrNoWork {
		t.Error("a completed range came back through the reclaim path")
	}
}

// A partly-reported range still times out, because the rest of it was never done.
func TestAPartlyReportedAssignmentStillReturnsToTheQueue(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }

	offer(q, "m/kt", 1, 3)
	a, _ := q.Lease("w", nil, 11)
	if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	back, err := q.Lease("w2", nil, 11)
	if err != nil {
		t.Fatalf("an abandoned range must return to the queue: %v", err)
	}
	if back.From != 1 || back.To != 3 {
		t.Errorf("reclaimed %d..%d, want the whole range back", back.From, back.To)
	}
}

// The give-up must survive the path results actually take.
//
// Results go through Accept before anything reschedules them, and an earlier
// version cleared the attempt counter there unconditionally — so every failure
// looked like the first, the give-up at maxAttempts was unreachable, and a
// permanently-lost epoch would have been re-leased forever. A test that called
// Reschedule directly could not see it; this one drives the real sequence.
func TestRetriesTerminateAlongTheRealResultPath(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }
	offer(q, "m/kt", 7, 7)

	var last bool
	for i := 1; i <= maxAttempts; i++ {
		now = now.Add(time.Hour) // past any backoff
		a, err := q.Lease("w", nil, 11)
		if err != nil {
			t.Fatalf("attempt %d: nothing to lease (%v)", i, err)
		}
		res := Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: 7,
			Err: "the operator no longer holds this epoch"}
		if err := q.Accept(res); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		_, last = q.Reschedule(res.Origin, res.Epoch)
	}
	if last {
		t.Errorf("still rescheduling after %d attempts; the give-up is unreachable", maxAttempts)
	}
	now = now.Add(time.Hour)
	if _, err := q.Lease("w", nil, 11); err != ErrNoWork {
		t.Error("an epoch the queue gave up on came back around anyway")
	}
}

// A retry serving its backoff is not queue depth.
//
// The feeder stops topping up when the queue looks full, so counting held-back
// retries would park it: a burst of unavailable epochs would leave every worker
// asking for work that exists but cannot be handed out yet.
func TestABackingOffRetryIsNotCountedAsAvailableWork(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }

	q.Reschedule("m/kt", 5)
	if pending, _ := q.Stats(); pending != 0 {
		t.Errorf("pending=%d while the only entry is serving a backoff, want 0", pending)
	}
	now = now.Add(2 * retryBase)
	if pending, _ := q.Stats(); pending != 1 {
		t.Errorf("pending=%d once the backoff elapsed, want 1", pending)
	}
}

// TestRangesAreContiguousAgain, and why that is not a weakening.
//
// Ranges used to be handed out interleaved — one assignment of the even epochs,
// one of the odds — so that no worker held two adjacent epochs. The reason was
// real: a worker holding E and E+1 can answer for E without doing the
// append-only check at all, because the published roots chain. curr_E is
// prev_{E+1} is Root(unchanged_{E+1}), computable from the neighbour's proof
// with the commitment never applied and the merged tree never built. Four tree
// hashes become three and both reported roots are correct.
//
// The mechanism did not deliver it. The queue refused the two halves only while
// both were held AT ONCE, and a worker was routinely handed the second half a
// couple of minutes after finishing the first — gpu-box took #7.0 at 13:52:56
// and #7.1 at 13:54:51. Nothing stopped it keeping the proofs from the first
// half and using them on the second. So the adjacency was never withheld, and
// the machinery cost real complexity: the completion arithmetic it required,
// counting (to-from)/step+1, stalled a laptop for a whole lease at a time when
// it was got wrong.
//
// What withholds it now is the canary, aimed at the part of the proof the
// shortcut does not read — a worker taking it never touches `inserted`, so a
// bit flipped there yields two correct roots from a corrupted proof, which is
// exactly the alarm. See internal/workrpc/proofs.go.
func TestRangesAreContiguousAgain(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 100, 130)

	a, err := q.Lease("w", nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.To - a.From + 1; got != 8 {
		t.Errorf("asked for 8 epochs, got %d (%d..%d)", got, a.From, a.To)
	}
	// Every epoch in the range, with no gaps: the whole run is this worker's.
	for e := a.From; e <= a.To; e++ {
		if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: e}); err != nil {
			t.Fatalf("epoch %d was refused inside its own assignment: %v", e, err)
		}
	}
	if _, leased := q.Stats(); leased != 0 {
		t.Errorf("a fully reported contiguous range was not released")
	}
}

// TestTwoWorkersAreNeverHandedTheSameEpoch.
//
// The Source reads the store, and the store does not know what is out on a
// lease — so two workers asking at the same moment would both be told the same
// epochs are unaudited. Overlap has to be refused here, and it is the one thing
// the queue is actually for: without it every machine would verify the same
// prefix and the fleet would do one machine's work.
func TestTwoWorkersAreNeverHandedTheSameEpoch(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 1, 100)

	held := map[int64]string{}
	for i := 0; i < 8; i++ {
		w := fmt.Sprintf("worker-%d", i)
		a, err := q.Lease(w, nil, 10)
		if err != nil {
			t.Fatalf("%s got no work with 100 epochs on offer: %v", w, err)
		}
		for e := a.From; e <= a.To; e++ {
			if other, dup := held[e]; dup {
				t.Fatalf("epoch %d handed to both %s and %s", e, other, w)
			}
			held[e] = w
		}
	}
	if len(held) != 80 {
		t.Errorf("eight workers asking for ten epochs hold %d in total, want 80", len(held))
	}
}

// TestTheLeaseIsSizedByWhatEpochsActuallyCost.
//
// It was twenty minutes, a constant chosen when twenty-five epochs cost about
// that much against the Rust subprocess. An epoch now costs a couple of
// seconds, so an abandoned range was stranded for roughly fifty times longer
// than the work would have taken — and a queue full of leases nobody is working
// looks exactly like a queue that is busy.
func TestTheLeaseIsSizedByWhatEpochsActuallyCost(t *testing.T) {
	q, _ := fixedQueue(t, time.Second) // minLease 1s, so the derivation shows
	offer(q, "m/kt", 1, 1000)

	// Nothing measured yet: the floor, and deliberately the long direction. A
	// lease that is too long merely delays reclaiming an abandoned range; one
	// that is too short expires under a worker doing real work.
	first, err := q.Lease("w", nil, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Report ten epochs at 500ms each.
	for e := first.From; e <= first.To; e++ {
		if err := q.Accept(Result{AssignmentID: first.ID, Nonce: first.Nonce,
			Origin: first.Origin, Epoch: e, DurationMS: 500}); err != nil {
			t.Fatal(err)
		}
	}

	// Now a lease for ten epochs should reflect that: 10 x 500ms x margin.
	second, err := q.Lease("w", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := second.Deadline.Sub(q.now())
	if got < 10*500*time.Millisecond {
		t.Errorf("lease %v is shorter than the work it covers (10 epochs at 500ms)", got)
	}
	if got > 2*time.Minute {
		t.Errorf("lease %v for five seconds of work; the margin has become a constant again", got)
	}
}

// TestAPartiallyLeasedRunKeepsTheFreePart pins a bug in the first version of
// the lease-overlap check.
//
// When a run began inside somebody else's lease it advanced past the whole RUN
// rather than past the LEASE: a lease covering 10..12 of a run 10..20 discarded
// 13..20 too. Free work, dropped, and not offered again until the cursor had
// wrapped the entire history — which on WhatsApp is half a million epochs.
func TestAPartiallyLeasedRunKeepsTheFreePart(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 1, 1000)

	// One worker takes 1..3.
	first, err := q.Lease("a", nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if first.From != 1 || first.To != 3 {
		t.Fatalf("first lease is %d..%d, want 1..3", first.From, first.To)
	}

	// Another asks, and must be given work that starts after the lease rather
	// than being told there is none — and must not overlap it.
	second, err := q.Lease("b", nil, 10)
	if err != nil {
		t.Fatalf("a second worker got nothing with 997 free epochs: %v", err)
	}
	if second.From <= first.To {
		t.Errorf("second range %d..%d overlaps the lease on %d..%d",
			second.From, second.To, first.From, first.To)
	}
	if n := second.To - second.From + 1; n != 10 {
		t.Errorf("second range holds %d epochs, want the 10 it asked for", n)
	}
}

// TestAFailedEpochIsNotHandedStraightBack.
//
// The Source reads the store, and the store records a failed epoch as
// unverified — which is true, and is exactly why the backoff cannot live there.
// Without the deferral the queue would re-offer the same broken epoch as fast
// as a worker could ask for it, which is a hot loop that looks like progress.
func TestAFailedEpochIsNotHandedStraightBack(t *testing.T) {
	q, now := fixedQueue(t, time.Minute)
	offer(q, "m/kt", 5, 5) // exactly one epoch exists

	a, err := q.Lease("w", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.From != 5 {
		t.Fatalf("leased %d, want 5", a.From)
	}
	q.Done(a.ID)
	if _, again := q.Reschedule("m/kt", 5); !again {
		t.Fatal("a first failure was not retried")
	}

	if _, err := q.Lease("w", nil, 1); err != ErrNoWork {
		t.Error("the failed epoch was offered again inside its backoff")
	}
	*now = now.Add(2 * retryBase)
	if _, err := q.Lease("w", nil, 1); err != nil {
		t.Errorf("the epoch was not offered again after its backoff: %v", err)
	}
}
