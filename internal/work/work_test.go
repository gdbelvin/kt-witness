package work

import (
	"testing"
	"time"
)

func fixedQueue(t *testing.T, lease time.Duration) (*Queue, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	q := NewQueue(lease)
	q.now = func() time.Time { return now }
	return q, &now
}

// TestNonceTiesAResultToOneDispatch.
//
// The operator's signed root is public, so a worker that did nothing can still
// report the correct answer. The nonce is what stops the cheapest version of
// that — replaying an earlier honest result as evidence of new work.
func TestNonceTiesAResultToOneDispatch(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	q.Add("meta.messenger.kt/v1", 100, 110)

	a, err := q.Lease("laptop", nil)
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
	q.Add("m/kt", 100, 110)
	a, _ := q.Lease("laptop", nil)

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
	q.Add("m/kt", 1, 10)

	a, _ := q.Lease("laptop", nil)
	if p, l := q.Stats(); p != 0 || l != 1 {
		t.Fatalf("after leasing: pending=%d leased=%d, want 0 and 1", p, l)
	}

	*now = now.Add(2 * time.Minute) // the lid closed

	if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Epoch: 5}); err != ErrLeaseExpired {
		t.Errorf("a result past its deadline was accepted: %v", err)
	}
	if p, l := q.Stats(); p != 1 || l != 0 {
		t.Fatalf("after expiry: pending=%d leased=%d, want 1 and 0", p, l)
	}
	// And it is handed out again, with a fresh nonce so the abandoned worker's
	// late reply cannot answer the new dispatch.
	b, err := q.Lease("other", nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.Nonce == a.Nonce {
		t.Error("the reissued assignment reused the abandoned nonce")
	}
}

// A worker is only given work it says it can do. A worker without the AKD
// sidecar handed AKD epochs would report every one of them unavailable, which
// looks exactly like the log being down.
func TestWorkersOnlyGetOriginsTheyDeclared(t *testing.T) {
	q, _ := fixedQueue(t, time.Minute)
	q.Add("meta.messenger.kt/v1", 1, 10)
	q.Add("proton.me/kt/v1", 1, 10)

	a, err := q.Lease("gpu-box", []string{"proton.me/kt/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Origin != "proton.me/kt/v1" {
		t.Errorf("got %s, want the only origin this worker declared", a.Origin)
	}
	if _, err := q.Lease("gpu-box", []string{"signal.org/kt"}); err != ErrNoWork {
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
	if _, err := q.Lease("w", nil); err != ErrNoWork {
		t.Errorf("a retry was leased before its backoff elapsed (%v)", err)
	}
	now = now.Add(2 * retryBase)
	a, err := q.Lease("w", nil)
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

	q.Add("m/kt", 1, 3)
	a, err := q.Lease("w", nil)
	if err != nil {
		t.Fatal(err)
	}
	for e := a.From; e <= a.To; e++ {
		if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: e}); err != nil {
			t.Fatalf("epoch %d: %v", e, err)
		}
	}
	if pending, leased := q.Stats(); pending != 0 || leased != 0 {
		t.Errorf("after a complete range: pending=%d leased=%d, want 0 and 0", pending, leased)
	}

	now = now.Add(2 * time.Minute) // past what would have been the deadline
	if _, err := q.Lease("w", nil); err != ErrNoWork {
		t.Error("a completed range came back through the reclaim path")
	}
}

// A partly-reported range still times out, because the rest of it was never done.
func TestAPartlyReportedAssignmentStillReturnsToTheQueue(t *testing.T) {
	q := NewQueue(time.Minute)
	now := time.Now()
	q.now = func() time.Time { return now }

	q.Add("m/kt", 1, 3)
	a, _ := q.Lease("w", nil)
	if err := q.Accept(Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	back, err := q.Lease("w2", nil)
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
	q.Add("m/kt", 7, 7)

	var last bool
	for i := 1; i <= maxAttempts; i++ {
		now = now.Add(time.Hour) // past any backoff
		a, err := q.Lease("w", nil)
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
	if _, err := q.Lease("w", nil); err != ErrNoWork {
		t.Error("an epoch the queue gave up on came back around anyway")
	}
}
