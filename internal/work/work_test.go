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
