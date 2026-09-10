package work

import (
	"testing"
	"time"
)

// A canary is indistinguishable from work, and its verdict is about the worker.
//
// The failure this guards is the one the whole mechanism exists for: a worker
// that reports the operator's published root without verifying anything. It
// would report a corrupted proof as verified, and if that were recorded as an
// audit it would also put a false hole in the coverage — so the queue has to
// recognise the result as a canary and answer both questions.
func TestACanaryIsCaughtOnlyWhenTheWorkerRefusesIt(t *testing.T) {
	q := NewQueue(time.Minute)
	id := q.AddCanary("m/kt", 42, "http://witness.local/canary/abc")

	a, err := q.Lease("laptop", []string{"m/kt"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != id {
		t.Fatalf("leased %s, want the canary %s", a.ID, id)
	}
	if a.ProofURL == "" {
		t.Error("the canary was handed out without the proof it is supposed to serve")
	}
	if a.From != 42 || a.To != 42 {
		t.Errorf("canary covers %d..%d, want one epoch", a.From, a.To)
	}

	// A worker that claims a corrupted proof verified has proved it is not
	// verifying.
	res := Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: 42,
		Verified: true, Root: "aa", SignedRoot: "aa"}
	if err := q.Accept(res); err != nil {
		t.Fatal(err)
	}
	isCanary, caught := q.CanaryVerdict(res)
	if !isCanary {
		t.Fatal("the result was not recognised as a canary; it would be recorded as an audit")
	}
	if caught {
		t.Error("a worker that verified a corrupted proof was counted as having caught it")
	}
}

func TestARefusedCanaryCounts(t *testing.T) {
	q := NewQueue(time.Minute)
	q.AddCanary("m/kt", 7, "http://witness.local/canary/xyz")
	a, _ := q.Lease("laptop", nil)
	res := Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin, Epoch: 7,
		Err: "append-only verification failed"}
	if err := q.Accept(res); err != nil {
		t.Fatal(err)
	}
	isCanary, caught := q.CanaryVerdict(res)
	if !isCanary || !caught {
		t.Errorf("a refused canary should count as caught: isCanary=%v caught=%v", isCanary, caught)
	}
}

// The worker inside the witness must not be handed one: it is tested where the
// proof can be corrupted directly, and taking a canary here would consume one
// meant for a machine that can actually be caught lying.
func TestTheLocalWorkerIsNotGivenCanaries(t *testing.T) {
	q := NewQueue(time.Minute)
	q.AddCanary("m/kt", 1, "http://witness.local/canary/abc")
	if _, err := q.LeaseExcludingCanaries("witness", nil); err != ErrNoWork {
		t.Error("the in-process worker was handed a canary")
	}
	q.Add("m/kt", 100, 124)
	a, err := q.LeaseExcludingCanaries("witness", nil)
	if err != nil {
		t.Fatalf("ordinary work should still be available: %v", err)
	}
	if a.ProofURL != "" {
		t.Error("ordinary work arrived with a proof URL")
	}
}
