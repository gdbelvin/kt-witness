package work

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Canaries are corrupted proofs handed to workers as ordinary assignments.
//
// # The hole this closes
//
// A worker reports that an epoch verified. The operator's signed root is
// public, so a worker that did no work at all can report the right answer and
// be believed — every check in this package establishes that a result answers
// work we handed out, and none of them can tell whether any work happened. The
// coverage figure this witness publishes rests on that gap.
//
// A canary asks the only question that closes it: here is a proof that does not
// verify, do you notice. A worker that says it verified has proved it is not
// verifying, and everything it has ever reported goes with it.
//
// # What it does not close
//
// A worker built to spot canaries — by noticing the proof came from the witness
// rather than the operator — would pass all of them and fabricate the rest.
// That is not defended against here and cannot be, short of routing every proof
// through the witness and giving up the bandwidth that makes remote workers
// worth having. The threat this addresses is a verifier that broke, was
// misconfigured, or was quietly doing nothing; the threat it does not address
// is an adversary, which is why the token belongs only on machines the operator
// controls.
type canary struct {
	// AssignmentID identifies the dispatch this canary was sent as.
	AssignmentID string
	Origin       string
	Epoch        int64
	Worker       string
	SentAt       time.Time
}

// AddCanary queues a single-epoch assignment whose proof is served from url and
// is known not to verify.
//
// It is an ordinary pending assignment in every other respect: same shape, same
// nonce discipline, same lease. A worker cannot tell it apart from work, which
// is the point.
func (q *Queue) AddCanary(origin string, epoch int64, url string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nextSeq++
	id := fmt.Sprintf("%s#%d-c%s", origin, q.nextSeq, shortToken())
	q.pending = append(q.pending, Assignment{
		ID: id, Origin: origin, From: epoch, To: epoch, ProofURL: url,
	})
	if q.canaries == nil {
		q.canaries = map[string]*canary{}
	}
	q.canaries[id] = &canary{AssignmentID: id, Origin: origin, Epoch: epoch}
	return id
}

// CanaryVerdict reports whether a result answers a canary, and if so whether
// the worker caught it.
//
// Called after Accept, so the result is already known to answer work we handed
// out. Returns (isCanary, caught).
func (q *Queue) CanaryVerdict(r Result) (bool, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	c := q.canaries[r.AssignmentID]
	if c == nil {
		return false, false
	}
	delete(q.canaries, r.AssignmentID)
	// Caught means the worker did not claim it verified. An error is a catch
	// too: a worker that could not decode a corrupted proof has still refused
	// to bless it, which is the property being tested.
	return true, !r.Verified
}

// PendingCanaries reports how many canaries are outstanding, so a worker that
// silently drops them cannot hide in the gap between sending and never hearing
// back.
func (q *Queue) PendingCanaries() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.canaries)
}

func shortToken() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A predictable canary id would let a worker recognise one without
		// verifying anything, which is the whole failure this exists to catch.
		panic("work: no randomness for a canary id: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
