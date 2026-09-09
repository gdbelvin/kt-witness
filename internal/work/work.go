// Package work hands verification out to machines that are not this one.
//
// # Why
//
// Verification is the constraint. The witness saturates 31 of its 32 cores
// while its link runs at 40% of capacity, so the scarce thing is CPU and the
// cheapest CPU available is whatever else the operator owns. A laptop with
// hardware SHA does ~11.9M hashes/sec/core against this host's 1.34M — nearly
// nine times per core — and it is idle most of the day.
//
// # What a worker is trusted with, which is almost nothing
//
// A worker reports that an epoch verified. It cannot be believed on that alone:
// the operator's signed root is public, so a worker that did no work at all can
// still report the right answer. Three things follow, and they shape the whole
// protocol.
//
// A result is only ever accepted when it agrees with itself — the root reported
// must equal the signed root reported — which catches corruption and truncation
// but not fabrication. Fabrication is caught by re-verifying a random sample
// here, which is why assignments carry a nonce the worker must echo: it ties a
// result to one assignment and stops a worker replaying an earlier honest one.
// And nothing a worker says can produce a misbehaviour finding; a disagreement
// means this witness re-runs the epoch itself and its own answer decides.
//
// The effect is that a hostile worker can waste our time and inflate a coverage
// number until spot-checked. It cannot make us accuse an operator.
package work

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Assignment is one unit of verification: a range of epochs on one log.
//
// Ranges rather than single epochs because the round trip is not free and a
// worker that has fetched a proof may as well be given its neighbours, and
// because a lease that covers a range can be reclaimed as a unit.
type Assignment struct {
	ID     string `json:"id"`
	Origin string `json:"origin"`
	From   int64  `json:"from"`
	To     int64  `json:"to"`

	// Nonce is echoed in every result for this assignment. It makes a result
	// answerable to one dispatch, so an old honest result cannot be replayed as
	// evidence of new work.
	Nonce string `json:"nonce"`

	// Deadline is when the lease expires and the range returns to the queue. A
	// worker past it should stop: its results will be refused, and continuing
	// wastes the one resource this whole design exists to conserve.
	Deadline time.Time `json:"deadline"`
}

// Result is a worker's verdict on one epoch.
type Result struct {
	AssignmentID string `json:"assignment_id"`
	Nonce        string `json:"nonce"`
	Origin       string `json:"origin"`
	Epoch        int64  `json:"epoch"`

	Verified   bool   `json:"verified"`
	Root       string `json:"root"`
	SignedRoot string `json:"signed_root"`

	// Worker names who did it, and DurationMS how long they took. Published in
	// the audit record, because a conclusion reached on somebody else's
	// hardware should say so.
	Worker     string `json:"worker"`
	DurationMS int64  `json:"duration_ms"`

	// Err is set when the worker could not verify. Not a finding: an epoch it
	// could not fetch is unavailable, not evidence.
	Err string `json:"err,omitempty"`
}

// Hello is what a worker sends when it connects.
type Hello struct {
	Name string `json:"name"`
	// Origins the worker is able to verify. A worker without the AKD sidecar
	// should not be handed AKD epochs.
	Origins []string `json:"origins"`
	// Parallel is how many epochs it will work on at once. Advisory: it sizes
	// the assignments, and a worker that overstates it simply misses deadlines.
	Parallel int `json:"parallel"`
}

var (
	ErrNoWork       = errors.New("work: nothing to hand out")
	ErrUnknownID    = errors.New("work: no such assignment")
	ErrBadNonce     = errors.New("work: nonce does not match the assignment")
	ErrLeaseExpired = errors.New("work: the lease for this assignment has expired")
)

// Queue hands out ranges and remembers who holds what.
//
// Deliberately in memory. A lease is a claim on a few minutes of somebody's
// CPU, not a durable fact, and losing the whole set on restart costs one lease
// interval of duplicated work — against the cost of persisting a structure that
// changes every few seconds.
type Queue struct {
	mu      sync.Mutex
	pending []Assignment
	leased  map[string]Assignment
	lease   time.Duration
	now     func() time.Time
	nextSeq int
}

func NewQueue(lease time.Duration) *Queue {
	if lease <= 0 {
		lease = 10 * time.Minute
	}
	return &Queue{leased: map[string]Assignment{}, lease: lease, now: time.Now}
}

// Add queues a range for dispatch.
func (q *Queue) Add(origin string, from, to int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.nextSeq++
	q.pending = append(q.pending, Assignment{
		ID:     fmt.Sprintf("%s#%d", origin, q.nextSeq),
		Origin: origin, From: from, To: to,
	})
}

// Lease hands out the next range a worker can do, or ErrNoWork.
//
// Expired leases are reclaimed here rather than by a sweeper: the only moment
// the answer matters is when somebody is asking for work, and a background
// timer would be a second thing to get wrong.
func (q *Queue) Lease(worker string, origins []string) (Assignment, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()

	can := map[string]bool{}
	for _, o := range origins {
		can[o] = true
	}
	for i, a := range q.pending {
		if len(can) > 0 && !can[a.Origin] {
			continue
		}
		q.pending = append(q.pending[:i], q.pending[i+1:]...)
		a.Nonce = newNonce()
		a.Deadline = q.now().Add(q.lease)
		q.leased[a.ID] = a
		return a, nil
	}
	return Assignment{}, ErrNoWork
}

// Accept checks a result against the assignment it claims to answer.
//
// It does not decide whether the epoch verified — that is the caller's, on the
// strength of the roots agreeing and whatever sampling it does. This only
// establishes that the result answers work we actually handed out, to the
// worker we handed it to, inside the lease.
func (q *Queue) Accept(r Result) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	a, ok := q.leased[r.AssignmentID]
	if !ok {
		return ErrUnknownID
	}
	if a.Nonce != r.Nonce {
		return ErrBadNonce
	}
	if q.now().After(a.Deadline) {
		delete(q.leased, r.AssignmentID)
		q.pending = append(q.pending, stripLease(a))
		return ErrLeaseExpired
	}
	if r.Epoch < a.From || r.Epoch > a.To {
		return fmt.Errorf("work: epoch %d is outside assignment %s (%d..%d)",
			r.Epoch, a.ID, a.From, a.To)
	}
	return nil
}

// Done releases an assignment once its whole range has been reported.
func (q *Queue) Done(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.leased, id)
}

// Stats reports queue depth, for the metrics that say whether workers are
// keeping up or starving.
func (q *Queue) Stats() (pending, leased int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()
	return len(q.pending), len(q.leased)
}

func (q *Queue) reclaimLocked() {
	now := q.now()
	for id, a := range q.leased {
		if now.After(a.Deadline) {
			delete(q.leased, id)
			q.pending = append(q.pending, stripLease(a))
		}
	}
}

func stripLease(a Assignment) Assignment {
	a.Nonce, a.Deadline = "", time.Time{}
	return a
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A predictable nonce would let a worker precompute a reply to an
		// assignment it has not been given. Better to hand out no work.
		panic("work: no randomness for an assignment nonce: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
