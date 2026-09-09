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

	// notBefore holds a retry back until its backoff has passed. Unexported:
	// it is the queue's bookkeeping and has no meaning to a worker, so it does
	// not belong on the wire.
	notBefore time.Time

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

// Capacity is what a worker can currently do, as it measures itself.
//
// Reported rather than inferred, because the witness cannot tell the difference
// between a machine that is yielding correctly and one that has broken: both
// look like results arriving more slowly. A worker saying "one at a time, my
// owner is back" is a healthy system doing its job, and that should be visible
// as such.
type Capacity struct {
	// Parallel is how many epochs it will run at once right now — its own
	// measurement, not a configured ceiling.
	Parallel int
	// CPUs it may use. On a Mac in background QoS this is the efficiency-core
	// count rather than the machine's, which is the point of running there.
	CPUs int
	// LoadCores and BudgetCores are what the worker sees of its whole machine
	// and the ceiling it holds itself to. Two machines will not agree on what a
	// core is; the interesting shape is each machine against its own budget.
	LoadCores   float64
	BudgetCores float64
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

	// reported counts what has come back for each leased assignment, so a
	// finished range can be released instead of sitting on a lease until it
	// expires and is handed out again.
	reported map[string]map[int64]bool

	// attempts counts failures per epoch, so an epoch that is simply gone stops
	// being rescheduled. Entries are dropped on success or on giving up.
	attempts map[string]int
}

const (
	// maxAttempts is how many times an epoch that came back unavailable is
	// handed out again before the queue accepts the answer.
	//
	// Three, because the two failures worth retrying — a worker that lost its
	// network, an operator having a bad minute — clear inside minutes, and the
	// failure that is not worth retrying is the one this witness exists to
	// find: data that has aged out and is never coming back. Retrying that
	// forever would burn the ecosystem's scarcest resource re-discovering a
	// fact already recorded.
	maxAttempts = 3

	// retryBase is the first backoff; it doubles per attempt. Long enough that
	// a retry is not simply the same request into the same broken thing.
	retryBase = time.Minute
)

func NewQueue(lease time.Duration) *Queue {
	if lease <= 0 {
		lease = 10 * time.Minute
	}
	return &Queue{
		leased:   map[string]Assignment{},
		reported: map[string]map[int64]bool{},
		attempts: map[string]int{},
		lease:    lease, now: time.Now,
	}
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
	now := q.now()
	for i, a := range q.pending {
		if len(can) > 0 && !can[a.Origin] {
			continue
		}
		if !a.notBefore.IsZero() && now.Before(a.notBefore) {
			continue // a retry whose backoff has not elapsed
		}
		q.pending = append(q.pending[:i], q.pending[i+1:]...)
		a.Nonce = newNonce()
		a.notBefore = time.Time{}
		a.Deadline = now.Add(q.lease)
		q.leased[a.ID] = a
		q.reported[a.ID] = map[int64]bool{}
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
		delete(q.reported, r.AssignmentID)
		q.pending = append(q.pending, stripLease(a))
		return ErrLeaseExpired
	}
	if r.Epoch < a.From || r.Epoch > a.To {
		return fmt.Errorf("work: epoch %d is outside assignment %s (%d..%d)",
			r.Epoch, a.ID, a.From, a.To)
	}

	// Release the range as soon as its last epoch is in.
	//
	// Nothing used to do this, and the consequence was quiet: a finished
	// assignment sat in the leased map until its deadline, and reclaimLocked
	// then put it back on the queue as though it had been abandoned. Every
	// range would have been verified twice, once for real and once ten minutes
	// later, and the only visible symptom is a coverage rate that is half what
	// the hardware should give.
	seen := q.reported[r.AssignmentID]
	if seen == nil {
		seen = map[int64]bool{}
		q.reported[r.AssignmentID] = seen
	}
	seen[r.Epoch] = true
	if int64(len(seen)) == a.To-a.From+1 {
		delete(q.leased, r.AssignmentID)
		delete(q.reported, r.AssignmentID)
	}
	if r.Err == "" {
		// Clear the retry counter only on an answer that stuck.
		//
		// Clearing it unconditionally made the give-up unreachable: Accept runs
		// before the caller reschedules, so every failure looked like the first
		// one and a permanently-lost epoch would have been re-leased forever on
		// a one-minute backoff — the queue busily re-discovering, at the
		// ecosystem's expense, a fact it had already recorded.
		delete(q.attempts, epochKey(r.Origin, r.Epoch))
	}
	return nil
}

// Reschedule takes an epoch a worker could not verify and decides whether
// anyone should try again. It reports the attempt number and whether the epoch
// went back on the queue.
//
// Rescheduling lives here rather than in the worker deliberately. A worker that
// retried its own failures would be making a scheduling decision from inside
// the machine that just failed — retrying the same fetch, over the same broken
// network, while holding a lease — and a worker that simply dropped them would
// leave the epoch unexamined with nothing recording that it had been skipped.
// Reported back as an answer, it becomes the queue's business, and the queue is
// the one party that can hand it to a different machine.
func (q *Queue) Reschedule(origin string, epoch int64) (attempt int, requeued bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	k := epochKey(origin, epoch)
	n := q.attempts[k] + 1
	if n >= maxAttempts {
		// Accept the answer. The epoch is unavailable, which is a finding about
		// the ecosystem rather than a failure of this queue, and the caller has
		// already recorded it.
		delete(q.attempts, k)
		return n, false
	}
	q.attempts[k] = n

	q.nextSeq++
	q.pending = append(q.pending, Assignment{
		ID:     fmt.Sprintf("%s#%d-retry%d", origin, q.nextSeq, n),
		Origin: origin, From: epoch, To: epoch,
		notBefore: q.now().Add(retryBase << (n - 1)),
	})
	return n, true
}

func epochKey(origin string, epoch int64) string {
	return fmt.Sprintf("%s@%d", origin, epoch)
}

// Finished reports whether an assignment is no longer held — because every
// epoch came back, or because its lease lapsed and the range returned to the
// queue. It is what lets a dispatcher hand a worker its next range only when
// the last one is actually settled.
func (q *Queue) Finished(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, held := q.leased[id]
	return !held
}

// Done releases an assignment once its whole range has been reported.
func (q *Queue) Done(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.leased, id)
}

// Stats reports queue depth, for the metrics that say whether workers are
// keeping up or starving.
// Depth reports what is waiting and what is out, per origin.
//
// Added after a worker sat idle for forty-nine minutes, connected and
// reporting capacity, while nothing could say whether the queue had run dry or
// was full of work it could not do. Every other part of this system publishes
// what it is doing; the queue in the middle of it published nothing, so the one
// question that mattered — "is this worker starved or broken?" — had no answer
// from outside the box.
func (q *Queue) Depth() (pendingByOrigin, leasedByOrigin map[string]int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()
	now := q.now()
	pendingByOrigin = map[string]int{}
	leasedByOrigin = map[string]int{}
	for _, a := range q.pending {
		if a.notBefore.IsZero() || !now.Before(a.notBefore) {
			pendingByOrigin[a.Origin]++
		}
	}
	for _, a := range q.leased {
		leasedByOrigin[a.Origin]++
	}
	return pendingByOrigin, leasedByOrigin
}

// Pending counts only what a worker could be given right now.
//
// A retry serving its backoff is queued but not available, and counting it as
// depth would be a small lie with a real effect: the feeder stops topping up
// when the queue looks full, so a burst of unavailable epochs would park the
// feeder and leave every worker asking for work that is not there.
func (q *Queue) Stats() (pending, leased int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()
	now := q.now()
	for _, a := range q.pending {
		if a.notBefore.IsZero() || !now.Before(a.notBefore) {
			pending++
		}
	}
	return pending, len(q.leased)
}

func (q *Queue) reclaimLocked() {
	now := q.now()
	for id, a := range q.leased {
		if now.After(a.Deadline) {
			delete(q.leased, id)
			delete(q.reported, id)
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
