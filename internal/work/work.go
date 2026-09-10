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

	// Worker is who currently holds this lease. Set on lease, empty while
	// pending. It is what lets the proof server answer "may this machine read
	// this epoch", which is the check that closes the root-chaining bypass.
	Worker string `json:"worker,omitempty"`

	// ProofBase, when set, is where to fetch proofs instead of the operator's
	// store: the worker asks for {base}/proof/{origin}/{epoch}.
	//
	// Set on EVERY assignment or on none. An earlier version set it only for
	// canaries, which labelled them — a worker had merely to refuse anything
	// coming from the witness to score perfectly while verifying nothing. A
	// test the subject can identify is not a test.
	ProofBase string `json:"proof_base,omitempty"`
}

// Result is a worker's verdict on one epoch.
type Result struct {
	AssignmentID string `json:"assignment_id"`
	Nonce        string `json:"nonce"`
	Origin       string `json:"origin"`
	Epoch        int64  `json:"epoch"`

	// ComputedPrev and ComputedCurr are the roots the worker rebuilt from the
	// proof. It is not told what the operator published and does not report a
	// verdict: a worker that does not know the expected answer cannot report it
	// without doing the work.
	ComputedPrev string `json:"computed_prev"`
	ComputedCurr string `json:"computed_curr"`

	// Verified is filled in by the WITNESS, after comparing the above against
	// the roots the operator published. It is never set by a worker.
	Verified bool `json:"verified"`

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

// ProtocolVersion is bumped whenever a change would make an older worker's
// messages mean something different rather than fail.
//
// 2: workers report the roots they computed instead of a verdict, and fetch
// proofs from the witness rather than the operator.
//
// 3: the channel is pull. A worker asks for work with Want and is given
// contiguous ranges; Assignment.step and .block are gone.
//
// This one needs the check more than either of the others, because a stale
// worker does not fail here — it succeeds quietly and does almost nothing. It
// never sends a Want, so after the opening request implied by its Hello it sits
// idle with a live session, reporting capacity, indistinguishable from a fleet
// whose queue has run dry. And the ranges it does get are contiguous while it
// still believes they are interleaved, so it verifies every epoch in them
// twice-over-nothing rather than the evens.
//
// Nothing about that looks broken from either end. That is the whole argument
// for this constant.
const ProtocolVersion = 3

// Hello is what a worker sends when it connects.
type Hello struct {
	Name string `json:"name"`
	// Origins the worker is able to verify. A worker without an AKD verifier
	// should not be handed AKD epochs.
	Origins []string `json:"origins"`
	// Parallel is how many epochs it will work on at once. Advisory: it sizes
	// the assignments, and a worker that overstates it simply misses deadlines.
	Parallel int `json:"parallel"`
}

var (
	ErrNoWork = errors.New("work: nothing to hand out")
	// ErrReportFailed ends a session whose results have nowhere to go: every
	// further epoch would be CPU spent on an answer nobody will receive.
	ErrReportFailed = errors.New("work: results could not be reported")
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
	mu     sync.Mutex
	leased map[string]Assignment
	now    func() time.Time

	// Origins is every log this queue serves, used when a worker declares none
	// and to rotate between them fairly.
	Origins []string

	// rotate is where the round-robin over origins starts, advanced on every
	// lease.
	//
	// Without it the first origin in the list wins every time a worker can do
	// more than one, and a log whose epochs are slow to fetch holds the others
	// back. That failure has now been fixed twice at other layers — a feeder
	// loop that queued Meta until its depth limit and never reached WhatsApp,
	// and a depth cap counted across every origin at once — so it goes here,
	// where the choice is actually made.
	rotate int

	// Source answers what still needs auditing. The queue does not hold a list
	// of pending work at all.
	//
	// It used to: a separate feeder walked each log's history on a thirty-second
	// timer and pushed fixed-size chunks into a slice here. That feeder kept its
	// own cursor, its own idea of which chunks were done, and its own depth cap
	// — three pieces of state duplicating what the store already knew, and every
	// one of them was wrong at some point today. The cursor only ever moved
	// forward, so an epoch that failed was never offered again; the "is this
	// chunk done" probe sampled one epoch in twenty-five; the depth cap was
	// shared across logs, so a bandwidth-bound one starved a fast one out
	// entirely and left a laptop idle in front of 7,877 unverified epochs.
	//
	// So the queue asks the store, at the moment somebody wants work. One
	// source of truth, no timer, and no chunk size to get wrong.
	Source Source

	// quiet is when an origin may be asked about again after answering with
	// nothing. Without it a fully-audited log is rescanned end to end on every
	// single request for work.
	quiet map[string]time.Time

	// cursor is where each origin's scan has reached. Not a record of what is
	// done — the Source knows that — only a hint so consecutive requests do not
	// re-scan the same prefix. It wraps.
	cursor map[string]int64

	// retry holds single epochs that came back unavailable, with the backoff
	// they are serving. These are offered before anything the Source suggests,
	// because an epoch that failed once is the work most likely to be missed.
	retry []Assignment

	// reported counts what has come back for each leased assignment, so a
	// finished range is released instead of sitting on a lease until it expires
	// and is handed out again.
	reported map[string]map[int64]bool

	// attempts counts failures per epoch, so an epoch that is simply gone stops
	// being rescheduled. Entries are dropped on success or on giving up.
	attempts map[string]int

	// deferred is when each failed epoch may be offered again.
	//
	// The backoff has to live here rather than in the Source, because the Source
	// reads the store and the store says — correctly — that a failed epoch is
	// unverified. Without this the queue would hand the same broken epoch out
	// again the instant it came back, as fast as a worker could ask.
	deferred map[string]time.Time

	// perEpoch is an exponentially-weighted mean of how long one epoch actually
	// takes, per origin, measured from the results workers report.
	//
	// It exists so the lease is not a constant. It was twenty minutes, chosen
	// when twenty-five epochs cost about that much against the Rust verifier. An
	// epoch now costs a couple of seconds, so a dead worker stranded its range
	// for roughly fifty times longer than the work would have taken — and the
	// only symptom is a queue that looks busy while nothing moves.
	perEpoch map[string]time.Duration

	// minLease floors the derived deadline, and is the whole answer before
	// anything has been measured. It is a bound on the pessimism, not a
	// schedule: the derivation grows past it as soon as one epoch has been
	// timed, which is what stops a slow log's ranges expiring under the worker.
	minLease time.Duration

	nextSeq int
}

// Source returns the next contiguous run of epochs needing audit for one
// origin, at or after `after`, at most n long. ok is false when there is
// nothing left from there to the end of that log's history.
//
// Contiguous, and that is a change. Ranges used to be split into two
// interleaved assignments — evens and odds — so that no worker held two
// adjacent epochs, because a worker holding E and E+1 can answer for E without
// doing the append-only check at all: the published roots chain, so curr_E is
// prev_{E+1} is Root(unchanged_{E+1}), computable from the neighbour's proof
// with the commitment never applied and the merged tree never built.
//
// The reasoning was right; the mechanism did not deliver it. The queue refused
// the two halves only SIMULTANEOUSLY, and a worker was routinely handed the
// second half a couple of minutes after finishing the first — nothing stopped
// it keeping the proofs. So the adjacency was never withheld, and the machinery
// cost the completion arithmetic that stalled a laptop for a lease at a time.
//
// What withholds it now is the canary, aimed at the part of the proof the
// shortcut does not read. See internal/workrpc/proofs.go.
type Source func(origin string, after int64, n int) (from, to int64, ok bool)

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

	// giveUpFor is how long an epoch the queue has given up on is left alone.
	//
	// A day rather than forever. The usual reason an epoch cannot be fetched is
	// that it has aged out of the operator's storage, and that does not undo
	// itself — but an operator restoring a bucket does happen, and a witness
	// that stopped looking permanently would never find out.
	giveUpFor = 24 * time.Hour

	// quietFor is how long an origin that answered "nothing" is left alone.
	//
	// Short, because it only has to outlive a burst of requests: new epochs are
	// published every few minutes, so half a minute of staleness costs nothing
	// and saves a full history scan per request on a log that is keeping up.
	// It is the cadence the feeder this replaced ran at, which was never the
	// part of it that was wrong.
	quietFor = 30 * time.Second
)

func NewQueue(minLease time.Duration) *Queue {
	if minLease <= 0 {
		minLease = 2 * time.Minute
	}
	return &Queue{
		leased:   map[string]Assignment{},
		reported: map[string]map[int64]bool{},
		attempts: map[string]int{},
		cursor:   map[string]int64{},
		quiet:    map[string]time.Time{},
		deferred: map[string]time.Time{},
		perEpoch: map[string]time.Duration{},
		minLease: minLease,
		now:      time.Now,
	}
}

// leaseForLocked is how long a worker gets for n epochs of this origin.
//
// Derived from what epochs of this log have actually been costing, times a
// generous margin, floored. The constant it replaces was twenty minutes, chosen
// when twenty-five epochs cost about that much against the Rust verifier; an
// epoch now costs a couple of seconds, so an abandoned range was stranded for
// roughly fifty times longer than the work would have taken, and the only
// symptom is a queue that looks busy while nothing moves.
func (q *Queue) leaseForLocked(origin string, n int) time.Duration {
	per := q.perEpoch[origin]
	if per <= 0 {
		// Nothing measured yet, so the floor is the whole answer. It is the
		// conservative direction on purpose: a lease that is too long merely
		// delays reclaiming an abandoned range, while one that is too short
		// expires under a worker doing real work and throws the answer away.
		return q.minLease
	}
	d := time.Duration(n) * per * 4
	if d < q.minLease {
		d = q.minLease
	}
	return d
}

// observeLocked folds one measured epoch into the running mean.
func (q *Queue) observeLocked(origin string, d time.Duration) {
	if d <= 0 {
		return
	}
	if cur := q.perEpoch[origin]; cur > 0 {
		// Slow exponential mean: one unusually slow epoch should widen the
		// lease a little, not quadruple it.
		q.perEpoch[origin] = (cur*7 + d) / 8
		return
	}
	q.perEpoch[origin] = d
}

// Lease hands a worker up to `want` contiguous epochs it can do.
//
// Pull, not push. The witness used to decide when to send: it leased a range,
// pushed it, and blocked until that range came back in full — so every worker
// held exactly one range whatever its size, and the pipeline drained at every
// boundary. The worker knows its own capacity and has always reported it; now
// it asks, and this answers.
//
// Retries first, then the Source. Expired leases are reclaimed here rather than
// by a sweeper: the only moment the answer matters is when somebody is asking
// for work, and a background timer would be a second thing to keep consistent.
func (q *Queue) Lease(worker string, origins []string, want int) (Assignment, error) {
	if want < 1 {
		want = 1
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()

	can := map[string]bool{}
	for _, o := range origins {
		can[o] = true
	}
	now := q.now()

	// An epoch that failed once is the work most likely to be missed
	// altogether, so it is offered before anything new.
	for i, a := range q.retry {
		if len(can) > 0 && !can[a.Origin] {
			continue
		}
		if !a.notBefore.IsZero() && now.Before(a.notBefore) {
			continue
		}
		q.retry = append(q.retry[:i], q.retry[i+1:]...)
		return q.handOutLocked(a, worker, now), nil
	}

	if q.Source == nil {
		return Assignment{}, ErrNoWork
	}
	// A worker that declared no origins gets anything, which is what it meant.
	try := origins
	if len(try) == 0 {
		try = q.Origins
	}
	if len(try) == 0 {
		return Assignment{}, ErrNoWork
	}

	// The Source is asked WITHOUT the lock.
	//
	// It reads the store, and on a long verified prefix that is not fast:
	// measured at 353ms across half a million audited epochs, which is what
	// WhatsApp's history looks like. Holding the queue mutex across it would
	// serialise every worker in the fleet behind one bolt scan — the cursor
	// makes the steady state short, but a cold start or a wrap pays the whole
	// thing, and "occasionally every worker stalls for a third of a second" is
	// not a property worth having.
	//
	// So: read the cursor under the lock, ask outside it, then re-acquire to
	// check the answer against the leases. Another worker may have taken the
	// range in between; trimLeasedLocked is what catches that, and the loop
	// tries the next origin rather than handing out an overlap.
	for i := range try {
		origin := try[(q.rotate+i)%len(try)]
		if len(can) > 0 && !can[origin] {
			continue
		}
		if t, ok := q.quiet[origin]; ok && now.Before(t) {
			// Asked recently and told there was nothing. Re-asking per request
			// means re-scanning the whole history per request once a log is
			// fully audited, which is the common state for a log that is
			// keeping up.
			continue
		}
		at := q.cursor[origin]
		src := q.Source

		q.mu.Unlock()
		from, to, found := scanFor(src, origin, at, want)
		q.mu.Lock()

		if !found {
			q.quiet[origin] = q.now().Add(quietFor)
			continue
		}
		now = q.now()
		f, t2, free, _ := q.trimLeasedLocked(origin, from, to)
		if free {
			f, t2, free = q.trimDeferredLocked(origin, f, t2, now)
		}
		if !free {
			// Somebody took it while the lock was down, or it is in backoff.
			// Move the cursor past it and let the next request try again rather
			// than scanning further while holding nothing.
			if to+1 > q.cursor[origin] {
				q.cursor[origin] = to + 1
			}
			continue
		}
		q.cursor[origin] = t2 + 1
		q.rotate++
		q.nextSeq++
		return q.handOutLocked(Assignment{
			ID:     fmt.Sprintf("%s#%d", origin, q.nextSeq),
			Origin: origin, From: f, To: t2,
		}, worker, now), nil
	}
	return Assignment{}, ErrNoWork
}

// scanFor asks the Source from `at`, and once from the bottom if that found
// nothing — the tail being done does not mean the gaps behind it are.
func scanFor(src Source, origin string, at int64, want int) (int64, int64, bool) {
	if from, to, ok := src(origin, at, want); ok {
		return from, to, true
	}
	if at == 0 {
		return 0, 0, false
	}
	from, to, ok := src(origin, 0, want)
	return from, to, ok
}

// trimLeasedLocked shortens a run so it does not overlap anything out on a
// lease, returning the free portion and where to resume looking.
//
// Two workers asking at the same moment must not be handed the same epochs, and
// the Source cannot know about leases — it reads the store, and the store
// records verdicts, not who is currently working on what. So the check belongs
// here.
//
// The `next` return is what the first version got wrong. When a run began
// inside a lease it advanced past the whole RUN, so a lease covering 10..12 of
// a run 10..20 discarded 13..20 as well — free work, dropped until the cursor
// wrapped all the way round the history. Advancing past the LEASE is the
// difference.
func (q *Queue) trimLeasedLocked(origin string, from, to int64) (f, t int64, free bool, next int64) {
	// Skip forward past any lease covering the start of the run. Repeated
	// because leases can abut: one worker on 10..12 and another on 13..15.
	for moved := true; moved; {
		moved = false
		for _, a := range q.leased {
			if a.Origin == origin && from >= a.From && from <= a.To {
				from = a.To + 1
				moved = true
			}
		}
		if from > to {
			return 0, 0, false, from
		}
	}
	// Then stop the run before the next lease that starts inside it.
	for _, a := range q.leased {
		if a.Origin == origin && a.From > from && a.From <= to {
			to = a.From - 1
		}
	}
	return from, to, from <= to, to + 1
}

// trimDeferredLocked drops epochs still serving a retry backoff from the front
// of a run, and truncates it before the next one.
//
// The backoff has to be applied here rather than in the Source, because the
// Source reads the store and the store says — correctly — that a failed epoch
// is unverified. Without this the queue would hand the same broken epoch out
// again the instant it came back, as fast as a worker could ask for it.
//
// Sparse by construction: these are epochs something went wrong with, so the
// common case walks a short run and finds nothing.
func (q *Queue) trimDeferredLocked(origin string, from, to int64, now time.Time) (int64, int64, bool) {
	for from <= to {
		if t, ok := q.deferred[epochKey(origin, from)]; ok && now.Before(t) {
			from++
			continue
		}
		break
	}
	for e := from; e <= to; e++ {
		if t, ok := q.deferred[epochKey(origin, e)]; ok && now.Before(t) {
			return from, e - 1, from <= e-1
		}
	}
	return from, to, from <= to
}

func (q *Queue) handOutLocked(a Assignment, worker string, now time.Time) Assignment {
	n := int(a.To-a.From) + 1
	a.Nonce = newNonce()
	a.notBefore = time.Time{}
	a.Deadline = now.Add(q.leaseForLocked(a.Origin, n))
	a.Worker = worker
	q.leased[a.ID] = a
	q.reported[a.ID] = map[int64]bool{}
	return a
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
		q.releaseLocked(a)
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
	// then put it back as though it had been abandoned. Every range would have
	// been verified twice, and the only visible symptom is a coverage rate that
	// is half what the hardware should give.
	//
	// The count is To-From+1 again, plainly, because ranges are contiguous
	// again. It briefly was (To-From)/step+1, for interleaved assignments, and
	// getting that wrong did not fail — it stalled. The range never registered
	// as finished, the dispatcher waited out the whole lease, and a machine that
	// had done its work sat idle for twenty minutes looking healthy.
	seen := q.reported[r.AssignmentID]
	if seen == nil {
		seen = map[int64]bool{}
		q.reported[r.AssignmentID] = seen
	}
	seen[r.Epoch] = true
	if r.Err == "" {
		// What this epoch actually cost, which is what sizes the next lease.
		q.observeLocked(r.Origin, time.Duration(r.DurationMS)*time.Millisecond)
		k := epochKey(r.Origin, r.Epoch)
		delete(q.deferred, k)
	}
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
		//
		// Deferred for a long time rather than merely forgotten, because the
		// Source would otherwise hand it straight back: the store records the
		// epoch as unverified, which is true and is the whole point of
		// recording it. Dropping the attempt counter alone would make the
		// give-up unreachable in a new way — the queue would re-offer a
		// permanently-lost epoch as fast as workers could ask, burning the
		// ecosystem's scarcest resource re-discovering a fact already written
		// down.
		//
		// Long, not forever. Data that has aged out is the common case and it
		// does not come back; but an operator restoring a bucket is a thing
		// that happens, and a witness that never looks again would never
		// notice.
		delete(q.attempts, k)
		q.deferred[k] = q.now().Add(giveUpFor)
		return n, false
	}
	q.attempts[k] = n

	q.nextSeq++
	notBefore := q.now().Add(retryBase << (n - 1))
	// Also recorded as deferred, so the Source does not simply hand this epoch
	// straight back. The store still says it is unverified — which is true, and
	// exactly why the backoff has to live here rather than there.
	q.deferred[k] = notBefore
	q.retry = append(q.retry, Assignment{
		ID:     fmt.Sprintf("%s#%d-retry%d", origin, q.nextSeq, n),
		Origin: origin, From: epoch, To: epoch,
		notBefore: notBefore,
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
	// "Pending" is now retries waiting to be offered again. There is no queue
	// of fresh work to count: what has not been audited lives in the store, and
	// kt_witness_history_unverified_epochs is the number that answers "how much
	// is left" — this one answers "how much has gone wrong".
	for _, a := range q.retry {
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
	for _, a := range q.retry {
		if a.notBefore.IsZero() || !now.Before(a.notBefore) {
			pending++
		}
	}
	return pending, len(q.leased)
}

// StatsFor is Stats for one origin.
//
// The feed needs this because the depth it keeps queued has to be per origin.
// Measured globally, a slow log crowds out a fast one completely: Meta's proofs
// are 284 MB and bandwidth-bound, so its assignments sit pending, accumulate to
// the cap, and the feed then declines to queue anything at all — including for
// a log whose proofs are a tenth the size and whose worker is idle. Observed
// exactly that: 40 Meta assignments pending, zero WhatsApp, 7,877 unverified
// WhatsApp epochs, and a laptop at 0% CPU that can only do WhatsApp.
//
// The round-robin inside the feed was written to fix the same shape one level
// up — a loop that queued Meta until the depth limit and never reached
// WhatsApp. It fixed the ORDER within a pass. It could not fix a limit that is
// shared.
func (q *Queue) StatsFor(origin string) (pending, leased int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()
	now := q.now()
	for _, a := range q.retry {
		if a.Origin != origin {
			continue
		}
		if a.notBefore.IsZero() || !now.Before(a.notBefore) {
			pending++
		}
	}
	for _, a := range q.leased {
		if a.Origin == origin {
			leased++
		}
	}
	return pending, leased
}

func (q *Queue) reclaimLocked() {
	now := q.now()
	for _, a := range q.leased {
		if now.After(a.Deadline) {
			q.releaseLocked(a)
		}
	}
}

// releaseLocked drops a lease and rewinds that origin's cursor to the start of
// the range, so it is offered again promptly.
//
// Nothing is put back on a list, because there is no list. The store still says
// those epochs are unverified — that is what makes them work — so releasing the
// lease is the whole of it. The rewind is only so the next request finds them
// now rather than after a full pass over half a million epochs.
func (q *Queue) releaseLocked(a Assignment) {
	delete(q.leased, a.ID)
	delete(q.reported, a.ID)
	if at, ok := q.cursor[a.Origin]; !ok || at > a.From {
		q.cursor[a.Origin] = a.From
	}
	// This range is work again, so a "nothing here" answer from before is now
	// wrong. Without clearing it, an abandoned range would wait out the quiet
	// interval on top of its lease.
	delete(q.quiet, a.Origin)
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

// LeasedBy reports whether this worker currently holds a lease covering one
// epoch.
//
// It is the authorisation check for handing over a proof, and the reason it
// exists is a bypass that authorisation closes. The published roots chain —
// curr_E equals prev_{E+1}, which this witness itself enforces — so a worker
// that can fetch epoch E+1's proof can answer for epoch E without ever checking
// the append-only property: report Root(unchanged_E) as the previous root and
// Root(unchanged_{E+1}) as the current one, and both match what the operator
// published. The commitment is never applied, the merged tree is never built,
// and the one property this witness exists to audit goes unexamined.
//
// The values are public and derivable two ways, so no amount of asking for a
// different number closes it. What closes it is denying the second proof: a
// worker may read exactly the epochs it has been asked about, and nothing else.
func (q *Queue) LeasedBy(worker, origin string, epoch int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reclaimLocked()
	for _, a := range q.leased {
		if a.Worker != worker || a.Origin != origin {
			continue
		}
		if epoch < a.From || epoch > a.To {
			continue
		}
		return true
	}
	return false
}
