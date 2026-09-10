package work

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Runner is the worker loop, and it is the same loop everywhere.
//
// # Why the witness runs one too
//
// An earlier design had two mechanisms: the witness walked a cursor downward
// through unaudited epochs, while remote machines were fed ranges from the
// opposite end so the two would not collide. That worked by keeping them far
// apart, which is a coordination scheme dressed up as an accident of geometry —
// and it would have failed quietly the day they met.
//
// There is one queue. The witness leases from it exactly as a laptop does, and
// the lease is what stops two machines doing the same epoch. Local work is not
// special; it is simply the worker with the shortest network path.
//
// What differs between participants is only the three functions below: where
// assignments come from, what verifies an epoch, and where verdicts go. In the
// witness those are a queue, a verifier and a store. On a laptop they are a
// gRPC stream, a verifier and the same stream back.
type Runner struct {
	// Next blocks until an assignment is available, or returns ErrNoWork to be
	// asked again after Idle.
	// Next asks for up to `want` more epochs. It is the pull.
	//
	// The witness used to decide when to send and this was a bare receive from
	// a channel — the worker had no way to say how much it could take, so it
	// got one range at a time whatever it was. `want` is what this machine has
	// room for right now, and the witness may answer with less.
	Next func(ctx context.Context, want int) (Assignment, error)
	// Verify rebuilds the two roots from the proof and returns them.
	//
	// It is not given the roots the operator published and does not decide
	// whether they match. That is the whole point: a worker that does not know
	// the expected answer cannot report it without doing the work, so a
	// fabricated result is not something to sample for — it is something that
	// cannot be produced. The witness holds the published roots and compares.
	//
	// An epoch it cannot fetch is an ERROR, and an error is an answer. The
	// worker reports it and moves on; rescheduling is the queue's business,
	// because a client that decided when to retry would be making a scheduling
	// decision using only its own narrow view of one machine.
	// proofBase, when non-empty, is where to fetch the proof from instead of
	// the operator's own store. Set on every assignment or none: a base that
	// appeared only sometimes would tell a worker which epochs were being
	// tested.
	Verify func(ctx context.Context, origin string, epoch int64, proofBase string) (computedPrev, computedCurr string, err error)
	// Report records one verdict. Calls are serialised, so an implementation
	// writing to a gRPC stream needs no lock of its own.
	Report func(ctx context.Context, r Result) error

	// BeforeNext gates how often this worker ASKS FOR MORE WORK, and that is
	// the whole of its pacing.
	//
	// Not per epoch. Once an assignment is in hand the machine works it at full
	// parallelism; the lever is whether to take on more, which is the decision
	// that actually protects the host. Gating each epoch instead would leave a
	// half-finished assignment sitting on a lease while the machine idled.
	BeforeNext func(ctx context.Context) error

	// Parallel reports how many epochs of this origin to verify at once,
	// consulted once per assignment. Nil means N-2.
	//
	// The origin is an argument because a proof's size is a fact about the log,
	// not about the machine. A WhatsApp epoch is a few megabytes and a Meta one
	// is nearly three hundred, and the same worker takes both; a single answer
	// for the host means whichever log has the largest proofs sets the width
	// for all of them, and a worker that has seen one Meta epoch runs WhatsApp
	// four at a time instead of eight for the rest of its life.
	//
	// A function rather than a number because the two hosts answer it
	// differently. A laptop answers with a constant — N-2 of the cores it is
	// allowed, which is what the operator asked for — and paces itself by not
	// asking for more work. The witness cannot: it shares its box with live
	// witnessing, which never yields, so its measured headroom sits at the
	// floor and a fixed threshold gate would wait forever. It answers instead
	// with what its governor says the machine can currently afford, and so
	// works one epoch at a time when the box is busy and eight when it is not.
	Parallel func(origin string) int

	Name string
	Idle time.Duration
	Log  *slog.Logger

	// EpochTimeout bounds one epoch. A rebuild is about a minute on a GPU and
	// a proof replay tens of seconds; far past that something has gone wrong in
	// a way that waiting will not fix, and the lease is expiring meanwhile.
	EpochTimeout time.Duration

	send sync.Mutex
}

// Fixed is a constant answer to Parallel, for a host whose share does not move
// and whose logs do not differ enough for it to matter.
func Fixed(n int) func(string) int { return func(string) int { return n } }

// DefaultParallel is N-2 cores, floored at one.
func DefaultParallel() int {
	n := runtime.GOMAXPROCS(0) - 2
	if n < 1 {
		return 1
	}
	return n
}

// Run keeps this machine's verification slots full until the context ends.
//
// A fixed pool of goroutines pulls epochs off one channel; a separate loop asks
// for more work whenever the channel is short. Nothing waits for a range to
// finish before the next one is requested, so the pipeline does not drain at
// range boundaries.
//
// It used to: Next returned one assignment, do() spread the pool across exactly
// that assignment's epochs, and everything stopped until the last one landed and
// an ack round-tripped. Measured on a laptop that could work eight at a time,
// twenty-three seconds passed between ranges of twelve epochs.
func (r *Runner) Run(ctx context.Context) error {
	idle := r.Idle
	if idle <= 0 {
		idle = 2 * time.Second
	}
	timeout := r.EpochTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	par := DefaultParallel()
	if r.Parallel != nil {
		par = r.Parallel("")
	}
	if par < 1 {
		par = 1
	}

	// Two contexts, and the split is the point.
	//
	// `ctx` governs whether to ask for MORE work: a cancelled parent stops the
	// request loop immediately. `work` governs epochs already accepted, and
	// deliberately survives the parent's cancellation — those epochs are out on
	// a lease and the witness is waiting for them, so dropping them strands the
	// range until its deadline and gains nothing. Each is still bounded by
	// EpochTimeout, so this cannot hang.
	//
	// The first version used one context for both, and a shutdown mid-range
	// silently discarded whatever was queued behind the epochs in flight.
	work, stopWork := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWork()

	// Depth two: one epoch being worked per slot, and one queued behind it. Any
	// deeper and this machine is holding a lease on work it will not start for
	// a while, which is the mistake the old dispatcher made in the other
	// direction — it pushed forty ranges at one worker, every one of them
	// counting down a deadline it could not meet.
	jobs := make(chan job, par*2)
	var inFlight atomic.Int64

	// Closed when reporting fails, which means the stream is gone. That is
	// different from the parent being cancelled: there, epochs already accepted
	// are still worth finishing because somebody is waiting for them. Here
	// nobody is, so everything stops — including the request loop, which would
	// otherwise go on asking a channel that has died.
	//
	// Without this the pool drained and Run never returned.
	failed := make(chan struct{})
	var failOnce sync.Once

	var wg sync.WaitGroup
	for i := 0; i < par; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if work.Err() != nil {
					inFlight.Add(-1)
					continue
				}
				if err := r.one(work, j.a, j.epoch, timeout); err != nil {
					// The results have nowhere to go: reporting failed, so
					// every further epoch would be CPU spent on an answer
					// nobody will receive.
					failOnce.Do(func() {
						stopWork()
						close(failed)
					})
				}
				inFlight.Add(-1)
			}
		}()
	}
	defer func() {
		close(jobs)
		wg.Wait()
	}()

	holding := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-failed:
			return ErrReportFailed
		default:
		}
		// Room for more? in-flight counts what is being worked and what is
		// queued behind it, so this asks before the pool runs dry rather than
		// after.
		room := int64(par*2) - inFlight.Load()
		if room <= 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-failed:
				return ErrReportFailed
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}

		if r.BeforeNext != nil {
			if err := r.BeforeNext(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// The host does not want more work yet. Wait and ask again;
				// this is pacing, not failure.
				//
				// Said out loud on the way in and the way out, because a worker
				// that is deliberately holding back and one that has hung look
				// identical from every other angle — and the silent version of
				// this cost an afternoon: a laptop sat in a gate that never
				// opened, never asked for work, and never noticed its own
				// connection had died, because nothing downstream of the gate
				// ever ran.
				if !holding && r.Log != nil {
					r.Log.Info("holding off asking for work; the host is busy", "reason", err)
				}
				holding = true
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(idle):
				}
				continue
			}
			if holding && r.Log != nil {
				r.Log.Info("host has room again; asking for work")
			}
			holding = false
		}

		a, err := r.Next(ctx, int(room))
		switch {
		case err == ErrNoWork:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(idle):
			}
			continue
		case err != nil:
			return err
		}
		if r.Log != nil {
			r.Log.Info("assignment", "id", a.ID, "origin", a.Origin,
				"from", a.From, "to", a.To, "epochs", a.To-a.From+1,
				"asked_for", room,
				"lease", time.Until(a.Deadline).Round(time.Second).String())
		}
		for e := a.From; e <= a.To; e++ {
			// Past the deadline the range may already belong to somebody else,
			// so continuing spends the scarcest resource on results that will
			// be refused.
			if !a.Deadline.IsZero() && time.Now().After(a.Deadline) {
				if r.Log != nil {
					r.Log.Warn("lease expired mid-assignment; stopping", "id", a.ID, "reached", e)
				}
				break
			}
			inFlight.Add(1)
			select {
			case <-ctx.Done():
				inFlight.Add(-1)
				return ctx.Err()
			case <-failed:
				inFlight.Add(-1)
				return ErrReportFailed
			case jobs <- job{a: a, epoch: e}:
			}
		}
	}
}

// job is one epoch and the assignment that authorises it.
type job struct {
	a     Assignment
	epoch int64
}

// one verifies a single epoch and reports whatever came of it. It returns an
// error only when the REPORT could not be delivered — a verification that
// failed is an answer and is reported as one.
func (r *Runner) one(ctx context.Context, a Assignment, e int64, timeout time.Duration) error {
	start := time.Now()
	res := Result{
		AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin,
		Epoch: e, Worker: r.Name,
	}
	ec, cancel := context.WithTimeout(ctx, timeout)
	prev, curr, err := r.Verify(ec, a.Origin, e, a.ProofBase)
	cancel()
	if err != nil {
		// Unavailable is an answer. The queue decides whether and when to try
		// again; this worker's job is to say what happened.
		res.Err = err.Error()
		// And to say it out loud. Nothing logged this, so a worker failing
		// every epoch and one verifying every epoch produced identical output:
		// the results went up the stream, the queue retried them one at a time,
		// and the only visible sign was assignments arriving with "-retry" in
		// their names, which is a long way from the machine that knows why.
		if r.Log != nil {
			r.Log.Warn("verification did not produce roots", "origin", a.Origin,
				"epoch", e, "err", err)
		}
	} else {
		// No verdict here, deliberately. Whether these match what the operator
		// published is the witness's question, and it is the only party that
		// knows the answer.
		res.ComputedPrev, res.ComputedCurr = prev, curr
	}
	res.DurationMS = time.Since(start).Milliseconds()

	r.send.Lock()
	defer r.send.Unlock()
	if err := r.Report(ctx, res); err != nil {
		if r.Log != nil {
			r.Log.Warn("cannot report; abandoning the rest of this range",
				"epoch", e, "err", err)
		}
		return err
	}
	return nil
}
