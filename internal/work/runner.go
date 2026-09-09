package work

import (
	"context"
	"log/slog"
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
// witness those are a queue, a sidecar and a store. On a laptop they are a gRPC
// stream, a sidecar and the same stream back.
type Runner struct {
	// Next blocks until an assignment is available, or returns ErrNoWork to be
	// asked again after Idle.
	Next func(ctx context.Context) (Assignment, error)
	// Verify returns what it computed and what the operator signed. It decides
	// nothing: a disagreement is for the witness to resolve, and a worker that
	// concluded misbehaviour on its own would be claiming an authority the
	// whole design withholds from it.
	Verify func(ctx context.Context, origin string, epoch int64) (root, signed string, err error)
	// Report records one verdict.
	Report func(ctx context.Context, r Result) error

	Name string
	Idle time.Duration
	Log  *slog.Logger

	// Acquire gates concurrency on THIS host, and is where a worker protects
	// the machine it is borrowing.
	//
	// It belongs here rather than on the witness because the question is local:
	// how much of this machine may a background job take without making it
	// unpleasant for whoever is actually using it. A witness cannot answer that
	// for a laptop — it has no idea what else the laptop is doing — and a
	// laptop taking its concurrency from a 32-core server would either idle or
	// bring its owner's machine to a crawl.
	//
	// Nil means no gating, which is right only for a machine doing nothing
	// else.
	Acquire func(ctx context.Context) (release func(), err error)

	// EpochTimeout bounds one epoch. A rebuild is about a minute on a GPU and
	// a proof replay tens of seconds; far past that something has gone wrong in
	// a way that waiting will not fix, and the lease is expiring meanwhile.
	EpochTimeout time.Duration
}

// Run works assignments until the context ends.
func (r *Runner) Run(ctx context.Context) error {
	idle := r.Idle
	if idle <= 0 {
		idle = 2 * time.Second
	}
	timeout := r.EpochTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := r.Next(ctx)
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
		r.do(ctx, a, timeout)
	}
}

func (r *Runner) do(ctx context.Context, a Assignment, timeout time.Duration) {
	if r.Log != nil {
		r.Log.Info("assignment", "id", a.ID, "origin", a.Origin,
			"from", a.From, "to", a.To,
			"lease", time.Until(a.Deadline).Round(time.Second).String())
	}
	for e := a.From; e <= a.To; e++ {
		if ctx.Err() != nil {
			return
		}
		// Past the deadline the witness refuses whatever we send, and the range
		// may already belong to somebody else. Stopping is the polite thing and
		// also the only useful one.
		if !a.Deadline.IsZero() && time.Now().After(a.Deadline) {
			if r.Log != nil {
				r.Log.Warn("lease expired mid-assignment; stopping", "id", a.ID, "reached", e)
			}
			return
		}
		release := func() {}
		if r.Acquire != nil {
			rel, err := r.Acquire(ctx)
			if err != nil {
				// Could not get permission to run. Not a failure of the epoch:
				// stop the assignment and let the lease return it, rather than
				// reporting epochs unverified because this host was busy.
				if r.Log != nil {
					r.Log.Info("yielding: this host is too busy to continue", "err", err)
				}
				return
			}
			release = rel
		}

		start := time.Now()
		res := Result{
			AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin,
			Epoch: e, Worker: r.Name,
		}
		ec, cancel := context.WithTimeout(ctx, timeout)
		root, signed, err := r.Verify(ec, a.Origin, e)
		cancel()
		if err != nil {
			res.Err = err.Error()
		} else {
			res.Root, res.SignedRoot = root, signed
			res.Verified = root != "" && root == signed
		}
		res.DurationMS = time.Since(start).Milliseconds()
		release()

		if err := r.Report(ctx, res); err != nil {
			if r.Log != nil {
				r.Log.Warn("reporting", "epoch", e, "err", err)
			}
			return
		}
	}
}
