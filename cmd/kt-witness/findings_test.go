package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

// fixedResolver publishes one pair of roots for every epoch.
type fixedResolver struct{ origin, prev, curr string }

func (r *fixedResolver) Origin() string { return r.origin }
func (r *fixedResolver) ResolveEpoch(context.Context, int64) (*audit.EpochRef, error) {
	return &audit.EpochRef{LogDirectory: "https://example.invalid",
		PrevRoot: r.prev, CurrRoot: r.curr}, nil
}

func findingsFixture(t *testing.T) (*store.Store, *work.Queue, []audit.Resolver, *slog.Logger) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	q := work.NewQueue(time.Minute)
	res := []audit.Resolver{&fixedResolver{origin: "m/kt", prev: "aa", curr: "bb"}}
	return db, q, res, slog.New(slog.NewTextHandler(io.Discard, nil))
}

// leaseOne puts an assignment in the queue so Accept-style bookkeeping has
// something to answer, and returns a result shaped like the worker's.
func leaseOne(t *testing.T, q *work.Queue, worker string, epoch int64) work.Result {
	t.Helper()
	q.Origins = []string{"m/kt"}
	q.Source = func(o string, after int64, n int) (int64, int64, bool) {
		return epoch, epoch, true
	}
	a, err := q.Lease(worker, []string{"m/kt"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return work.Result{AssignmentID: a.ID, Nonce: a.Nonce, Origin: "m/kt",
		Epoch: epoch, Worker: worker}
}

// TestOnlyThisWitnessesOwnArithmeticPoisonsALog.
//
// A fork record is a permanent, public accusation that a named operator built
// its tree wrongly. Getting it wrong in the accusing direction is the worst
// thing this program can do, so both halves are pinned here.
func TestOnlyThisWitnessesOwnArithmeticPoisonsALog(t *testing.T) {
	t.Run("a remote worker's mismatch does not", func(t *testing.T) {
		db, q, res, log := findingsFixture(t)
		r := leaseOne(t, q, "somebody-elses-laptop", 100)
		r.ComputedPrev, r.ComputedCurr = "ff", "ee" // disagrees with aa/bb

		if err := recordWorkerResult(context.Background(), db, q, nil, nil, res, r, false, log); err != nil {
			t.Fatal(err)
		}
		forks, err := db.Forks()
		if err != nil {
			t.Fatal(err)
		}
		if len(forks) != 0 {
			t.Fatalf("a borrowed machine's disagreement published an accusation: %+v", forks)
		}
	})

	t.Run("a worker CALLING itself witness does not", func(t *testing.T) {
		// The check must be structural, not a name off the wire. Anything on
		// the work channel can send Hello.Name "witness"; if that were enough
		// to poison a log, one hostile worker could make this witness accuse an
		// honest operator.
		db, q, res, log := findingsFixture(t)
		r := leaseOne(t, q, "witness", 101)
		r.ComputedPrev, r.ComputedCurr = "ff", "ee"

		if err := recordWorkerResult(context.Background(), db, q, nil, nil, res, r, false, log); err != nil {
			t.Fatal(err)
		}
		if forks, _ := db.Forks(); len(forks) != 0 {
			t.Fatalf("a worker that named itself 'witness' published an accusation: %+v", forks)
		}
	})

	t.Run("this witness's own verifier does", func(t *testing.T) {
		db, q, res, log := findingsFixture(t)
		r := leaseOne(t, q, "witness", 102)
		r.ComputedPrev, r.ComputedCurr = "ff", "ee"

		if err := recordWorkerResult(context.Background(), db, q, nil, nil, res, r, true, log); err != nil {
			t.Fatal(err)
		}
		forks, err := db.Forks()
		if err != nil {
			t.Fatal(err)
		}
		if len(forks) != 1 {
			t.Fatalf("this witness computed a root the operator did not publish and "+
				"recorded %d findings, want 1", len(forks))
		}
		if forks[0].Origin != "m/kt" {
			t.Errorf("finding names %q", forks[0].Origin)
		}
	})

	t.Run("an epoch that could not be fetched does not", func(t *testing.T) {
		// "I could not check this" and "this is provably wrong" must never be
		// the same outcome. A download failure is about the network, or about
		// data ageing out of the operator's storage — neither is evidence
		// about how the tree was built.
		db, q, res, log := findingsFixture(t)
		r := leaseOne(t, q, "witness", 103)
		r.Err = "download body: connection reset"

		if err := recordWorkerResult(context.Background(), db, q, nil, nil, res, r, true, log); err != nil {
			t.Fatal(err)
		}
		if forks, _ := db.Forks(); len(forks) != 0 {
			t.Fatalf("an unreachable epoch published an accusation: %+v", forks)
		}
	})

	t.Run("agreement records the epoch and accuses nobody", func(t *testing.T) {
		db, q, res, log := findingsFixture(t)
		r := leaseOne(t, q, "witness", 104)
		r.ComputedPrev, r.ComputedCurr = "aa", "bb" // matches what was published

		if err := recordWorkerResult(context.Background(), db, q, nil, nil, res, r, true, log); err != nil {
			t.Fatal(err)
		}
		if forks, _ := db.Forks(); len(forks) != 0 {
			t.Fatalf("a matching verification published an accusation: %+v", forks)
		}
		a, err := db.GetAudit("m/kt", 104)
		if err != nil || a == nil || !a.Verified {
			t.Errorf("a good verification was not recorded as verified: %+v %v", a, err)
		}
	})
}
