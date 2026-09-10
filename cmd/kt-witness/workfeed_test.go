package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/work"
)

func newFeeder(t *testing.T, origins ...string) (*feeder, *store.Store, *work.Queue) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	q := work.NewQueue(20 * time.Minute)
	return &feeder{db: db, q: q, origins: origins,
		log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		next: map[string]int64{}}, db, q
}

func recordVerified(t *testing.T, db *store.Store, origin string, epochs ...int64) {
	t.Helper()
	for _, e := range epochs {
		if err := db.RecordAudit(&store.Audit{
			Origin: origin, Epoch: e, Verified: true, Sampled: true,
			DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTheFeedComesBackForWhatItSkipped is the bug that left a laptop idle in
// front of 7,880 unverified epochs with an empty queue.
//
// The cursor only ever moved forward. When it reached the end of a history it
// parked there, and every later pass fell through the "nothing left to offer"
// branch — so anything that had failed, been rescheduled, or been skipped was
// never offered again until the process restarted. That restart is the only
// reason it was survivable, and it made the symptom look like something else
// each time.
func TestTheFeedComesBackForWhatItSkipped(t *testing.T) {
	const origin = "whatsapp.kt/v2"
	f, db, q := newFeeder(t, origin)
	if err := db.RecordHistory(&store.History{Origin: origin, From: 1, To: 200,
		Epochs: 200, VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	// Drain the whole history the way a healthy fleet would, marking every
	// epoch verified as it goes, until the feed says there is nothing left.
	for i := 0; i < 100; i++ {
		f.topUp()
		a, err := q.Lease("w", []string{origin})
		if err != nil {
			break
		}
		step := a.Step
		if step < 1 {
			step = 1
		}
		for e := a.From; e <= a.To; e += step {
			recordVerified(t, db, origin, e)
		}
		q.Done(a.ID)
	}

	// Now one epoch turns out to be unverified — a failure, a reschedule, a
	// canary that came back wrong. The feed must offer it again.
	if err := db.RecordAudit(&store.Audit{
		Origin: origin, Epoch: 87, Verified: false, Sampled: true,
		DecidedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	f.topUp()
	if p, l := q.Stats(); p+l == 0 {
		t.Fatal("the feed offered nothing while an unverified epoch remained; " +
			"the cursor parked at the end and never came back")
	}
}

// TestAHalfDoneChunkIsNotCountedAsDone. A range is handed out as two
// interleaved assignments — evens and odds — so when one half succeeds and the
// other fails, the chunk's FIRST epoch is verified and a dozen others are not.
// Probing only that first epoch declared the whole chunk done and skipped it
// permanently, which is how a hole gets left behind that nothing ever fills.
func TestAHalfDoneChunkIsNotCountedAsDone(t *testing.T) {
	const origin = "whatsapp.kt/v2"
	f, db, _ := newFeeder(t, origin)
	h := &store.History{Origin: origin, From: 1, To: 100}

	// The odd epochs of the first chunk are done; the even ones are not —
	// which is exactly what one interleaved half succeeding looks like. Both
	// ends of the chunk (1 and 25) are odd, so the two-probe version of this
	// declared the chunk finished and skipped twelve epochs permanently.
	for e := int64(1); e <= feedChunk; e += 2 {
		recordVerified(t, db, origin, e)
	}

	at, found := f.nextUnaudited(origin, h, 1)
	if !found {
		t.Fatal("reported a fully-audited history when half a chunk was missing")
	}
	if at != 2 {
		t.Errorf("first unaudited epoch is %d, want 2 — epoch 1 is verified and "+
			"epoch 2 is the first that is not", at)
	}
}

// TestAFullyAuditedHistoryIsNotRescannedForever: the wrap must not turn into a
// busy loop that re-offers verified work to every machine in the fleet.
func TestAFullyAuditedHistoryIsNotRescannedForever(t *testing.T) {
	const origin = "whatsapp.kt/v2"
	f, db, _ := newFeeder(t, origin)
	h := &store.History{Origin: origin, From: 1, To: 100}
	for e := int64(1); e <= 100; e++ {
		recordVerified(t, db, origin, e)
	}
	if _, found := f.nextUnaudited(origin, h, 1); found {
		t.Error("a fully audited history still reported work to do")
	}
}
