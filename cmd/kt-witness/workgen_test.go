package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

func genStore(t *testing.T, origin string, from, to int64) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.RecordHistory(&store.History{Origin: origin, From: from, To: to,
		Epochs: int(to - from + 1), VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return db
}

// markVerified writes the fixture.
//
// Kept small on purpose: RecordAudit takes its own transaction per call, so a
// ten-thousand-epoch fixture is ten thousand fsyncs and the test looks like a
// hang. None of these properties needs a long history to hold — they are about
// which direction a cursor moves, not how far.
func markVerified(t *testing.T, db *store.Store, origin string, from, to int64) {
	t.Helper()
	now := time.Now().UTC()
	for e := from; e <= to; e++ {
		if err := db.RecordAudit(&store.Audit{Origin: origin, Epoch: e,
			Verified: true, Sampled: true, DecidedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTheForwardCursorDoesNotRewind is the property that lets a steady state
// exist at all.
//
// The previous generator reset its cursor to zero whenever it found nothing
// from where it was. A log that is caught up has its first unverified epoch at
// the TIP, so that reset made every poll walk the entire verified history to
// rediscover it — 353ms across half a million epochs, every ten seconds, per
// log, growing linearly for as long as the log lives. That is not a slow steady
// state; it is the absence of one.
func TestTheForwardCursorDoesNotRewind(t *testing.T) {
	const o = "whatsapp.kt/v2"
	db := genStore(t, o, 1, 260)
	h := &store.History{Origin: o, From: 1, To: 260}
	markVerified(t, db, o, 1, 200)

	var c cursors
	c.init(db, o, h)

	// First pass finds the unverified region above the verified prefix.
	got := c.forward(db, o, h, 4)
	if len(got) != 4 || got[0] != 201 {
		t.Fatalf("first pass returned %v, want four epochs from 201", got)
	}
	after := c.fwd
	if after <= 200 {
		t.Fatalf("cursor at %d after finding work at 201", after)
	}

	// Everything verified: the cursor must PARK at the tip, not rewind.
	markVerified(t, db, o, 201, 260)
	if got := c.forward(db, o, h, 4); len(got) != 0 {
		t.Errorf("returned %v for a fully verified history", got)
	}
	if c.fwd < 200 {
		t.Errorf("cursor rewound to %d; the next published epoch appears at the "+
			"tip and this is what makes finding it cheap", c.fwd)
	}

	// A newly published epoch is found without re-walking anything.
	h.To = 261
	if got := c.forward(db, o, h, 4); len(got) != 1 || got[0] != 261 {
		t.Errorf("new epoch at the tip: got %v, want [261]", got)
	}
}

// TestTheBackwardCursorDescendsAndWraps. The history sweep is what finds gaps
// the forward pass went past — epochs that failed, or were never fetched. It
// must descend rather than sit, and must start over rather than stop.
func TestTheBackwardCursorDescendsAndWraps(t *testing.T) {
	const o = "m/kt"
	db := genStore(t, o, 1, 300)
	h := &store.History{Origin: o, From: 1, To: 300}
	markVerified(t, db, o, 1, 300)

	// One hole, well below the tip.
	if err := db.RecordAudit(&store.Audit{Origin: o, Epoch: 100,
		Verified: false, Sampled: true, DecidedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	var c cursors
	c.init(db, o, h)
	c.fwd, c.back = 300, 300
	c.stride = 32 // so the fixture need not be thousands of epochs long

	// Descending, it must reach the hole within a bounded number of probes
	// rather than needing one poll per epoch.
	found := false
	start := c.back
	for i := 0; i < 20 && !found; i++ {
		for _, e := range c.backward(db, o, h, 4) {
			if e == 100 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the sweep did not reach the gap at 100 (cursor %d -> %d)", start, c.back)
	}
	if c.back >= start {
		t.Errorf("the backward cursor did not descend: %d -> %d", start, c.back)
	}
}

// TestCursorsSurviveARestart. Both are seeded from what the store already
// recorded, so a restart does not re-cover ground the last run covered — which
// on a half-million-epoch history is the difference between resuming and
// starting again.
func TestCursorsSurviveARestart(t *testing.T) {
	const o = "m/kt"
	db := genStore(t, o, 1, 100000)
	h := &store.History{Origin: o, From: 1, To: 100000} // no records written; only the watermarks matter
	if err := db.SetAuditProgress(o, 60000); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBackAuditProgress(o, 40000); err != nil {
		t.Skipf("no back-progress accessor to seed: %v", err)
	}

	var c cursors
	c.init(db, o, h)
	if c.fwd != 60000 {
		t.Errorf("forward cursor %d, want the recorded progress 60000", c.fwd)
	}
	if c.back != 40000 {
		t.Errorf("backward cursor %d, want the recorded back progress 40000", c.back)
	}
}
