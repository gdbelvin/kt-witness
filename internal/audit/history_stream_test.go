package audit

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// The pipeline reorders results aggressively — three stages, each with its own
// pool — so these pin the settlement rules against completion order rather than
// assuming it.
//
// Every one of these describes a bug that has actually happened in this file.

func streamAuditor(t *testing.T, db *store.Store, v Verifier) *Auditor {
	t.Helper()
	return &Auditor{
		Store:   db,
		Sidecar: v,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: 5 * time.Second,
	}
}

func streamStore(t *testing.T, name, origin string, from, to int64) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.RecordHistory(&store.History{Origin: origin, From: from, To: to}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAuditProgress(origin, to); err != nil {
		t.Fatal(err)
	}
	return db
}

// gapSidecar refuses exactly one epoch and verifies everything else, with
// randomised delays so results arrive in an order unrelated to epoch order.
type gapSidecar struct {
	refuse int64
	mu     sync.Mutex
	seen   []int64
}

func (g *gapSidecar) Verify(context.Context, string, int64, string, string, time.Duration) (*Result, error) {
	return nil, nil
}

func (g *gapSidecar) VerifyCached(_ context.Context, _ string, epoch int64, _, _, _ string, _ time.Duration) (*Result, error) {
	// Jitter, so completion order is genuinely not epoch order.
	time.Sleep(time.Duration(rand.Intn(8)) * time.Millisecond)
	g.mu.Lock()
	g.seen = append(g.seen, epoch)
	g.mu.Unlock()
	if epoch == g.refuse {
		return &Result{OK: false, Kind: "fetch", Error: "HTTP 403"}, nil
	}
	return &Result{OK: true, Bytes: 1, VerifyMS: 1}, nil
}

func (g *gapSidecar) Close() {}

// The cursor must never step past an epoch that is not settled, however the
// results happen to arrive.
//
// This is the property that makes the whole coverage claim meaningful: a hole
// inside the swept range would make "audited across published history" false
// while looking complete.
func TestCursorNeverPassesAGapUnderReordering(t *testing.T) {
	const origin = "meta.test/v1"
	db := streamStore(t, "gap.db", origin, 1, 1000)
	a := streamAuditor(t, db, &gapSidecar{refuse: 990})

	if _, err := a.RunHistory(context.Background(), &staticResolver{origin: origin}, 32); err != nil {
		t.Fatal(err)
	}

	back, started, err := db.BackAuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	if !started {
		t.Fatal("sweep recorded no progress at all")
	}
	// 999..991 verify; 990 is refused. The cursor must stop at 991 and must
	// never reach 990 or below.
	if back != 991 {
		t.Fatalf("cursor at %d, want 991 — it must halt at the epoch above the "+
			"refused one (990) no matter what order results arrived in", back)
	}
}

// Verified epochs BELOW a gap must still be recorded, even though the cursor
// cannot advance over them.
//
// These are two different questions, and conflating them threw away completed
// verifications once already: the next pass simply redid them, so coverage
// stood still while the machine was plainly busy.
func TestWorkBehindAGapIsStillRecorded(t *testing.T) {
	const origin = "meta.test/v1"
	db := streamStore(t, "behind.db", origin, 1, 1000)
	a := streamAuditor(t, db, &gapSidecar{refuse: 995})

	if _, err := a.RunHistory(context.Background(), &staticResolver{origin: origin}, 32); err != nil {
		t.Fatal(err)
	}

	// 994 sits below the refused epoch, so the cursor cannot claim it — but it
	// was verified and that fact must survive.
	got, err := db.GetAudit(origin, 994)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Verified {
		t.Fatalf("epoch 994 (below the gap at 995) is %+v; verified work behind a "+
			"gap must be recorded, or the next pass pays for it again", got)
	}
	// And the cursor must still not have passed the gap.
	back, _, err := db.BackAuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	if back <= 995 {
		t.Fatalf("cursor at %d; recording work behind the gap must not license "+
			"advancing over it", back)
	}
}

// The refused epoch spends exactly one attempt per pass — not one per worker,
// and not none.
func TestRefusedEpochSpendsExactlyOneAttemptPerPass(t *testing.T) {
	const origin = "meta.test/v1"
	db := streamStore(t, "attempts.db", origin, 1, 1000)
	a := streamAuditor(t, db, &gapSidecar{refuse: 999})

	for pass := 1; pass <= 2; pass++ {
		if _, err := a.RunHistory(context.Background(), &staticResolver{origin: origin}, 16); err != nil {
			t.Fatal(err)
		}
		got, err := db.GetAudit(origin, 999)
		if err != nil || got == nil {
			t.Fatalf("pass %d: no record for the refused epoch: %v", pass, err)
		}
		if got.Attempts != pass {
			t.Fatalf("pass %d: attempts=%d, want %d", pass, got.Attempts, pass)
		}
	}
	// After the attempts are spent the epoch carries a backoff rather than a
	// permanent verdict.
	got, _ := db.GetAudit(origin, 999)
	if got.Attempts >= maxFetchAttempts && got.RetryAfter.IsZero() {
		t.Fatal("an exhausted epoch must carry a retry time, or the hole is permanent")
	}
}

// A cancelled context must leave no trace: no records, no attempts, no cursor
// movement. Restarts would otherwise retire epochs nobody ever asked for.
func TestCancelledPipelineRecordsNothing(t *testing.T) {
	const origin = "meta.test/v1"
	db := streamStore(t, "cancel-stream.db", origin, 1, 1000)
	a := streamAuditor(t, db, &cancelSidecar{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.RunHistory(ctx, &staticResolver{origin: origin}, 32); err != nil {
		t.Fatal(err)
	}

	for epoch := int64(970); epoch < 1000; epoch++ {
		got, err := db.GetAudit(origin, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("epoch %d recorded (attempts=%d) after a cancelled pass; "+
				"we stopped asking, the log did not refuse", epoch, got.Attempts)
		}
	}
}

// A clean run settles the whole budget contiguously.
func TestCleanRunAdvancesOverTheWholeBudget(t *testing.T) {
	const origin = "meta.test/v1"
	db := streamStore(t, "clean.db", origin, 1, 1000)
	a := streamAuditor(t, db, &gapSidecar{refuse: -1}) // refuse nothing

	out, err := a.RunHistory(context.Background(), &staticResolver{origin: origin}, 32)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verified != 32 {
		t.Fatalf("verified %d of a 32 budget", out.Verified)
	}
	back, _, err := db.BackAuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	if back != 968 { // 999 down to 968 inclusive is 32 epochs
		t.Fatalf("cursor at %d, want 968 after settling 32 epochs cleanly", back)
	}
}
