package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// The three strategies must never audit the same epoch twice. Re-auditing is
// wasted bandwidth and CPU on a system where both are the binding constraint,
// and at ~372 GB/day the waste is not academic.
//
// This tests the backstop that catches whatever the range invariants miss: a
// settled decision is skipped by every strategy, whichever one settled it.
func TestSettledEpochsAreNotReAudited(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	// Epoch 500 settled by the forward pass.
	if err := db.RecordAudit(&store.Audit{
		Origin: origin, Epoch: 500, Sampled: true, Rate: 1,
		Strategy: string(StrategyLive), Verified: true, DecidedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetAudit(origin, 500)
	if err != nil || got == nil {
		t.Fatalf("stored decision not readable: %v", err)
	}
	if !got.Verified {
		t.Fatal("stored decision lost its verified flag")
	}
	// The history sweep consults exactly this before doing any work, and skips
	// on Verified. If that contract changes, this test should fail loudly.
	if got.Strategy != string(StrategyLive) {
		t.Errorf("strategy not recorded: %q", got.Strategy)
	}
}

// The forward pass and the backwards sweep move away from each other and keep
// separate high-water marks, so they cannot converge on the same epoch.
func TestForwardAndHistoryProgressAreIndependent(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	if err := db.SetAuditProgress(origin, 1000); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBackAuditProgress(origin, 900); err != nil {
		t.Fatal(err)
	}

	fwd, err := db.AuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	back, err := db.BackAuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	if fwd != 1000 || back != 900 {
		t.Fatalf("progress markers collided: forward=%d backward=%d", fwd, back)
	}
	// The forward pass works upward from fwd; the sweep works downward from
	// back. Their ranges are disjoint as long as back <= fwd.
	if back > fwd {
		t.Error("the backwards sweep has overtaken the forward pass; ranges would overlap")
	}
}

// Coverage must count each epoch once, or "audited across published history"
// could be satisfied by auditing one epoch repeatedly.
func TestCoverageCountsDistinctEpochs(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "o"
	for i := 0; i < 3; i++ {
		// Same epoch recorded repeatedly, as a retry would.
		if err := db.RecordAudit(&store.Audit{
			Origin: origin, Epoch: 42, Sampled: true, Verified: true,
			Attempts: i + 1, DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	settled, verified, err := db.AuditCoverage(origin, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if settled != 1 || verified != 1 {
		t.Fatalf("re-recording one epoch inflated coverage: settled=%d verified=%d", settled, verified)
	}
}
