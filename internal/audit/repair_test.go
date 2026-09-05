package audit

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// A hole must be retried, not written off.
//
// The backwards sweep only ever walks down, so an epoch it passed is behind it
// forever. Before this, a transient refusal — a stale negative listing from
// CloudFront, a 403 that clears a minute later — became a permanent gap inside
// the range tier B+ claims to have audited.
func TestHolesAreRetriedAfterBackoff(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "repair.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	if err := db.RecordHistory(&store.History{Origin: origin, From: 1, To: 1000}); err != nil {
		t.Fatal(err)
	}
	// The sweep has walked down to 900, leaving a hole at 950 behind it.
	if err := db.SetBackAuditProgress(origin, 900); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-2 * time.Hour)
	if err := db.RecordAudit(&store.Audit{
		Origin: origin, Epoch: 950, Sampled: true, Rate: 1,
		Strategy: string(StrategyHistory), Verified: false,
		Attempts: maxFetchAttempts, DecidedAt: past,
		RetryAfter: past.Add(time.Hour), // elapsed
	}); err != nil {
		t.Fatal(err)
	}

	a := &Auditor{
		Store:   db,
		Sidecar: &okSidecar{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: time.Second,
	}

	res, err := a.RunRepair(context.Background(), &staticResolver{origin: origin}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attempted != 1 {
		t.Fatalf("attempted %d holes, want 1 — the sweep cannot reach 950 again, "+
			"so if repair does not it is a permanent gap", res.Attempted)
	}
	if res.Repaired != 1 {
		t.Fatalf("repaired %d, want 1", res.Repaired)
	}
	got, err := db.GetAudit(origin, 950)
	if err != nil || got == nil {
		t.Fatalf("record missing after repair: %v", err)
	}
	if !got.Verified {
		t.Fatal("hole was retried successfully but not recorded as verified")
	}
}

// A hole whose backoff has NOT elapsed must be left alone, or the backoff buys
// nothing and a dead epoch is hammered every round.
func TestHolesWaitForTheirBackoff(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "backoff.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	if err := db.RecordHistory(&store.History{Origin: origin, From: 1, To: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetBackAuditProgress(origin, 900); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.RecordAudit(&store.Audit{
		Origin: origin, Epoch: 950, Sampled: true, Rate: 1,
		Strategy: string(StrategyHistory), Verified: false,
		Attempts: maxFetchAttempts, DecidedAt: now,
		RetryAfter: now.Add(time.Hour), // still waiting
	}); err != nil {
		t.Fatal(err)
	}

	a := &Auditor{
		Store:   db,
		Sidecar: &okSidecar{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: time.Second,
	}
	res, err := a.RunRepair(context.Background(), &staticResolver{origin: origin}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if res.Attempted != 0 {
		t.Fatalf("attempted %d; a hole inside its backoff must be left alone", res.Attempted)
	}
}

// The backoff must grow, and must stop growing at the cap.
func TestRetryBackoffGrowsAndIsCapped(t *testing.T) {
	now := time.Now().UTC()

	if got := retryAfter(now, maxFetchAttempts-1); !got.IsZero() {
		t.Fatalf("an epoch with attempts left should carry no backoff, got %v", got)
	}

	first := retryAfter(now, maxFetchAttempts).Sub(now)
	if first != retryBackoffBase {
		t.Fatalf("first backoff %v, want %v", first, retryBackoffBase)
	}
	second := retryAfter(now, maxFetchAttempts+1).Sub(now)
	if second != 2*retryBackoffBase {
		t.Fatalf("second backoff %v, want %v", second, 2*retryBackoffBase)
	}
	// Far past the cap, it must not keep doubling into the heat death.
	capped := retryAfter(now, maxFetchAttempts+50).Sub(now)
	if capped != retryBackoffMax {
		t.Fatalf("backoff %v at high attempt count, want the cap %v", capped, retryBackoffMax)
	}
}

// The contiguous verified region is the honest form of the coverage claim: an
// audited count cannot distinguish a solid range from a sieve.
func TestVerifiedRegionReportsTheUnbrokenRun(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "region.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	// 100..104 verified, 105 a hole, 106..110 verified. Nine verified epochs,
	// but the largest unbroken run is five.
	for e := int64(100); e <= 110; e++ {
		if err := db.RecordAudit(&store.Audit{
			Origin: origin, Epoch: e, Sampled: true, Rate: 1,
			Verified: e != 105, DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	lo, hi, run, holes, err := db.VerifiedRegion(origin, 100, 110)
	if err != nil {
		t.Fatal(err)
	}
	if holes != 1 {
		t.Fatalf("holes=%d, want 1", holes)
	}
	if run != 5 {
		t.Fatalf("largest run %d..%d (%d epochs), want 5 — a count of ten "+
			"audited epochs would hide the gap at 105", lo, hi, run)
	}
}

// A log whose history starts at epoch 0 must report its run correctly.
//
// The first version derived the run length from lo and hi and used `lo > 0` to
// mean "no run found". thelemail.com/keys starts at epoch 0, so a fully audited
// log reported a verified run of zero — the metric said the weakest possible
// thing about the most completely audited log we have.
func TestVerifiedRegionHandlesEpochZero(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "zero.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "thelemail.test/keys"
	for e := int64(0); e <= 9; e++ {
		if err := db.RecordAudit(&store.Audit{
			Origin: origin, Epoch: e, Sampled: true, Rate: 1,
			Verified: true, DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	lo, hi, run, holes, err := db.VerifiedRegion(origin, 0, 9)
	if err != nil {
		t.Fatal(err)
	}
	if run != 10 || lo != 0 || hi != 9 || holes != 0 {
		t.Fatalf("run=%d lo=%d hi=%d holes=%d; want a complete run of 10 from 0..9 — "+
			"epoch 0 is a real epoch, not an absent one", run, lo, hi, holes)
	}
}

// okSidecar verifies everything it is asked about.
type okSidecar struct{}

func (o *okSidecar) Verify(context.Context, string, int64, string, string, time.Duration) (*Result, error) {
	return &Result{OK: true, Bytes: 1, VerifyMS: 1}, nil
}

func (o *okSidecar) VerifyCached(context.Context, string, int64, string, string, string, time.Duration) (*Result, error) {
	return &Result{OK: true, Bytes: 1, VerifyMS: 1}, nil
}

func (o *okSidecar) Close() {}
