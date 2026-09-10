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

// A shutdown must not spend an epoch's fetch attempts.
//
// # The bug this pins
//
// Every `blocked` result incremented Attempts, and a cancelled context produces
// a blocked result. So each container restart charged an attempt to every epoch
// in the in-flight batch — up to sixty-four of them. At three attempts the skip
// loop treats an epoch as settled and the cursor steps over it, so three deploys
// landing while the sweep sat near the same region would punch a permanent hole
// in the swept range without a single request having been refused.
//
// That is the worst shape a bug can take here: it manufactures a gap in
// published history coverage out of nothing but operator activity, and the
// resulting record claims the epoch was checked and found wanting when in truth
// it was never asked for.
//
// The rule: "the log would not give it to us" and "we stopped asking" are
// different facts and only the first one counts against an epoch.
//
// This drives the real RunHistory rather than reimplementing its loop. The
// earlier tests in this package restate the logic they check, which is why they
// kept passing through three consecutive bugs in exactly that logic.
func TestShutdownDoesNotConsumeFetchAttempts(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"

	// A log published 1..1000; the forward auditor established a floor at 1000,
	// so the backwards sweep starts there.
	if err := db.RecordHistory(&store.History{Origin: origin, From: 1, To: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAuditProgress(origin, 1000); err != nil {
		t.Fatal(err)
	}

	a := &Auditor{
		Store:    db,
		Verifier: &cancelVerifier{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout:  time.Second,
	}

	// Three passes, each cancelled the way a shutdown cancels one.
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already dead before any work starts
		if _, err := a.RunHistory(ctx, &staticResolver{origin: origin}, 8); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}

	// After three cancelled passes the epochs below the cursor must be exactly
	// as untouched as before: no record, and therefore no attempts spent.
	for epoch := int64(992); epoch < 1000; epoch++ {
		got, err := db.GetAudit(origin, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("epoch %d has a record after three cancelled passes "+
				"(verified=%v attempts=%d); a shutdown is not a failed fetch, and "+
				"charging attempts for it lets restarts retire an epoch that was "+
				"never actually requested",
				epoch, got.Verified, got.Attempts)
		}
	}

	// And the cursor must not have advanced over them.
	back, _, err := db.BackAuditProgress(origin)
	if err != nil {
		t.Fatal(err)
	}
	if back != 0 && back < 1000 {
		t.Fatalf("sweep cursor advanced to %d across cancelled passes; "+
			"nothing was verified, so nothing should have been claimed", back)
	}
}

// A genuine refusal, by contrast, must still spend an attempt — otherwise the
// stall this protects against comes straight back.
func TestRefusedFetchStillConsumesAnAttempt(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "refuse.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "meta.test/v1"
	if err := db.RecordHistory(&store.History{Origin: origin, From: 1, To: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAuditProgress(origin, 1000); err != nil {
		t.Fatal(err)
	}

	a := &Auditor{
		Store:    db,
		Verifier: &refusingVerifier{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout:  time.Second,
	}

	// A live context: the log refuses, we do not stop.
	if _, err := a.RunHistory(context.Background(), &staticResolver{origin: origin}, 4); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := db.GetAudit(origin, 999)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("a refused fetch left no record; the epoch would be retried forever")
	}
	if got.Attempts != 1 {
		t.Fatalf("attempts=%d after one refusal, want 1", got.Attempts)
	}
	if got.Verified {
		t.Fatal("a refused fetch must never be recorded as verified")
	}
}

// staticResolver resolves every epoch successfully; the interesting behaviour is
// in the verifiers below.
type staticResolver struct{ origin string }

func (s *staticResolver) Origin() string { return s.origin }

func (s *staticResolver) ResolveEpoch(ctx context.Context, epoch int64) (*EpochRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &EpochRef{LogDirectory: "https://example.invalid", PrevRoot: "aa", CurrRoot: "bb"}, nil
}

// cancelVerifier stands in for work interrupted by shutdown.
type cancelVerifier struct{}

func (c *cancelVerifier) Verify(ctx context.Context, _ string, _ int64, _, _ string, _ time.Duration) (*Result, error) {
	return nil, ctx.Err()
}

func (c *cancelVerifier) VerifyCached(ctx context.Context, _ string, _ int64, _, _, _ string, _ time.Duration) (*Result, error) {
	return nil, ctx.Err()
}

func (c *cancelVerifier) Close() {}

// refusingVerifier stands in for a log that will not serve a proof: a 403, a
// pruned blob, a hole in the CDN. Not a finding, but it is the log's answer.
type refusingVerifier struct{}

func (r *refusingVerifier) Verify(context.Context, string, int64, string, string, time.Duration) (*Result, error) {
	return &Result{OK: false, Kind: "fetch", Error: "HTTP 403"}, nil
}

func (r *refusingVerifier) VerifyCached(context.Context, string, int64, string, string, string, time.Duration) (*Result, error) {
	return &Result{OK: false, Kind: "fetch", Error: "HTTP 403"}, nil
}

func (r *refusingVerifier) Close() {}
