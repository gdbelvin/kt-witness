package audit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

// fakeSidecar writes a shell script that speaks the sidecar's line protocol, so
// the auditor's decision logic can be tested without a 284 MB download.
func fakeSidecar(t *testing.T, response string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-sidecar")
	script := fmt.Sprintf(`#!/bin/sh
while IFS= read -r line; do
  epoch=$(printf '%%s' "$line" | sed -n 's/.*"epoch":\([0-9]*\).*/\1/p')
  printf '%s\n' "$epoch"
done
`, response)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type stubResolver struct{ origin string }

func (s *stubResolver) Origin() string { return s.origin }
func (s *stubResolver) ResolveEpoch(context.Context, int64) (*EpochRef, error) {
	return &EpochRef{LogDirectory: "https://example.invalid", PrevRoot: "aa", CurrRoot: "bb"}, nil
}

func newTestAuditor(t *testing.T, sidecarPath string, rate float64) (*Auditor, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	sc := NewSidecar(sidecarPath)
	t.Cleanup(sc.Close)

	return &Auditor{
		Store: db, Beacon: NewBeacon(""), Sidecar: sc,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rate:    rate,
		Timeout: 30 * time.Second,
	}, db
}

// seed records a witnessed head so the auditor has a range to work over.
func seed(t *testing.T, db *store.Store, origin string, size int64) {
	t.Helper()
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: size, Hash: tlog.Hash{}, WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// Audit from a couple of epochs back.
	if err := db.SetAuditProgress(origin, size-3); err != nil {
		t.Fatal(err)
	}
}

// The path that matters most: a proof that fails verification is arithmetic, not
// observation, so it permanently poisons the log.
func TestVerificationFailurePoisonsTheLog(t *testing.T) {
	origin := "meta.test/v1"
	sc := fakeSidecar(t, `{"ok":false,"epoch":%s,"error":"root mismatch","kind":"verify"}`)
	a, db := newTestAuditor(t, sc, 1.0) // sample everything
	seed(t, db, origin, 100)

	err := a.Run(context.Background(), &stubResolver{origin: origin})
	if err == nil {
		t.Fatal("a failed construction audit must surface as an error")
	}

	forks, _ := db.Forks()
	if len(forks) != 1 {
		t.Fatalf("want fork evidence recorded, got %d", len(forks))
	}
	if forked, _ := db.IsForked(origin); !forked {
		t.Fatal("a failed construction audit must poison the log permanently")
	}
}

// A download or decode problem means we could not check — it must never escalate
// into a public accusation.
func TestUnverifiableEpochDoesNotAccuse(t *testing.T) {
	for _, kind := range []string{"fetch", "decode"} {
		t.Run(kind, func(t *testing.T) {
			origin := "meta.test/v1"
			sc := fakeSidecar(t, `{"ok":false,"epoch":%s,"error":"boom","kind":"`+kind+`"}`)
			a, db := newTestAuditor(t, sc, 1.0)
			seed(t, db, origin, 100)

			if err := a.Run(context.Background(), &stubResolver{origin: origin}); err == nil {
				t.Fatal("should report an error")
			}
			if forks, _ := db.Forks(); len(forks) != 0 {
				t.Fatalf("kind %q must not be recorded as a fork, got %d", kind, len(forks))
			}
			if forked, _ := db.IsForked(origin); forked {
				t.Fatalf("kind %q must not poison the log", kind)
			}
		})
	}
}

func TestSuccessfulAuditAdvancesProgress(t *testing.T) {
	origin := "meta.test/v1"
	sc := fakeSidecar(t, `{"ok":true,"epoch":%s,"download_ms":10,"decode_ms":20,"verify_ms":30,"bytes":1048576}`)
	a, db := newTestAuditor(t, sc, 1.0)
	seed(t, db, origin, 100)

	if err := a.Run(context.Background(), &stubResolver{origin: origin}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.AuditProgress(origin)
	if got != 100 {
		t.Fatalf("want progress at 100, got %d", got)
	}

	records, _ := db.Audits(origin, 100)
	if len(records) != 3 {
		t.Fatalf("want 3 audit records, got %d", len(records))
	}
	for _, r := range records {
		if !r.Verified {
			t.Errorf("epoch %d should be verified", r.Epoch)
		}
		// Beacon evidence must be retained or the sample is not checkable.
		if r.BeaconRound == 0 || r.BeaconRandom == "" || r.BeaconSig == "" {
			t.Errorf("epoch %d missing beacon evidence: %+v", r.Epoch, r)
		}
	}
}

// Declined epochs must still be recorded, or a published coverage rate cannot be
// checked by anyone.
func TestDeclinedEpochsAreRecorded(t *testing.T) {
	origin := "meta.test/v1"
	// Rate 0 means the sidecar is never invoked; point at a path that would
	// fail if it were, so the test also proves we skip the expensive work.
	a, db := newTestAuditor(t, "/nonexistent/sidecar", 0)
	seed(t, db, origin, 100)

	if err := a.Run(context.Background(), &stubResolver{origin: origin}); err != nil {
		t.Fatal(err)
	}
	records, _ := db.Audits(origin, 100)
	if len(records) != 3 {
		t.Fatalf("want 3 recorded decisions even though none were sampled, got %d", len(records))
	}
	for _, r := range records {
		if r.Sampled {
			t.Errorf("epoch %d should not have been sampled at rate 0", r.Epoch)
		}
	}
}

// A poisoned log is not audited further; there is nothing left to establish.
func TestForkedLogIsNotAudited(t *testing.T) {
	origin := "meta.test/v1"
	a, db := newTestAuditor(t, "/nonexistent/sidecar", 1.0)
	seed(t, db, origin, 100)
	if err := db.RecordFork(&store.Fork{Origin: origin, Reason: "earlier", DetectedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if err := a.Run(context.Background(), &stubResolver{origin: origin}); err != nil {
		t.Fatalf("auditing a poisoned log should be a no-op, got %v", err)
	}
}

// An epoch we can never fetch must not stall auditing forever. Retrying without
// bound would mean one dead proof blob silently bricks tier B for that log —
// the same livelock shape fixed in the witness catch-up path.
func TestPermanentlyUnfetchableEpochIsSkippedNotRetriedForever(t *testing.T) {
	origin := "meta.test/v1"
	sc := fakeSidecar(t, `{"ok":false,"epoch":%s,"error":"HTTP 404","kind":"fetch"}`)
	a, db := newTestAuditor(t, sc, 1.0)
	seed(t, db, origin, 100)

	start, _ := db.AuditProgress(origin)

	// Run repeatedly, as the audit loop would. Three epochs are in range and
	// each gets its own attempt budget, so allow for all of them.
	var lastErr error
	for range 3*maxAttempts + 3 {
		lastErr = a.Run(context.Background(), &stubResolver{origin: origin})
	}

	// Progress must have moved past the dead epoch.
	got, _ := db.AuditProgress(origin)
	if got <= start {
		t.Fatalf("auditing stalled: progress stuck at %d", got)
	}
	if lastErr != nil {
		t.Fatalf("once the epoch is abandoned the round should succeed, got %v", lastErr)
	}

	// And the skip must be recorded honestly rather than silently dropped, or
	// the published coverage figure overstates what we checked.
	rec, err := db.GetAudit(origin, start+1)
	if err != nil || rec == nil {
		t.Fatalf("abandoned epoch must still be recorded: %v", err)
	}
	if !rec.Sampled || rec.Verified || rec.Kind != "unavailable" {
		t.Fatalf("want sampled-but-unverified with kind=unavailable, got %+v", rec)
	}
	if rec.Attempts < maxAttempts {
		t.Fatalf("want at least %d attempts recorded, got %d", maxAttempts, rec.Attempts)
	}

	// It must never be mistaken for misbehaviour.
	if forks, _ := db.Forks(); len(forks) != 0 {
		t.Fatal("an unfetchable epoch must never be recorded as a fork")
	}
}
