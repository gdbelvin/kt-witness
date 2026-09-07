package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

func writeJSONL(t *testing.T, dir string, recs []map[string]any) string {
	t.Helper()
	p := filepath.Join(dir, "backfill.jsonl")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestImportRefusesRecordsThatContradictThemselves is the one that matters.
// Coverage is what this witness publishes, so a file must not be able to raise
// it by asserting "verified" next to two roots that do not match.
func TestImportRefusesRecordsThatContradictThemselves(t *testing.T) {
	db := testStore(t)
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		{"epoch": 10, "verified": true, "root": "aa", "signed_root": "aa", "gpu_agreed": true},
		{"epoch": 11, "verified": true, "root": "bb", "signed_root": "cc", "gpu_agreed": true}, // lie
		{"epoch": 12, "verified": true, "root": "", "signed_root": "", "gpu_agreed": true},     // empty
	})
	st, err := ImportResults(db, "example.org/kt", p, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 1 || st.Rejected != 2 {
		t.Fatalf("imported=%d rejected=%d, want 1 and 2", st.Imported, st.Rejected)
	}
	if a, _ := db.GetAudit("example.org/kt", 11); a != nil {
		t.Error("a self-contradicting record was stored")
	}
	if a, _ := db.GetAudit("example.org/kt", 10); a == nil || !a.Verified {
		t.Error("a consistent record was not stored")
	}
}

func TestImportIsIdempotent(t *testing.T) {
	db := testStore(t)
	p := writeJSONL(t, t.TempDir(), []map[string]any{
		{"epoch": 10, "verified": true, "root": "aa", "signed_root": "aa", "gpu_agreed": true},
		{"epoch": 11, "verified": true, "root": "bb", "signed_root": "bb", "gpu_agreed": true},
	})
	if _, err := ImportResults(db, "example.org/kt", p, quietLog()); err != nil {
		t.Fatal(err)
	}
	// Running again while the far end is still appending must not double-count
	// or churn: this runs on a timer against a file that is still growing.
	st, err := ImportResults(db, "example.org/kt", p, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if st.Imported != 0 || st.Skipped != 2 {
		t.Errorf("second pass imported=%d skipped=%d, want 0 and 2", st.Imported, st.Skipped)
	}
}

// A failed construction audit is recorded as settled-but-unverified, never as a
// verified epoch, and never silently. It must lower coverage, not raise it.
func TestImportRecordsAFailureWithoutVerifying(t *testing.T) {
	db := testStore(t)
	p := writeJSONL(t, t.TempDir(), []map[string]any{
		{"epoch": 10, "verified": false, "root": "aa", "signed_root": "zz", "gpu_agreed": true,
			"note": "CONSTRUCTION AUDIT FAILED"},
	})
	st, err := ImportResults(db, "example.org/kt", p, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if st.Failures != 1 || st.Imported != 1 {
		t.Fatalf("failures=%d imported=%d, want 1 and 1", st.Failures, st.Imported)
	}
	a, err := db.GetAudit("example.org/kt", 10)
	if err != nil || a == nil {
		t.Fatal("failed epoch was not recorded at all")
	}
	if a.Verified {
		t.Error("a failed construction audit was stored as verified")
	}
	settled, verified, err := db.AuditCoverage("example.org/kt", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if settled != 1 || verified != 0 {
		t.Errorf("coverage settled=%d verified=%d, want 1 and 0", settled, verified)
	}
}

// Provenance survives into the published record: a reader of /audits can tell
// this conclusion was reached on other hardware.
func TestImportedRecordsCarryTheirProvenance(t *testing.T) {
	db := testStore(t)
	p := writeJSONL(t, t.TempDir(), []map[string]any{
		{"epoch": 10, "verified": true, "root": "aa", "signed_root": "aa", "gpu_agreed": true},
	})
	if _, err := ImportResults(db, "example.org/kt", p, quietLog()); err != nil {
		t.Fatal(err)
	}
	a, _ := db.GetAudit("example.org/kt", 10)
	if a == nil || a.Strategy != ImportedStrategy {
		t.Errorf("strategy = %q, want %q", a.Strategy, ImportedStrategy)
	}
}
