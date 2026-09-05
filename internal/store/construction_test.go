package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Backfill must be able to resume, and must never be told it can resume past a
// gap.
//
// An entry log re-verified its whole tree on every backfill pass because there
// was no way to ask where the audited run ended. For a 172-entry log that was a
// sub-second burst of real work carrying no new information, which a one-minute
// rate window then extrapolated into an apparent ten thousand verifications an
// hour.
func TestConstructionAuditedThrough(t *testing.T) {
	open := func(t *testing.T, name string) *Store {
		t.Helper()
		db, err := Open(filepath.Join(t.TempDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}

	t.Run("nothing audited is distinguishable from index zero audited", func(t *testing.T) {
		db := open(t, "empty.db")
		through, ok, err := db.ConstructionAuditedThrough("example.com/log")
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("reported a run through %d for a log with no audits at all; "+
				"index 0 and 'nothing' must not share a representation", through)
		}
	})

	t.Run("index zero alone is a real run", func(t *testing.T) {
		db := open(t, "zero.db")
		if err := db.RecordConstructionAudit("example.com/log", 0); err != nil {
			t.Fatal(err)
		}
		through, ok, err := db.ConstructionAuditedThrough("example.com/log")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || through != 0 {
			t.Fatalf("through=%d ok=%v; index 0 is a legitimate audited index", through, ok)
		}
	})

	t.Run("a contiguous run resumes at its end", func(t *testing.T) {
		db := open(t, "run.db")
		for i := int64(0); i <= 171; i++ {
			if err := db.RecordConstructionAudit("example.com/log", i); err != nil {
				t.Fatal(err)
			}
		}
		through, ok, err := db.ConstructionAuditedThrough("example.com/log")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || through != 171 {
			t.Fatalf("through=%d ok=%v, want 171 — backfill would re-read the "+
				"whole log every pass", through, ok)
		}
	})

	t.Run("a gap stops the run", func(t *testing.T) {
		db := open(t, "gap.db")
		// 0,1,2 verified; 3 missing; 4,5 verified. Resuming past the gap would
		// silently skip index 3 forever, which is worse than re-reading.
		for _, i := range []int64{0, 1, 2, 4, 5} {
			if err := db.RecordConstructionAudit("example.com/log", i); err != nil {
				t.Fatal(err)
			}
		}
		through, ok, err := db.ConstructionAuditedThrough("example.com/log")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || through != 2 {
			t.Fatalf("through=%d ok=%v, want 2 — the run ends at the gap, and "+
				"reporting 5 would skip index 3 forever", through, ok)
		}
	})

	t.Run("an unverified record does not extend the run", func(t *testing.T) {
		db := open(t, "unverified.db")
		for _, i := range []int64{0, 1} {
			if err := db.RecordConstructionAudit("example.com/log", i); err != nil {
				t.Fatal(err)
			}
		}
		// Settled but NOT verified: a decision exists, the check did not happen.
		if err := db.RecordAudit(&Audit{
			Origin: "example.com/log", Epoch: 2, Sampled: true, Rate: 1,
			Verified: false, Attempts: 3, DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		through, ok, err := db.ConstructionAuditedThrough("example.com/log")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || through != 1 {
			t.Fatalf("through=%d ok=%v, want 1 — a settled-but-unverified index "+
				"is a hole, not coverage", through, ok)
		}
	})
}
