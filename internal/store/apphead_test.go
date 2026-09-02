package store

import (
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// A contradiction must be reported once, not on every scan for the life of the
// record. Re-reporting trains an operator to ignore the one log line that is
// supposed to demand attention — and on this project's first deployment it
// produced 56 ERROR lines in eight minutes from a handful of stale entries.
func TestObserveAppHeadReportsEachConflictOnce(t *testing.T) {
	db := testStore(t)
	now := time.Now()

	if _, fresh, err := db.ObserveAppHead(now, &AppHead{
		Origin: "o", TreeID: 1, LogSize: 100, Revision: 10, RootHash: "aa",
	}); err != nil || len(fresh) != 0 {
		t.Fatalf("first observation: fresh=%v err=%v", fresh, err)
	}

	// A smaller log size is a contradiction, and must be reported.
	_, fresh, err := db.ObserveAppHead(now, &AppHead{
		Origin: "o", TreeID: 1, LogSize: 90, Revision: 9, RootHash: "bb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 {
		t.Fatalf("expected the contradiction to be reported once, got %d", len(fresh))
	}

	// The identical contradiction again must NOT be reported again.
	_, fresh, err = db.ObserveAppHead(now, &AppHead{
		Origin: "o", TreeID: 1, LogSize: 90, Revision: 9, RootHash: "bb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 0 {
		t.Errorf("a repeat of a known contradiction was reported again: %v", fresh)
	}
}

// The conflict list must not grow without bound: it is persisted and published.
func TestAppHeadConflictsAreBounded(t *testing.T) {
	db := testStore(t)
	now := time.Now()
	if _, _, err := db.ObserveAppHead(now, &AppHead{
		Origin: "o", TreeID: 1, LogSize: 1_000_000, Revision: 1, RootHash: "aa",
	}); err != nil {
		t.Fatal(err)
	}
	// Each distinct smaller size is a distinct contradiction.
	for i := 0; i < maxAppHeadConflicts*3; i++ {
		if _, _, err := db.ObserveAppHead(now, &AppHead{
			Origin: "o", TreeID: 1, LogSize: uint64(1000 + i), Revision: 1, RootHash: "aa",
		}); err != nil {
			t.Fatal(err)
		}
	}
	heads, err := db.AppHeads()
	if err != nil {
		t.Fatal(err)
	}
	if len(heads) != 1 {
		t.Fatalf("expected one head, got %d", len(heads))
	}
	if n := len(heads[0].Conflicts); n > maxAppHeadConflicts {
		t.Errorf("conflicts grew to %d, past the %d cap", n, maxAppHeadConflicts)
	}
}
