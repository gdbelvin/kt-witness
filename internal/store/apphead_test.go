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

// The between-snapshot check is only as good as its memory. Held in RAM it
// resets on every deploy, and coverage silently becomes "since the last
// restart" while still reporting success.
func TestLogEntriesSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	var a, b [32]byte
	a[0], b[0] = 1, 2

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutLogEntries("signal.org/kt", map[uint64][32]byte{4: a, 8: b}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopen, as a restart would.
	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	got, err := db2.LogEntries("signal.org/kt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[4] != a || got[8] != b {
		t.Fatalf("entries did not survive a reopen: %v", got)
	}

	// Origins must not bleed into each other.
	if other, err := db2.LogEntries("other.example/log"); err != nil || len(other) != 0 {
		t.Errorf("entries leaked across origins: %v (err %v)", other, err)
	}
}

// The entry set must not grow without bound, and the entries kept must be the
// low-numbered ones: those recur across searches, while the frontier churns.
func TestLogEntriesAreBoundedKeepingLowestIDs(t *testing.T) {
	db := testStore(t)
	entries := make(map[uint64][32]byte, maxLogEntriesPerOrigin+500)
	for i := uint64(0); i < maxLogEntriesPerOrigin+500; i++ {
		var h [32]byte
		h[0] = byte(i)
		entries[i] = h
	}
	if err := db.PutLogEntries("o", entries); err != nil {
		t.Fatal(err)
	}
	got, err := db.LogEntries("o")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxLogEntriesPerOrigin {
		t.Fatalf("kept %d entries, want the cap of %d", len(got), maxLogEntriesPerOrigin)
	}
	if _, ok := got[0]; !ok {
		t.Error("the lowest entry id was evicted; low ids are the ones searches revisit")
	}
	if _, ok := got[maxLogEntriesPerOrigin+499]; ok {
		t.Error("a frontier entry survived past the cap")
	}
}
