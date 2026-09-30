package store

import (
	"path/filepath"
	"testing"
	"time"
)

// A changed list must never re-key a log we already know. The second add
// carries a different key; the stored one must be the first.
func TestAddPushLogIsAddOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	first := &PushLog{
		Origin: "example.com/log", VKey: "example.com/log+00000000+AAAA",
		QPD: 24, Contact: "ops@example.com", List: "https://list.one",
		AddedAt: time.Unix(1000, 0).UTC(),
	}
	added, err := db.AddPushLog(first)
	if err != nil || !added {
		t.Fatalf("first add: added=%v err=%v", added, err)
	}

	second := *first
	second.VKey = "example.com/log+11111111+BBBB"
	second.QPD = 86400
	second.Contact = "attacker@example.net"
	second.List = "https://list.two"
	added, err = db.AddPushLog(&second)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("second add of an existing origin reported added")
	}

	check := func(db *Store) {
		t.Helper()
		logs, err := db.PushLogs()
		if err != nil {
			t.Fatal(err)
		}
		if len(logs) != 1 {
			t.Fatalf("got %d logs, want 1", len(logs))
		}
		got := logs[0]
		if got.VKey != first.VKey || got.QPD != first.QPD || got.Contact != first.Contact ||
			got.List != first.List || !got.AddedAt.Equal(first.AddedAt) {
			t.Fatalf("stored log changed: %+v, want %+v", got, first)
		}
	}
	check(db)

	// And it survives a restart unchanged.
	db.Close()
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	check(db)
}

func TestPushLogsOrderedAndEmptyOriginRejected(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if logs, err := db.PushLogs(); err != nil || len(logs) != 0 {
		t.Fatalf("empty store: %v %v", logs, err)
	}
	for _, o := range []string{"c.example", "a.example", "b.example"} {
		if _, err := db.AddPushLog(&PushLog{Origin: o, VKey: o + "+00000000+AA"}); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := db.PushLogs()
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 || logs[0].Origin != "a.example" || logs[2].Origin != "c.example" {
		t.Fatalf("unexpected order: %v", logs)
	}
	if _, err := db.AddPushLog(&PushLog{}); err == nil {
		t.Fatal("empty origin accepted")
	}
}
