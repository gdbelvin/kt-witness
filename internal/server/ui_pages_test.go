package server

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

func testStoreWithLog(t *testing.T, origin string) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var h tlog.Hash
	h[0] = 7
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: 42, Hash: h,
		Cosigned: []byte(origin + "\n42\nAAAA=\n"), WitnessedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

// The per-log page must render for a log we hold, and 404 for one we do not —
// rather than showing an empty shell that looks like a log with no activity.
func TestLogPageRendersAndRejectsUnknown(t *testing.T) {
	const origin = "example.com/log"
	db := testStoreWithLog(t, origin)
	s := &Server{Store: db, VKey: "witness+00000000+AAAA"}

	rec := httptest.NewRecorder()
	s.logPage(rec, httptest.NewRequest("GET", "/log?origin="+origin, nil))
	if rec.Code != 200 {
		t.Fatalf("status %d for a known log", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, origin) {
		t.Fatalf("page does not name the log:\n%s", body[:min(400, len(body))])
	}

	rec = httptest.NewRecorder()
	s.logPage(rec, httptest.NewRequest("GET", "/log?origin=not.a.log", nil))
	if rec.Code != 404 {
		t.Fatalf("status %d for an unknown log, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.logPage(rec, httptest.NewRequest("GET", "/log", nil))
	if rec.Code != 400 {
		t.Fatalf("status %d with no origin, want 400", rec.Code)
	}
}

// The gossip page must say what cannot be detected, not only what was compared.
// A reader seeing "2 peers polled" and nothing else would reasonably conclude
// split views are covered. They are not.
func TestGossipPageStatesItsLimits(t *testing.T) {
	db := testStoreWithLog(t, "example.com/log")
	s := &Server{Store: db, VKey: "witness+00000000+AAAA"}

	rec := httptest.NewRecorder()
	s.gossip(rec, httptest.NewRequest("GET", "/gossip", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"agree by construction", // why our own fetch cannot detect a fork
		"signed peer views",     // what is missing
		"nobody but that user",  // the attack no auditor can catch
	} {
		if !strings.Contains(body, want) {
			t.Errorf("gossip page omits %q", want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
