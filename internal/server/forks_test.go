package server

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// TestForksPageShowsRetraction: an accusation and its withdrawal must travel
// together.
//
// Anyone reading /forks is reading it to learn whether a log misbehaved.
// Showing the claim without the retraction leaves them believing something the
// witness no longer asserts — which, for the real case this covers, meant a
// page accusing the Go checksum database of forking after we had established
// it had not.
func TestForksPageShowsRetraction(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "go.sum database tree"
	if err := db.RecordFork(&store.Fork{
		Origin: origin, Reason: "size went backwards", DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{Store: db}

	// Before retraction the finding stands.
	rec := httptest.NewRecorder()
	s.forks(rec, httptest.NewRequest("GET", "/forks", nil))
	if body := rec.Body.String(); strings.Contains(body, "WITHDRAWN") {
		t.Fatalf("a standing finding was shown as withdrawn:\n%s", body)
	}

	if err := db.RetractFork(origin, "stale replica, not equivocation"); err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	s.forks(rec, httptest.NewRequest("GET", "/forks", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "WITHDRAWN") {
		t.Fatalf("retracted finding not marked withdrawn:\n%s", body)
	}
	if !strings.Contains(body, "stale replica, not equivocation") {
		t.Fatalf("retraction reason missing:\n%s", body)
	}
	if !strings.Contains(body, "NOT an accusation") {
		t.Fatalf("page does not say plainly that this is not an accusation:\n%s", body)
	}
	// The evidence must survive: a reversal that erases the record is not
	// auditable.
	if !strings.Contains(body, "size went backwards") {
		t.Fatalf("original evidence was dropped:\n%s", body)
	}
}
