package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestHistoryRemembersWhatHasAgedOut pins the watermark.
//
// Proton retains about ninety days and its floor advances a few epochs a day.
// Each backfill records the window as it stands, and the record is overwritten
// — so without this, the witness reports a window that silently slides forward
// and never says that anything left it. What left it is the part that matters:
// an epoch whose diff is no longer served cannot be reconstructed by any third
// party again.
func TestHistoryRemembersWhatHasAgedOut(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	first := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := db.RecordHistory(&History{Origin: "p/kt", From: 6000, To: 6500,
		Epochs: 501, VerifiedAt: first}); err != nil {
		t.Fatal(err)
	}
	// Ninety days later the floor has moved and the tip has advanced.
	if err := db.RecordHistory(&History{Origin: "p/kt", From: 6236, To: 6736,
		Epochs: 501, VerifiedAt: first.Add(90 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	hs, err := db.Histories()
	if err != nil {
		t.Fatal(err)
	}
	var h *History
	for _, x := range hs {
		if x.Origin == "p/kt" {
			h = x
		}
	}
	if h == nil {
		t.Fatal("no history recorded")
	}
	if h.EverFrom != 6000 {
		t.Errorf("EverFrom = %d, want 6000 — the earliest epoch we ever saw published", h.EverFrom)
	}
	if got := h.Expired(); got != 236 {
		t.Errorf("Expired() = %d, want 236", got)
	}
	if !h.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen = %v, want the first observation %v", h.FirstSeen, first)
	}

	// A window that has not moved has lost nothing.
	if err := db.RecordHistory(&History{Origin: "m/kt", From: 1, To: 500,
		Epochs: 500, VerifiedAt: first}); err != nil {
		t.Fatal(err)
	}
	hs, _ = db.Histories()
	for _, x := range hs {
		if x.Origin == "m/kt" && x.Expired() != 0 {
			t.Errorf("a stable window reported %d expired epochs", x.Expired())
		}
	}
}
