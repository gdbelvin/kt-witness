package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestRetractFork covers the reversal path that the go.sum false positive
// forced into existence: an accusation must be withdrawable, and the withdrawal
// must be as auditable as the accusation.
func TestRetractFork(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const origin = "go.sum database tree"

	if err := s.RecordFork(&Fork{
		Origin: origin, Reason: "size went backwards", DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if forked, _ := s.IsForked(origin); !forked {
		t.Fatal("log should be poisoned")
	}

	// A reason is mandatory: a silent retraction is how an accusation gets
	// quietly disappeared.
	if err := s.RetractFork(origin, ""); err == nil {
		t.Fatal("retraction without a reason must be refused")
	}

	if err := s.RetractFork(origin, "stale replica, not equivocation"); err != nil {
		t.Fatalf("retract: %v", err)
	}
	if forked, _ := s.IsForked(origin); forked {
		t.Fatal("log should no longer be poisoned")
	}

	// The original evidence survives — what is withdrawn is the accusation, not
	// the record that it was made.
	forks, err := s.Forks()
	if err != nil || len(forks) != 1 {
		t.Fatalf("original fork evidence was destroyed: %+v (err %v)", forks, err)
	}
	rs, err := s.Retractions()
	if err != nil || len(rs) != 1 {
		t.Fatalf("retraction not recorded: %+v (err %v)", rs, err)
	}
	if rs[0].Reason == "" || rs[0].Fork == nil || rs[0].Fork.Reason != "size went backwards" {
		t.Fatalf("retraction does not carry the withdrawn finding: %+v", rs[0])
	}

	// Retracting something that is not forked is an error, not a silent no-op.
	if err := s.RetractFork("other/log", "because"); err == nil {
		t.Fatal("retracting an un-forked log must be refused")
	}
}
