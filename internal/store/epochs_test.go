package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestEpochCommitmentDetectsEquivocation is the check Proton's design assigns an
// external auditor: exactly one (epochID, chainHash, issuanceTime) per epoch.
//
// The re-record case matters as much as the conflict case. The same epoch is
// re-observed on every pass, so if an identical commitment were treated as a
// conflict the witness would accuse Proton of equivocating with itself within
// minutes of starting.
func TestEpochCommitmentDetectsEquivocation(t *testing.T) {
	s := newTestStore(t)
	const origin = "proton.me/kt/v1"

	if err := s.RecordEpochCommitment(origin, 6712, "aabb", 1788298290); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// Idempotent.
	if err := s.RecordEpochCommitment(origin, 6712, "aabb", 1788298290); err != nil {
		t.Fatalf("re-recording an identical commitment must be a no-op: %v", err)
	}
	// A different epoch is fine.
	if err := s.RecordEpochCommitment(origin, 6713, "ccdd", 1788298300); err != nil {
		t.Fatalf("different epoch: %v", err)
	}

	// A different chain hash for the same epoch is the contradiction.
	err := s.RecordEpochCommitment(origin, 6712, "beef", 1788298290)
	var c *EpochConflict
	if !errors.As(err, &c) {
		t.Fatalf("got %v, want *EpochConflict", err)
	}
	if c.Stored.ChainHash != "aabb" || c.Seen.ChainHash != "beef" {
		t.Fatalf("conflict does not carry both commitments: %+v", c)
	}

	// So is a different issuance time for the same chain hash: the SAN binds
	// both, so changing either changes what was committed.
	if err := s.RecordEpochCommitment(origin, 6713, "ccdd", 1788299999); !errors.As(err, &c) {
		t.Fatalf("changed issuance time not caught: %v", err)
	}

	// Origins are independent.
	if err := s.RecordEpochCommitment("other/log", 6712, "beef", 1); err != nil {
		t.Fatalf("another origin must not collide: %v", err)
	}
}

// TestEpochCommitmentsSurviveReopen pins persistence. An in-memory ledger only
// catches an operator that equivocates twice while one process is running; the
// interesting attack shows one commitment now and another after a restart.
func TestEpochCommitmentsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.db")
	const origin = "proton.me/kt/v1"

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.RecordEpochCommitment(origin, 42, "aabb", 100); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	var c *EpochConflict
	if err := s2.RecordEpochCommitment(origin, 42, "beef", 100); !errors.As(err, &c) {
		t.Fatalf("equivocation across a restart was not caught: %v", err)
	}
	got, err := s2.EpochCommitments(origin)
	if err != nil || len(got) != 1 || got[0].ChainHash != "aabb" {
		t.Fatalf("commitments after reopen: %+v (err %v)", got, err)
	}
}
