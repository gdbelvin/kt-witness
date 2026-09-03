//go:build unix

package proton

import (
	"os"
	"path/filepath"
	"testing"
)

// A truncated download must never be mistaken for a retained tree. It would
// rebuild to a wrong root and read as Proton having misbehaved, which is the
// worst possible way for a disk error to present itself.
func TestBaseIgnoresTruncatedTrees(t *testing.T) {
	dir := t.TempDir()
	a := &IncrementalAuditor{Dir: dir}

	// A whole number of 68-byte leaves: usable.
	good := filepath.Join(dir, "epoch_tree_100.bin")
	if err := os.WriteFile(good, make([]byte, protonRecordLength*3), 0o644); err != nil {
		t.Fatal(err)
	}
	// A partial leaf: a truncated download, and a higher epoch, so a naive
	// "highest wins" would pick it.
	bad := filepath.Join(dir, "epoch_tree_200.bin")
	if err := os.WriteFile(bad, make([]byte, protonRecordLength*2+7), 0o644); err != nil {
		t.Fatal(err)
	}
	// An in-progress download must not be picked up either.
	if err := os.WriteFile(filepath.Join(dir, "epoch_tree_300.bin.partial"),
		make([]byte, protonRecordLength), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := a.Base()
	if err != nil {
		t.Fatal(err)
	}
	if got != 100 {
		t.Fatalf("Base() = %d, want 100 — a truncated or partial file was accepted "+
			"as a tree", got)
	}
}

func TestBaseIsZeroWhenNothingRetained(t *testing.T) {
	a := &IncrementalAuditor{Dir: filepath.Join(t.TempDir(), "absent")}
	got, err := a.Base()
	if err != nil || got != 0 {
		t.Fatalf("an empty corpus should report no base, got %d / %v", got, err)
	}
}

// Filling the volume would stop the witness, and a witness that is not running
// is worse than an unaudited epoch. The floor must refuse rather than warn.
func TestAuditRefusesBelowTheFreeSpaceFloor(t *testing.T) {
	dir := t.TempDir()
	a := &IncrementalAuditor{
		Dir: dir,
		// Larger than any plausible free space, so the floor always trips.
		MinFreeBytes: 1 << 62,
	}
	if err := os.WriteFile(a.treePath(1), make([]byte, protonRecordLength), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := a.Step(nil, 1, 2, &EpochMeta{})
	if err == nil {
		t.Fatal("an audit started below the free-space floor")
	}
	if got := err.Error(); !contains(got, "floor") {
		t.Errorf("the error should name the floor, got: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
