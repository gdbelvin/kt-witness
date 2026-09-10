package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubKeeper stands in for a sidecar that was asked to retain its download.
type stubKeeper struct {
	kept string // what it will report having left on disk
	got  string // what it was handed
}

func (s *stubKeeper) Verify(ctx context.Context, dir string, epoch int64, prev, curr string, to time.Duration) (*Result, error) {
	return s.VerifyCached(ctx, dir, epoch, prev, curr, "", to)
}

func (s *stubKeeper) VerifyCached(ctx context.Context, dir string, epoch int64, prev, curr, proofPath string, to time.Duration) (*Result, error) {
	s.got = proofPath
	return &Result{Epoch: epoch, OK: true, ProofPath: s.kept}, nil
}

func (s *stubKeeper) Close() {}

// TestReaperDeletesWhatTheSidecarWasAskedToKeep pins the leak that filled a
// 12 GB tmpfs in about forty epochs.
//
// KeepProofs is on because the canary needs the bytes that just verified. The
// shadow used to delete them and was switched off, so nothing did — and the
// symptom was "unverifiable (fetch): No space left on device", which names
// neither a file nor a filesystem nor a retained proof.
func TestReaperDeletesWhatTheSidecarWasAskedToKeep(t *testing.T) {
	dir := t.TempDir()
	kept := filepath.Join(dir, "retained.bin")
	if err := os.WriteFile(kept, []byte("a proof"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Reaper{Primary: &stubKeeper{kept: kept}}
	res, err := r.VerifyCached(context.Background(), "d", 1, "p", "c", "", time.Minute)
	if err != nil || res == nil || !res.OK {
		t.Fatalf("verification did not pass through: res=%v err=%v", res, err)
	}
	if _, err := os.Stat(kept); !os.IsNotExist(err) {
		t.Errorf("the retained proof is still there: %v", err)
	}
}

// TestReaperLeavesTheCallersOwnProofAlone. A proof handed IN belongs to
// whoever cached it — the prefetch cache holds 55 GB of them on purpose — and
// deleting one would throw away a download somebody is keeping deliberately.
func TestReaperLeavesTheCallersOwnProofAlone(t *testing.T) {
	dir := t.TempDir()
	cached := filepath.Join(dir, "cached.bin")
	if err := os.WriteFile(cached, []byte("a cached proof"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The sidecar reports back the same path it was given, which is what it
	// does when it reads a cached proof rather than downloading one.
	r := &Reaper{Primary: &stubKeeper{kept: cached}}
	if _, err := r.VerifyCached(context.Background(), "d", 1, "p", "c", cached, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("the caller's cached proof was deleted: %v", err)
	}
}

// TestReaperSurvivesAProofThatIsAlreadyGone: a missing file is the normal
// outcome when something upstream cleaned up, and must not be reported as a
// problem — a warning per epoch is how a real one gets missed.
func TestReaperSurvivesAProofThatIsAlreadyGone(t *testing.T) {
	r := &Reaper{Primary: &stubKeeper{kept: filepath.Join(t.TempDir(), "never-existed.bin")}}
	if _, err := r.VerifyCached(context.Background(), "d", 1, "p", "c", "", time.Minute); err != nil {
		t.Errorf("a missing retained proof was treated as an error: %v", err)
	}
}
