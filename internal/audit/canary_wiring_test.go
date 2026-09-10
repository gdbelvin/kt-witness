package audit

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// countingVerifier records that it was asked, and hands back the bytes it was
// given when told to keep them — the way GoVerifier does.
type countingVerifier struct {
	name  string
	calls int
	keep  bool
	proof []byte
}

func (v *countingVerifier) Verify(ctx context.Context, dir string, epoch int64, prev, curr string, to time.Duration) (*Result, error) {
	return v.VerifyCached(ctx, dir, epoch, prev, curr, "", to)
}

func (v *countingVerifier) VerifyCached(ctx context.Context, dir string, epoch int64, prev, curr, path string, to time.Duration) (*Result, error) {
	v.calls++
	res := &Result{Epoch: epoch, OK: true}
	if v.keep {
		res.Proof = v.proof
	}
	return res, nil
}

func (v *countingVerifier) KeepProofs() { v.keep = true }
func (v *countingVerifier) Close()      {}

// VerifyBytes makes this a bytesVerifier, so the canary hands it a slice rather
// than writing a file. It rejects everything, which is what a working verifier
// does with a corrupted proof.
func (v *countingVerifier) VerifyBytes(ctx context.Context, epoch int64, prev, curr string, proof []byte) (*Result, error) {
	v.calls++
	return &Result{Epoch: epoch, OK: false, Kind: "verify"}, nil
}

// TestTheCanaryTestsTheVerifierThatDecides is the property that was broken in
// production for as long as canaries have been on.
//
// The witness built the Go verifier, logged "verifying in-process", and then
// the canary block replaced the hot path with Canary{Primary: pool} — the Rust
// sidecar. Every epoch went through the reference; the Go verifier was reached
// only from inside the canary. Nothing failed, so nothing said so: the timings
// were four times slower and the errno mentioned a file, and that was the whole
// of the evidence.
//
// A canary whose Primary is not the verifier in the hot path is testing
// something the witness does not use, which is worse than not testing at all.
func TestTheCanaryTestsTheVerifierThatDecides(t *testing.T) {
	hot := &countingVerifier{name: "hot", proof: []byte("a proof that verified")}
	c := &Canary{Primary: hot, Every: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// The canary asks its Primary to hand back what it verified.
	if k, ok := c.Primary.(interface{ KeepProofs() }); ok {
		k.KeepProofs()
	}

	res, err := c.VerifyCached(context.Background(), "d", 7, "p", "cu", "", time.Minute)
	if err != nil || res == nil || !res.OK {
		t.Fatalf("the real verification did not pass through: %v %v", res, err)
	}
	// Twice: once for the epoch, once for the corrupted copy. One call means
	// the canary did not run.
	if hot.calls != 2 {
		t.Errorf("the hot-path verifier was asked %d times; want 2 — the epoch and "+
			"then the corrupted copy of it", hot.calls)
	}
}

// TestACanaryWithNothingToCorruptSaysSo. A canary that silently stops firing is
// indistinguishable from one that keeps passing, and this is the one check in
// the system that cannot be satisfied by doing nothing — so it has to complain
// when it is doing nothing.
func TestACanaryWithNothingToCorruptSaysSo(t *testing.T) {
	silent := &countingVerifier{name: "silent"} // never keeps, so no bytes
	c := &Canary{Primary: silent, Every: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if _, err := c.VerifyCached(context.Background(), "d", 7, "p", "cu", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	if silent.calls != 1 {
		t.Errorf("verifier called %d times; with no proof to corrupt only the epoch "+
			"itself should have been verified", silent.calls)
	}
}

// TestTheCanaryNeedsNoFilesystem. The temp file existed only because the
// reference implementation is a separate process reached through a pipe, and
// writing a 284 MB corrupted copy is what filled the witness's scratch space.
// An in-process verifier is handed the bytes.
func TestTheCanaryNeedsNoFilesystem(t *testing.T) {
	before, _ := countTempFiles(t)
	hot := &countingVerifier{proof: make([]byte, 1<<20)}
	hot.KeepProofs()
	c := &Canary{Primary: hot, Every: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for i := 0; i < 5; i++ {
		if _, err := c.VerifyCached(context.Background(), "d", int64(i), "p", "cu", "", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := countTempFiles(t)
	if after > before {
		t.Errorf("the canary left %d temp files behind; an in-process verifier "+
			"takes the bytes directly", after-before)
	}
}

// countTempFiles counts kt-canary temp files, so the test above measures the
// thing it names rather than the whole of /tmp.
func countTempFiles(t *testing.T) (int, error) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "kt-canary-*.bin"))
	if err != nil {
		return 0, err
	}
	return len(matches), nil
}
