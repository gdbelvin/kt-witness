package audit

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Reaper deletes the proofs the sidecar was asked to retain.
//
// # Why this is its own thing
//
// Pool.KeepProofs makes every verification leave its ~295 MB download on disk,
// and its doc comment says "the caller becomes responsible for deleting them".
// For a while the caller was Shadow, which read the retained bytes and removed
// the file when it was done. Then the shadow was switched off, and with it went
// the only deleter — while KeepProofs stayed on, because something else still
// wanted those bytes.
//
// The witness then filled a 12 GB tmpfs in about forty epochs and reported
//
//	unverifiable (fetch): No space left on device (os error 28)
//
// on a host with 568 GB free, five times per epoch, until each was recorded
// permanently unverified and skipped. Nothing in that names a file, a
// filesystem, or a retained proof.
//
// So ownership is explicit and it is a layer of its own, installed OUTSIDE
// every wrapper that wants to read the bytes. Putting the delete inside one of
// them makes correctness depend on which happens to be outermost, which is
// exactly the coupling that broke this the first time: the shadow's deletion
// was correct right up until something unrelated was turned off.
type Reaper struct {
	Primary Verifier
	Log     *slog.Logger
}

func (r *Reaper) Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return r.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

func (r *Reaper) VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	res, err := r.Primary.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, proofPath, timeout)
	// A proof handed IN belongs to the caller — the prefetch cache owns those,
	// and deleting one would throw away a download somebody is keeping on
	// purpose. Only what the sidecar was asked to retain is ours.
	if res != nil && res.ProofPath != "" && res.ProofPath != proofPath {
		if rmErr := os.Remove(res.ProofPath); rmErr != nil && !os.IsNotExist(rmErr) && r.Log != nil {
			r.Log.Warn("could not delete a retained proof; scratch space will fill",
				"path", res.ProofPath, "err", rmErr)
		}
	}
	return res, err
}

func (r *Reaper) Close() { r.Primary.Close() }
