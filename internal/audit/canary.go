package audit

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Canary corrupts a proof and requires the verifier to reject it.
//
// # Why agreement is not evidence
//
// The shadow compares two verifiers on real proofs and counts how often they
// agree. That measures almost nothing about correctness: every proof a log
// publishes is valid, so a verifier that returned "valid" unconditionally would
// agree with the reference on every epoch forever and accumulate a spotless
// record. The same is true of a worker that reports the operator's published
// root without doing any work — the root is public, so its answer is right for
// the wrong reason and no amount of agreement will show it.
//
// The only test that distinguishes a verifier from a rubber stamp is giving it
// something it must refuse. So: flip one bit, anywhere in the proof bytes, and
// require rejection. One bit rather than a mangled file, because a verifier
// that checks structure but not every hash will catch the mangled one and pass
// the forgery that matters.
//
// # What a failure means
//
// A canary that is accepted is not a slow verifier or a flaky network. It means
// the thing this witness exists to do is not being done, and every verdict that
// verifier has produced is worth nothing. There is no proportionate response
// short of shouting, so this logs at ERROR with the specifics needed to
// reproduce it, and counts it in a metric that should never leave zero.
type Canary struct {
	Primary Verifier
	Log     *slog.Logger

	// Every is the sampling interval: 100 tests one epoch in a hundred. Zero
	// means the default.
	//
	// A rate rather than every epoch because a canary costs a whole extra
	// verification — the expensive resource on this machine — and detection at
	// 1% is a question of how long a broken verifier survives, not whether it
	// is caught. At the rate this fleet works, one in a hundred is a few
	// minutes.
	Every int

	// OnProof, if set, is handed a proof that has just verified, so something
	// else can build a canary from it. Called at the same cadence as the
	// in-process canary and given the file before it is deleted.
	//
	// Bytes that have already been checked, deliberately: a canary built from a
	// proof we have not verified ourselves could fail for a reason unrelated to
	// the bit that was flipped, and a canary that might legitimately fail
	// proves nothing when it does.
	OnProof func(logDirectory string, epoch int64, prevRoot, currRoot, proofPath string)

	mu        sync.Mutex
	seen      int
	quietOnce sync.Once
}

const defaultCanaryEvery = 100

// bytesVerifier is a verifier that can be handed a proof directly, rather than
// a path to read it from. Everything in this process can; only the sidecar
// cannot, and that is the whole reason the scratch filesystem existed.
type bytesVerifier interface {
	VerifyBytes(ctx context.Context, epoch int64, prevRoot, currRoot string, proof []byte) (*Result, error)
}

func (c *Canary) Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return c.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

func (c *Canary) VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	res, err := c.Primary.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, proofPath, timeout)
	if err != nil || res == nil || !res.OK {
		// Only a proof that just verified is worth corrupting: if it did not
		// verify, requiring the corrupted version to fail proves nothing.
		return res, err
	}

	if !c.due() {
		return res, err
	}

	// The bytes, from wherever the verifier left them.
	//
	// In memory is the ordinary case now: an in-process verifier already has
	// the proof and hands it straight over. A path is the sidecar's way of
	// saying the same thing, and it is what required a scratch filesystem, a
	// retention flag, and something to delete the file afterwards — three
	// things that only existed because a verdict had to cross a pipe.
	var data []byte
	src := proofPath
	if src == "" {
		src = res.ProofPath
	}
	switch {
	case len(res.Proof) > 0:
		data = res.Proof
	case src != "":
		b, rErr := os.ReadFile(src)
		if rErr != nil {
			if c.Log != nil {
				c.Log.Warn("canary could not be run; no conclusion either way",
					"epoch", epoch, "err", rErr)
			}
			metrics.Inc("kt_witness_canary_error_total", nil)
			return res, err
		}
		data = b
	default:
		// Nothing to corrupt. Said out loud rather than skipped silently: a
		// canary that stops firing looks exactly like a canary that keeps
		// passing, and the whole point of this is to be the one check that
		// cannot be satisfied by doing nothing.
		c.quiet(epoch)
		return res, err
	}

	if c.OnProof != nil && src != "" {
		c.OnProof(logDirectory, epoch, prevRoot, currRoot, src)
	}
	if cErr := c.run(ctx, logDirectory, epoch, prevRoot, currRoot, data, timeout); cErr != nil && c.Log != nil {
		c.Log.Warn("canary could not be run; no conclusion either way", "epoch", epoch, "err", cErr)
		metrics.Inc("kt_witness_canary_error_total", nil)
	}
	return res, err
}

// quiet reports a canary that had nothing to work with, once, loudly enough to
// be noticed and not so often as to be filtered out.
func (c *Canary) quiet(epoch int64) {
	metrics.Inc("kt_witness_canary_no_proof_total", nil)
	c.quietOnce.Do(func() {
		if c.Log != nil {
			c.Log.Error("THE CANARY HAS NOTHING TO CORRUPT and is therefore not testing "+
				"anything. The verifier in the hot path is not handing back the proof it "+
				"verified — call KeepProofs on it — and until it does, a verifier that "+
				"accepted everything would look exactly like this one",
				"epoch", epoch)
		}
	})
}

func (c *Canary) due() bool {
	every := c.Every
	if every <= 0 {
		every = defaultCanaryEvery
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen++
	return c.seen%every == 0
}

// run flips one bit of a proof that just verified and requires both verifiers
// to reject it.
func (c *Canary) run(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, proof []byte, timeout time.Duration) error {
	if len(proof) == 0 {
		return fmt.Errorf("proof is empty")
	}
	// A copy, because the corruption is destructive and these bytes may be the
	// verifier's own buffer.
	data := make([]byte, len(proof))
	copy(data, proof)

	// Anywhere in the file, uniformly. Not a chosen field: the point is to
	// catch a verifier that checks the parts somebody thought to test.
	byteAt, err := rand.Int(rand.Reader, big.NewInt(int64(len(data))))
	if err != nil {
		return err
	}
	bitAt, err := rand.Int(rand.Reader, big.NewInt(8))
	if err != nil {
		return err
	}
	i := byteAt.Int64()
	mask := byte(1) << uint(bitAt.Int64())
	data[i] ^= mask

	where := fmt.Sprintf("byte %d of %d, bit %d", i, len(data), bitAt.Int64())

	// The verifier in the hot path, on the corrupted bytes. A decode failure
	// counts as a rejection: a proof that cannot be parsed has not been
	// accepted, which is the property under test.
	//
	// A temp file only if the verifier cannot be handed bytes. That is the
	// sidecar, which takes a path because a verdict has to cross a pipe — and
	// writing a 284 MB corrupted copy is what filled the witness's scratch
	// filesystem. An in-process verifier gets the slice.
	var ref *Result
	var refErr error
	if bv, ok := c.Primary.(bytesVerifier); ok {
		ref, refErr = bv.VerifyBytes(ctx, epoch, prevRoot, currRoot, data)
	} else {
		tmp, tErr := os.CreateTemp("", "kt-canary-*.bin")
		if tErr != nil {
			return tErr
		}
		defer os.Remove(tmp.Name())
		if _, wErr := tmp.Write(data); wErr != nil {
			tmp.Close()
			return wErr
		}
		if cErr := tmp.Close(); cErr != nil {
			return cErr
		}
		ref, refErr = c.Primary.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, tmp.Name(), timeout)
	}
	refAccepted := refErr == nil && ref != nil && ref.OK

	// The Go verifier, on the same bytes.
	goAccepted := false
	goRan := false
	if inserted, unchanged, dErr := akdtree.Decode(data); dErr == nil {
		if prev, e1 := akdtree.ParseDigest(prevRoot); e1 == nil {
			if curr, e2 := akdtree.ParseDigest(currRoot); e2 == nil {
				var v akdtree.Verifier
				if ok, vErr := v.VerifyAppendOnly(unchanged, inserted, prev, curr, uint64(epoch)); vErr == nil {
					goRan, goAccepted = true, ok
				}
			}
		}
	}

	switch {
	case refAccepted || goAccepted:
		metrics.Inc("kt_witness_canary_accepted_total", nil)
		if c.Log != nil {
			c.Log.Error("A VERIFIER ACCEPTED A CORRUPTED PROOF — every verdict it has "+
				"produced is worthless and this witness must not publish coverage based "+
				"on it. Reproduce with the epoch and bit position below",
				"origin_directory", logDirectory, "epoch", epoch,
				"corrupted", where,
				"reference_accepted", refAccepted,
				"go_verifier_accepted", goAccepted,
				"prev_root", prevRoot, "curr_root", currRoot)
		}
	default:
		metrics.Inc("kt_witness_canary_rejected_total", nil)
		if c.Log != nil {
			c.Log.Info("canary rejected as it should be", "epoch", epoch,
				"corrupted", where, "go_verifier_ran", goRan)
		}
	}
	return nil
}

func (c *Canary) Close() { c.Primary.Close() }
