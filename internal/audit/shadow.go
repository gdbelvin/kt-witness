package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Shadow runs the Go verifier beside the reference and records whether they
// agree. It never changes the answer.
//
// # Why shadow rather than switch
//
// The Go implementation is about eight times cheaper for the same arithmetic,
// which is worth having on a backlog measured in hundreds of thousands of
// epochs. It is also a fresh reimplementation of somebody else's tree math, and
// the two ways it could be wrong are not symmetric with the ways ordinary code
// is wrong: accepting what it should reject approves a forged proof, and
// rejecting what it should accept accuses an operator of a fork — publicly,
// permanently, and on the strength of a bug.
//
// So the reference decides, always. This only watches, counts, and shouts when
// the two disagree. That is the same arrangement the Proton GPU rebuild shipped
// under, and it is what turns "it agreed on the epochs I tried" into an
// operating record long enough to argue from.
//
// # What a disagreement means
//
// Nothing about the log, and everything about this code. The reference is the
// definition of correct here; a disagreement is a bug in the Go verifier until
// proven otherwise, and it is logged at ERROR so it cannot be missed. It does
// not withhold a cosignature, does not mark the epoch unverified, and does not
// produce a finding.
//
// # What it costs
//
// It runs only when the proof is already on disk — the prefetcher's file, which
// the sidecar was given anyway. Without that it would have to download the
// proof a second time, and doubling this witness's bandwidth to check its own
// arithmetic is the wrong trade; those epochs are counted as skipped rather
// than quietly ignored.
type Shadow struct {
	Primary Verifier
	// Second is the other implementation, run on the same bytes and compared.
	//
	// Which one is which is a deployment choice, and the comparison is the same
	// either way: the reference in the hot path with Go watching, or Go in the
	// hot path with the reference watching. What must never happen is both
	// being the same implementation, which would compare a thing to itself and
	// report perfect agreement forever.
	Second Verifier
	Log    *slog.Logger

	// Every, if above 1, shadows only one epoch in Every. The full rate is the
	// right default while the record is being built; a busy operator who wants
	// the CPU back can turn it down without losing the signal entirely.
	Every int

	mu   sync.Mutex
	seen int

	// verifiers holds one scratch buffer per concurrent check. A single shared
	// Verifier behind a mutex would serialise the shadow across the pool's
	// eight workers and make the observer the bottleneck — which is a strange
	// way to find out whether the thing you are observing is fast.
	verifiers sync.Pool
}

func (s *Shadow) Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return s.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

func (s *Shadow) VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	res, err := s.Primary.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, proofPath, timeout)
	// The reference's answer leaves this function untouched, whatever happens
	// below. Everything after this point is observation.
	if err != nil || res == nil {
		return res, err
	}

	// Where to read the same bytes the reference just read.
	//
	// Either the prefetcher's file, which belongs to the prefetcher and must be
	// left alone, or one the sidecar was asked to retain for us — which we then
	// own and must delete, because it is a 284 MB temp file and there are eight
	// of these in flight.
	read := proofPath
	if read == "" && res.ProofPath != "" {
		read = res.ProofPath
		defer func() {
			if rmErr := os.Remove(res.ProofPath); rmErr != nil && s.Log != nil {
				s.Log.Warn("could not remove a retained proof; disk will fill",
					"path", res.ProofPath, "err", rmErr)
			}
		}()
	}
	if read == "" {
		// Say which of the two ways this happened, because they have different
		// fixes and "no proof to read" covered both: a primary that was handed
		// a cached file and then had nothing to retain, versus one that
		// downloaded and did not keep it. Guessing between them from a single
		// counter wasted a round trip.
		reason := "sidecar kept nothing"
		if !res.OK {
			reason = "primary rejected, nothing retained"
		}
		metrics.Inc("kt_witness_shadow_skipped_total", map[string]string{"reason": reason})
		return res, err
	}
	if !res.OK && res.Kind != "verify" {
		// The reference could not reach a verdict — a fetch or decode failure —
		// so there is nothing to agree or disagree with.
		metrics.Inc("kt_witness_shadow_skipped_total", map[string]string{"reason": "no verdict"})
		return res, err
	}
	if s.Every > 1 {
		s.mu.Lock()
		s.seen++
		skip := s.seen%s.Every != 0
		s.mu.Unlock()
		if skip {
			metrics.Inc("kt_witness_shadow_skipped_total", map[string]string{"reason": "sampled out"})
			return res, err
		}
	}

	start := time.Now()
	var agreed bool
	var shadowErr error
	if s.Second != nil {
		agreed, shadowErr = s.checkWith(ctx, s.Second, logDirectory, epoch, prevRoot, currRoot, read, timeout, res.OK)
	} else {
		agreed, shadowErr = s.check(read, epoch, prevRoot, currRoot, res.OK)
	}
	took := time.Since(start)

	switch {
	case shadowErr != nil:
		metrics.Inc("kt_witness_shadow_error_total", nil)
		if s.Log != nil {
			s.Log.Warn("shadow verifier could not reach a verdict; the reference's answer stands",
				"epoch", epoch, "err", shadowErr)
		}
	case agreed:
		metrics.Inc("kt_witness_shadow_agree_total", nil)
		metrics.Add("kt_witness_shadow_seconds_sum", nil, took.Seconds())
	default:
		metrics.Inc("kt_witness_shadow_disagree_total", nil)
		if s.Log != nil {
			// Loud, because a silent disagreement is a bug accumulating a
			// record it has not earned.
			s.Log.Error("SHADOW VERIFIER DISAGREES WITH THE REFERENCE — this is a bug in "+
				"internal/akdtree until proven otherwise. The reference's answer was used and "+
				"nothing about the log is being claimed",
				"origin_directory", logDirectory, "epoch", epoch,
				"reference_verified", res.OK, "shadow_verified", !res.OK,
				"proof", read)
		}
	}
	return res, err
}

// check runs the Go verifier on a proof already on disk and reports whether it
// reached the same verdict as the reference.
func (s *Shadow) check(proofPath string, epoch int64, prevRoot, currRoot string, referenceOK bool) (bool, error) {
	data, err := os.ReadFile(proofPath)
	if err != nil {
		return false, err
	}
	inserted, unchanged, err := akdtree.Decode(data)
	if err != nil {
		return false, err
	}
	prev, err := akdtree.ParseDigest(prevRoot)
	if err != nil {
		return false, err
	}
	curr, err := akdtree.ParseDigest(currRoot)
	if err != nil {
		return false, err
	}

	v, _ := s.verifiers.Get().(*akdtree.Verifier)
	if v == nil {
		v = &akdtree.Verifier{}
	}
	defer s.verifiers.Put(v)

	ok, err := v.VerifyAppendOnly(unchanged, inserted, prev, curr, uint64(epoch))
	if err != nil {
		return false, err
	}
	return ok == referenceOK, nil
}

// checkWith runs the other implementation over a proof already on disk.
func (s *Shadow) checkWith(ctx context.Context, second Verifier, logDirectory string,
	epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration, primaryOK bool) (bool, error) {
	res, err := second.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, proofPath, timeout)
	if err != nil {
		return false, err
	}
	if res == nil {
		return false, errNoResult
	}
	if !res.OK && res.Kind == "fetch" {
		// The second opinion could not be reached. That is not a disagreement.
		return false, errNoResult
	}
	return res.OK == primaryOK, nil
}

var errNoResult = errors.New("the second verifier reached no verdict")

func (s *Shadow) Close() { s.Primary.Close() }
