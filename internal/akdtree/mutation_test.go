package akdtree

import (
	"bytes"
	"math/rand"
	"testing"
)

// The property no valid proof can test: does the verifier notice a change.
//
// Checking against real proofs only ever asks a verifier to say yes. Every
// proof a log publishes is valid, so a verifier that returned true
// unconditionally would pass every such check forever. These tests ask the
// other question, and they are the ones that would catch a verifier that had
// quietly stopped verifying.

// TestMutatedProofsAreRejected runs the acceptance trial in the test suite,
// where it belongs: no network, no fixture, and it runs on every change.
//
// Half the trials are corrupted. A verifier that ignores the proof is right
// about any one of them with probability one half, so passing k corrupted
// trials has probability 2^-k — at the default k this is past the point where
// the number means anything, and it costs under a second because the proofs are
// synthetic and small.
func TestMutatedProofsAreRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const trials = 1000

	corrupted, clean := 0, 0
	for i := 0; i < trials; i++ {
		p := makeSynthProof(rng, 40, 8, 1000+uint64(i))

		if rng.Intn(2) == 0 {
			// One bit, anywhere in the encoding — including the framing, the
			// lengths and the label bytes, not just the values. A verifier that
			// checks the parts somebody thought to test would pass a narrower
			// version of this.
			wire := append([]byte(nil), p.wire...)
			at := rng.Intn(len(wire))
			wire[at] ^= 1 << uint(rng.Intn(8))
			if bytes.Equal(wire, p.wire) {
				continue // vanishingly unlikely, but not a trial either way
			}
			if verifyWire(wire, p.prev, p.curr, p.epoch) {
				t.Fatalf("trial %d: a corrupted proof verified (byte %d of %d)",
					i, at, len(p.wire))
			}
			corrupted++
		} else {
			if !verifyWire(p.wire, p.prev, p.curr, p.epoch) {
				t.Fatalf("trial %d: a valid proof was rejected", i)
			}
			clean++
		}
	}
	t.Logf("%d trials: %d corrupted all rejected, %d valid all accepted (2^-%d against a verifier that ignores the proof)",
		trials, corrupted, clean, corrupted)
	if corrupted < 128 {
		t.Errorf("only %d corrupted trials; below 128 this is not cryptographic confidence", corrupted)
	}
}

// A wrong root must be rejected even when the proof is untouched.
//
// This is the shape of the failure that matters most in production: a worker
// that reports the operator's published root without verifying anything. Its
// answer is right about the root and wrong about everything else, and only a
// check that ties the proof to the root catches it.
func TestAProofDoesNotVerifyAgainstTheWrongRoots(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	p := makeSynthProof(rng, 64, 16, 5)
	other := makeSynthProof(rng, 64, 16, 5)

	if verifyWire(p.wire, other.prev, p.curr, p.epoch) {
		t.Error("verified against somebody else's previous root")
	}
	if verifyWire(p.wire, p.prev, other.curr, p.epoch) {
		t.Error("verified against somebody else's current root")
	}
	if verifyWire(p.wire, p.prev, p.curr, p.epoch+1) {
		t.Error("verified at the wrong epoch; the commitment is not binding")
	}
}

// FuzzMutatedProofIsRejected lets the fuzzer look for the mutation this package
// does not notice.
//
// The fixed trials above sample uniformly; a fuzzer steers, and it will find
// the structurally interesting edits — a length prefix that still parses, a
// field truncated to nothing, a label shortened — that random flips reach only
// by luck.
//
// The invariant: any input that is not byte-identical to the valid proof must
// not verify against its roots. Decode failures count as rejection, which is
// what the property is about.
func FuzzMutatedProofIsRejected(f *testing.F) {
	rng := rand.New(rand.NewSource(3))
	base := makeSynthProof(rng, 24, 6, 77)
	f.Add(base.wire)

	// A couple of shapes beyond the seed, so the corpus does not describe one
	// tree: an empty insert set, and one where everything is new.
	f.Add(makeSynthProof(rng, 24, 0, 77).wire)
	f.Add(makeSynthProof(rng, 0, 24, 77).wire)

	f.Fuzz(func(t *testing.T, wire []byte) {
		if bytes.Equal(wire, base.wire) {
			if !verifyWire(wire, base.prev, base.curr, base.epoch) {
				t.Fatal("the unmodified proof did not verify")
			}
			return
		}
		if verifyWire(wire, base.prev, base.curr, base.epoch) {
			t.Fatalf("a modified proof verified against the original roots (%d bytes vs %d)",
				len(wire), len(base.wire))
		}
	})
}
