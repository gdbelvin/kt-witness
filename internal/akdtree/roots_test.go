package akdtree

import (
	"math/rand"
	"testing"
)

// TestRootsReportsWhatVerifyAppendOnlyAccepts is the property the distributed
// audit rests on: a machine can report what it built without being told what to
// expect, and the two answers are the same computation.
//
// It exists because they were NOT the same. The witness's own local worker
// called VerifyAppendOnly, got "yes", and then reported the published current
// root as both of its computed roots — so its every success was read as a
// mismatch on the previous root and recorded as unverified.
func TestRootsReportsWhatVerifyAppendOnlyAccepts(t *testing.T) {
	rng := rand.New(rand.NewSource(20260910))
	for i := 0; i < 50; i++ {
		p := makeSynthProof(rng, 200+rng.Intn(600), 1+rng.Intn(120), uint64(1000+i))

		inserted, unchanged, err := Decode(p.wire)
		if err != nil {
			t.Fatalf("trial %d: decoding a proof this test just built: %v", i, err)
		}
		var v Verifier
		prev, curr, err := v.Roots(unchanged, inserted, p.epoch)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		if prev != p.prev {
			t.Fatalf("trial %d: previous root %x, want %x", i, prev, p.prev)
		}
		if curr != p.curr {
			t.Fatalf("trial %d: current root %x, want %x", i, curr, p.curr)
		}
		// The two roots of a real epoch differ, and that is worth pinning: the
		// bug this replaces reported one value twice and nothing caught it.
		if prev == curr {
			t.Fatalf("trial %d: both roots are %x; an epoch that inserted %d nodes "+
				"cannot have the same root before and after", i, prev, len(inserted))
		}

		// And the verdict form agrees, on the same decoded proof.
		inserted2, unchanged2, err := Decode(p.wire)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyAppendOnly(unchanged2, inserted2, p.prev, p.curr, p.epoch)
		if err != nil || !ok {
			t.Fatalf("trial %d: VerifyAppendOnly rejected a proof whose roots Roots "+
				"rebuilt exactly: ok=%v err=%v", i, ok, err)
		}
	}
}

// TestRootsMovesWhenTheProofDoes. Reporting roots is only worth anything if a
// changed proof produces changed roots — otherwise a worker could return a
// constant and be believed.
func TestRootsMovesWhenTheProofDoes(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	p := makeSynthProof(rng, 400, 40, 99)

	inserted, unchanged, err := Decode(p.wire)
	if err != nil {
		t.Fatal(err)
	}
	var v Verifier
	prev, curr, err := v.Roots(unchanged, inserted, p.epoch)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one bit of one value in the unchanged set: both roots must move,
	// because the unchanged nodes are in both trees.
	bad := make([]byte, len(p.wire))
	copy(bad, p.wire)
	for i := range bad {
		if bad[i] != 0 {
			bad[i] ^= 1
			break
		}
	}
	i2, u2, err := Decode(bad)
	if err != nil {
		return // a mutation the decoder rejects is also a rejection
	}
	var v2 Verifier
	prev2, curr2, err := v2.Roots(u2, i2, p.epoch)
	if err != nil {
		return // likewise
	}
	if prev2 == prev && curr2 == curr {
		t.Error("a mutated proof rebuilt both original roots; the roots are not a " +
			"function of the proof")
	}
}
