package akdtree

import (
	"encoding/binary"
	"math/rand"
)

// Synthetic proofs, so the property tests need no network and no 40 MB fixture.
//
// What they can and cannot establish is worth being precise about. A proof
// built here is valid by construction against THIS implementation, so it says
// nothing about whether this package agrees with Meta — that is established by
// cmd/kt-akd-diff against roots Meta actually published, and it is the only
// thing that can establish it.
//
// What these are for is the other property, the one no valid proof can test:
// that a verifier notices when a proof changes. For that, self-consistency is
// exactly the right oracle — the question is whether a single flipped bit
// anywhere in the encoding changes the answer, and that is answerable without
// leaving the package.

// synthProof is a valid append-only proof and the roots it must rebuild.
type synthProof struct {
	wire       []byte
	prev, curr Digest
	epoch      uint64
}

// makeSynthProof builds a proof with n unchanged nodes and m inserted ones.
//
// Labels are drawn at random over the full 256-bit space with full length, so
// the tree branches the way a real one does rather than degenerating into a
// chain — a verifier that mishandled deep single-child paths would pass a test
// built from sequential labels.
func makeSynthProof(rng *rand.Rand, n, m int, epoch uint64) synthProof {
	seen := map[[32]byte]bool{}
	draw := func() Element {
		var e Element
		for {
			rng.Read(e.Label[:])
			if !seen[e.Label] {
				seen[e.Label] = true
				break
			}
		}
		e.Len = 256
		rng.Read(e.Value[:])
		return e
	}

	unchanged := make([]Element, n)
	for i := range unchanged {
		unchanged[i] = draw()
	}
	inserted := make([]Element, m)
	for i := range inserted {
		inserted[i] = draw()
	}

	// The roots this proof must rebuild, computed the way a verifier will.
	sorted := append([]Element(nil), unchanged...)
	Sort(sorted)
	prev, err := Root(sorted)
	if err != nil {
		panic("synth: unchanged set has no root: " + err.Error())
	}
	both := append([]Element(nil), unchanged...)
	for _, e := range inserted {
		e.Value = HashLeafWithCommitment(e.Value, epoch)
		both = append(both, e)
	}
	Sort(both)
	curr, err := Root(both)
	if err != nil {
		panic("synth: combined set has no root: " + err.Error())
	}

	return synthProof{wire: encodeProof(inserted, unchanged), prev: prev, curr: curr, epoch: epoch}
}

// encodeProof writes the SingleAppendOnlyProof wire format the decoder reads.
//
// A test-only encoder, matching akd's own minimisation: label_val is sent with
// trailing zero bytes stripped, which is the detail that broke the decoder the
// first time and therefore the one a synthetic proof must reproduce.
func encodeProof(inserted, unchanged []Element) []byte {
	var out []byte
	for _, e := range inserted {
		out = appendField(out, 1, encodeElement(e))
	}
	for _, e := range unchanged {
		out = appendField(out, 2, encodeElement(e))
	}
	return out
}

func encodeElement(e Element) []byte {
	var label []byte
	label = appendField(label, 1, minimiseLabel(e.Label))
	label = appendVarint(label, 2, uint64(e.Len))

	var out []byte
	out = appendField(out, 1, label)
	out = appendField(out, 2, e.Value[:])
	return out
}

func minimiseLabel(v [32]byte) []byte {
	last := -1
	for i := 31; i >= 0; i-- {
		if v[i] != 0 {
			last = i
			break
		}
	}
	if last < 0 {
		return nil
	}
	return v[:last+1]
}

func appendField(dst []byte, field int, body []byte) []byte {
	dst = appendUvarint(dst, uint64(field)<<3|2)
	dst = appendUvarint(dst, uint64(len(body)))
	return append(dst, body...)
}

func appendVarint(dst []byte, field int, v uint64) []byte {
	dst = appendUvarint(dst, uint64(field)<<3|0)
	return appendUvarint(dst, v)
}

func appendUvarint(dst []byte, v uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], v)
	return append(dst, buf[:n]...)
}

// verifyWire is what a verifier does with bytes off the wire, in one call.
func verifyWire(wire []byte, prev, curr Digest, epoch uint64) bool {
	inserted, unchanged, err := Decode(wire)
	if err != nil {
		// A proof that will not decode has not been accepted, which is the
		// property under test.
		return false
	}
	var v Verifier
	ok, err := v.VerifyAppendOnly(unchanged, inserted, prev, curr, epoch)
	return err == nil && ok
}
