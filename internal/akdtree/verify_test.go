package akdtree

import (
	"testing"
)

// These are structural tests. The real correctness evidence is cmd/kt-akd-diff
// checking against roots Meta and WhatsApp actually published, which is the
// only oracle that can say this implements THEIR tree rather than a
// self-consistent tree of its own. What is guarded here is the behaviour a
// refactor could quietly break without any published root noticing.

func elem(first byte, bits uint32, v byte) Element {
	var e Element
	e.Label[0] = first
	e.Len = bits
	e.Value[0] = v
	return e
}

// An empty proof has a root, and it is not the root of a tree with something
// in it. The reference keeps the initial root value rather than combining two
// absent children, and getting that wrong would only show up on a log with an
// empty epoch — rare, and therefore exactly the case to pin.
func TestEmptyTreeHasItsOwnRoot(t *testing.T) {
	empty, err := Root(nil)
	if err != nil {
		t.Fatal(err)
	}
	one := []Element{elem(0x80, 8, 1)}
	Sort(one)
	got, err := Root(one)
	if err != nil {
		t.Fatal(err)
	}
	if empty == got {
		t.Error("a tree with one element hashes the same as an empty one")
	}
}

// Every bit of every value has to reach the root, or a proof could be altered
// where nobody is looking.
func TestChangingAnyValueChangesTheRoot(t *testing.T) {
	base := []Element{
		elem(0x00, 8, 1), elem(0x40, 8, 2), elem(0x80, 8, 3), elem(0xc0, 8, 4),
	}
	Sort(base)
	want, err := Root(base)
	if err != nil {
		t.Fatal(err)
	}
	for i := range base {
		mutated := append([]Element(nil), base...)
		mutated[i].Value[31] ^= 1
		got, err := Root(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			t.Errorf("flipping a bit in element %d left the root unchanged", i)
		}
	}
}

// The label is hashed into the tree alongside the value, so two elements
// carrying the same value at different positions must not be interchangeable.
func TestPositionMatters(t *testing.T) {
	a := []Element{elem(0x00, 8, 7), elem(0x80, 8, 9)}
	b := []Element{elem(0x00, 8, 9), elem(0x80, 8, 7)}
	Sort(a)
	Sort(b)
	ra, err := Root(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Root(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra == rb {
		t.Error("swapping two values between positions left the root unchanged")
	}
}

// A tree leaning entirely one way still has to hash the missing side, because
// the reference substitutes a fixed hash rather than omitting the term.
func TestOneSidedTreeIsNotTheSameAsHalfATree(t *testing.T) {
	left := []Element{elem(0x00, 8, 1), elem(0x10, 8, 2)}
	Sort(left)
	l, err := Root(left)
	if err != nil {
		t.Fatal(err)
	}
	// The same two values on the other side of the root.
	right := []Element{elem(0x80, 8, 1), elem(0x90, 8, 2)}
	Sort(right)
	r, err := Root(right)
	if err != nil {
		t.Fatal(err)
	}
	if l == r {
		t.Error("a left-leaning tree hashes the same as a right-leaning one")
	}
}

// An element sitting exactly on the interior node that covers it would be
// dropped while partitioning, and a dropped element is a committed value that
// never reached the tree. The reference rejects the proof; so must this.
func TestAnElementOnAnInteriorNodeIsRejected(t *testing.T) {
	elems := []Element{
		elem(0x00, 1, 1), // one bit: sits exactly where the others' prefix ends
		elem(0x00, 8, 2),
		elem(0x40, 8, 3),
	}
	Sort(elems)
	if _, err := Root(elems); err == nil {
		t.Error("an element that would be dropped was accepted; a committed value can vanish")
	}
}

// Order of input must not change the answer: the sort is what makes the
// recursion valid, and a caller passing elements in a different order is not
// making a different claim.
func TestInputOrderDoesNotMatter(t *testing.T) {
	a := []Element{elem(0xc0, 8, 4), elem(0x00, 8, 1), elem(0x80, 8, 3), elem(0x40, 8, 2)}
	b := []Element{elem(0x00, 8, 1), elem(0x40, 8, 2), elem(0x80, 8, 3), elem(0xc0, 8, 4)}
	Sort(a)
	Sort(b)
	ra, err := Root(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Root(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra != rb {
		t.Error("the same elements in a different order produced different roots")
	}
}

// The commitment binds a value to the epoch it was inserted in, so the same
// value inserted at a different epoch must hash differently.
func TestCommitmentBindsTheEpoch(t *testing.T) {
	var v Digest
	v[0] = 42
	if HashLeafWithCommitment(v, 100) == HashLeafWithCommitment(v, 101) {
		t.Error("the same value committed to two epochs produced one hash")
	}
}

// prefixOf must zero the bits beyond the length, because a label's trailing
// bits are not guaranteed to be zero and two labels that differ only there are
// the same position in the tree.
func TestPrefixZeroesTheTail(t *testing.T) {
	var label [32]byte
	label[0] = 0xff
	got := prefixOf(label, 4)
	if got[0] != 0xf0 {
		t.Errorf("prefixOf(0xff, 4) = %#x, want 0xf0", got[0])
	}
	for i := 1; i < 32; i++ {
		if got[i] != 0 {
			t.Errorf("byte %d was not cleared", i)
		}
	}
}
