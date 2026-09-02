package signal

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// referenceTree builds a whole log tree explicitly and reads node values out of
// it. deriveRoot only ever sees a proof, so checking it against a tree built
// independently — bottom-up, from leaves — is a real test of the math rather
// than a restatement of it.
type referenceTree struct {
	n uint64
}

func (rt referenceTree) leaf(i uint64) hash {
	return sha256.Sum256([]byte(fmt.Sprintf("leaf-%d", i)))
}

// nodeAt computes the node with id x in a tree of size leaves.
func (rt referenceTree) nodeAt(t *testing.T, x, size uint64) node {
	t.Helper()
	if level(x) == 0 {
		return node{interior: false, value: rt.leaf(x / 2)}
	}
	l, err := leftChild(x)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rightChild(x, size)
	if err != nil {
		t.Fatal(err)
	}
	return treeHash(rt.nodeAt(t, l, size), rt.nodeAt(t, r, size))
}

func (rt referenceTree) root(t *testing.T, size uint64) hash {
	t.Helper()
	return rt.nodeAt(t, treeRoot(size), size).value
}

// proof reads the consistency proof for m->n straight out of the built tree.
func (rt referenceTree) proof(t *testing.T, m, n uint64) []hash {
	t.Helper()
	ids, err := consistencyProofNodes(m, n)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]hash, 0, len(ids))
	for _, id := range ids {
		out = append(out, rt.nodeAt(t, id, n).value)
	}
	return out
}

// The central property: running a consistency proof forwards from a known root
// reproduces the newer root. This is what lets us recover Signal's service root,
// which it never serves directly.
func TestDeriveRootMatchesIndependentlyBuiltTree(t *testing.T) {
	rt := referenceTree{}
	for n := uint64(2); n <= 40; n++ {
		for m := uint64(1); m < n; m++ {
			want := rt.root(t, n)
			got, err := deriveRoot(m, n, rt.proof(t, m, n), rt.root(t, m))
			if err != nil {
				t.Fatalf("derive %d->%d: %v", m, n, err)
			}
			if got != want {
				t.Fatalf("derive %d->%d: got %x, want %x", m, n, got, want)
			}
		}
	}
}

func TestVerifyConsistencyAcceptsGenuineExtension(t *testing.T) {
	rt := referenceTree{}
	for _, tc := range [][2]uint64{{1, 2}, {3, 8}, {4, 5}, {8, 16}, {7, 23}, {16, 17}} {
		m, n := tc[0], tc[1]
		if err := verifyConsistency(m, n, rt.proof(t, m, n), rt.root(t, m), rt.root(t, n)); err != nil {
			t.Errorf("%d->%d should verify: %v", m, n, err)
		}
	}
}

// A proof for the wrong destination is caught when the proof length differs.
func TestDeriveRejectsWrongLengthProof(t *testing.T) {
	rt := referenceTree{}
	tooLong := append(rt.proof(t, 4, 20), hash{})
	if _, err := deriveRoot(4, 20, tooLong, rt.root(t, 4)); err == nil {
		t.Fatal("a proof of the wrong length must be rejected")
	}
}

// Documents a real limit rather than hiding it: when m is a power of two the old
// tree is one full subtree, so mRoot is inserted directly and the proof cannot
// be checked against it. A wrong-but-correctly-sized proof then derives a wrong
// root silently. This is safe only because both callers compare the derived root
// against one authenticated by Signal's signature — never trust deriveRoot alone.
func TestDeriveCannotSelfCheckWhenOldSizeIsPowerOfTwo(t *testing.T) {
	rt := referenceTree{}
	// 4 -> 19 and 4 -> 20 happen to need the same number of hashes.
	wrong := rt.proof(t, 4, 19)
	right := rt.proof(t, 4, 20)
	if len(wrong) != len(right) {
		t.Skip("proof lengths differ; this case no longer illustrates the limit")
	}

	got, err := deriveRoot(4, 20, wrong, rt.root(t, 4))
	if err != nil {
		t.Fatalf("expected silent derivation, got error: %v", err)
	}
	if got == rt.root(t, 20) {
		t.Fatal("a proof for a different tree should not derive the correct root")
	}
	// The protection is the caller's comparison, not deriveRoot.
	if err := verifyConsistency(4, 20, wrong, rt.root(t, 4), rt.root(t, 20)); err == nil {
		t.Fatal("verifyConsistency must reject it by comparing against the real root")
	}
}

// A proof that does not reconstruct the root we already witnessed must be
// rejected, or an attacker could hand us a valid proof for a different history.
func TestDeriveRejectsProofAgainstWrongOldRoot(t *testing.T) {
	rt := referenceTree{}
	var wrong hash
	wrong[0] = 0xFF
	// m=3 is not a power of two, so the old root is reconstructed from the proof
	// and checked.
	if _, err := deriveRoot(3, 11, rt.proof(t, 3, 11), wrong); err == nil {
		t.Fatal("a proof that does not reconstruct the witnessed root must be rejected")
	}
}

func TestVerifyConsistencyRejectsWrongNewRoot(t *testing.T) {
	rt := referenceTree{}
	var wrong hash
	wrong[0] = 0xAB
	if err := verifyConsistency(3, 11, rt.proof(t, 3, 11), rt.root(t, 3), wrong); err == nil {
		t.Fatal("a root the proof does not imply must be rejected")
	}
}

func TestDeriveRejectsDegenerateRanges(t *testing.T) {
	rt := referenceTree{}
	for _, tc := range [][2]uint64{{0, 5}, {5, 5}, {6, 5}} {
		if _, err := deriveRoot(tc[0], tc[1], nil, rt.root(t, 5)); err == nil {
			t.Errorf("m=%d n=%d should be rejected", tc[0], tc[1])
		}
	}
}

// Leaf and interior nodes must hash differently, or a leaf value could be
// passed off as a subtree root.
func TestLeafAndInteriorHashesDiffer(t *testing.T) {
	var v hash
	v[0] = 1
	leaf := node{interior: false, value: v}
	interior := node{interior: true, value: v}
	if string(leaf.marshal()) == string(interior.marshal()) {
		t.Fatal("leaf and interior encodings must differ")
	}
	if len(leaf.marshal()) != 33 {
		t.Fatalf("node encoding is %d bytes, want 33", len(leaf.marshal()))
	}
}

// Spot-check the RFC 9420 numbering against hand-worked values.
func TestNodeArithmetic(t *testing.T) {
	if level(0) != 0 || level(1) != 1 || level(3) != 2 || level(7) != 3 {
		t.Error("level should count trailing one bits")
	}
	if nodeWidth(0) != 0 || nodeWidth(1) != 1 || nodeWidth(4) != 7 {
		t.Error("unexpected node width")
	}
	if treeRoot(1) != 0 || treeRoot(4) != 3 || treeRoot(8) != 7 {
		t.Errorf("unexpected root ids: %d %d %d", treeRoot(1), treeRoot(4), treeRoot(8))
	}
}
