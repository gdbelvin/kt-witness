package signal

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// Signal's log tree, reimplemented from libsignal (rust/keytrans/src/log.rs and
// left_balanced.rs).
//
// It is a left-balanced binary Merkle tree using the RFC 9420 node numbering
// (leaves at even indices, a node's level being its count of trailing one
// bits), rather than the RFC 6962 layout. Nodes hash as
//
//	H(marshal(left) || marshal(right))
//
// where marshal is a 33-byte encoding: one byte that is 1 for interior nodes
// and 0 for leaves, followed by the 32-byte value. The interior byte is what
// makes leaf and interior hashes non-interchangeable.
//
// The reason to have this at all: a consistency proof does not merely check a
// new root, it *determines* one. Signal never serves the service tree's root
// directly, but every auditor tree head carries a signed root at the auditor's
// size plus a consistency proof up to the service's size. Running that proof
// forwards yields the service root — which can then be checked against the
// service's own signature, and used to prove append-only across our own
// observations. That is the difference between tier S and tier A here.

type hash = [32]byte

// node is a tree node. The interior flag is part of the hash preimage.
type node struct {
	interior bool
	value    hash
}

func (n node) marshal() []byte {
	out := make([]byte, 33)
	if n.interior {
		out[0] = 1
	}
	copy(out[1:], n.value[:])
	return out
}

func treeHash(left, right node) node {
	h := sha256.New()
	h.Write(left.marshal())
	h.Write(right.marshal())
	var v hash
	copy(v[:], h.Sum(nil))
	return node{interior: true, value: v}
}

// --- RFC 9420 node arithmetic ------------------------------------------------

func log2(n uint64) uint {
	if n == 0 {
		return 0
	}
	return uint(bits.Len64(n) - 1)
}

// level is the height of a node: leaves are 0. In this numbering that is the
// count of trailing one bits.
func level(x uint64) int { return bits.TrailingZeros64(^x) }

func leftStep(x uint64) (uint64, error) {
	k := level(x)
	if k == 0 {
		return 0, fmt.Errorf("signal/logtree: leaf node %d has no children", x)
	}
	return x ^ (1 << (k - 1)), nil
}

func rightStep(x uint64) (uint64, error) {
	k := level(x)
	if k == 0 {
		return 0, fmt.Errorf("signal/logtree: leaf node %d has no children", x)
	}
	return x ^ (3 << (k - 1)), nil
}

func nodeWidth(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 2*(n-1) + 1
}

func treeRoot(n uint64) uint64 { return (1 << log2(nodeWidth(n))) - 1 }

func leftChild(x uint64) (uint64, error) { return leftStep(x) }

// rightChild descends past nodes that do not exist in a tree of n leaves, which
// is how the left-balanced layout handles a partially filled right side.
func rightChild(x, n uint64) (uint64, error) {
	r, err := rightStep(x)
	if err != nil {
		return 0, err
	}
	w := nodeWidth(n)
	for r >= w {
		if r, err = leftStep(r); err != nil {
			return 0, err
		}
	}
	return r, nil
}

func isFullSubtree(x, n uint64) bool {
	rightmost := 2 * (n - 1)
	return x+(1<<level(x))-1 <= rightmost
}

// fullSubtrees decomposes x into the full subtrees it consists of, walking down
// the right edge while the node is not full.
func fullSubtrees(x, n uint64) ([]uint64, error) {
	var out []uint64
	for {
		if isFullSubtree(x, n) {
			return append(out, x), nil
		}
		l, err := leftChild(x)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
		if x, err = rightChild(x, n); err != nil {
			return nil, err
		}
	}
}

// consistencyProofNodes lists the node ids a consistency proof between trees of
// m and n leaves consists of (RFC 6962's algorithm over this numbering).
func consistencyProofNodes(m, n uint64) ([]uint64, error) {
	var out []uint64
	err := subProof(m, n, true, &out)
	return out, err
}

func subProof(m, n uint64, b bool, out *[]uint64) error {
	if m == n {
		if !b {
			*out = append(*out, treeRoot(m))
		}
		return nil
	}
	k := uint64(1) << log2(n)
	if k == n {
		k /= 2
	}
	if m <= k {
		if err := subProof(m, k, b, out); err != nil {
			return err
		}
		r, err := rightChild(treeRoot(n), n)
		if err != nil {
			return err
		}
		*out = append(*out, r)
		return nil
	}

	l, err := leftChild(treeRoot(n))
	if err != nil {
		return err
	}
	*out = append(*out, l)

	start := len(*out)
	if err := subProof(m-k, n-k, false, out); err != nil {
		return err
	}
	// The recursive call numbered nodes as if the right subtree were a tree of
	// its own; shift them into this tree's numbering.
	for i := start; i < len(*out); i++ {
		(*out)[i] += 2 * k
	}
	return nil
}

// --- root calculator ---------------------------------------------------------

// rootCalculator folds inserted nodes into a root, combining whenever two nodes
// meet at the same level. Equivalent to libsignal's SimpleRootCalculator.
type rootCalculator struct {
	chain []*node
}

func (c *rootCalculator) insert(lvl int, value hash) {
	for len(c.chain) < lvl+1 {
		c.chain = append(c.chain, nil)
	}
	acc := node{interior: lvl != 0, value: value}
	i := lvl
	for i < len(c.chain) && c.chain[i] != nil {
		acc = treeHash(*c.chain[i], acc)
		c.chain[i] = nil
		i++
	}
	if i == len(c.chain) {
		c.chain = append(c.chain, &acc)
	} else {
		c.chain[i] = &acc
	}
}

func (c *rootCalculator) root() (hash, error) {
	var zero hash
	if len(c.chain) == 0 {
		return zero, fmt.Errorf("signal/logtree: empty chain")
	}
	pos := -1
	for i, nd := range c.chain {
		if nd != nil {
			pos = i
			break
		}
	}
	if pos < 0 {
		return zero, fmt.Errorf("signal/logtree: malformed chain")
	}
	acc := *c.chain[pos]
	for _, nd := range c.chain[pos+1:] {
		if nd != nil {
			acc = treeHash(*nd, acc)
		}
	}
	return acc.value, nil
}

// --- consistency -------------------------------------------------------------

// deriveRoot runs a consistency proof forwards: given the root of a tree of m
// leaves and a proof to a tree of n leaves, it returns the root the proof
// implies for n.
//
// It first checks the proof genuinely reconstructs mRoot, so a proof that does
// not describe the tree we already witnessed is rejected rather than silently
// producing some other root.
//
// One limit worth knowing: when m is a power of two the old tree is a single
// full subtree, so mRoot is inserted directly and there is nothing to check it
// against. In that case a wrong-but-correctly-sized proof yields a wrong root
// with no error. Callers must therefore always compare the derived root against
// one authenticated some other way — which is what both callers here do, via
// Signal's signature.
func deriveRoot(m, n uint64, proof []hash, mRoot hash) (hash, error) {
	var zero hash
	if m == 0 || m >= n {
		return zero, fmt.Errorf("signal/logtree: m must be in [1, n), got m=%d n=%d", m, n)
	}
	ids, err := consistencyProofNodes(m, n)
	if err != nil {
		return zero, err
	}
	if len(proof) != len(ids) {
		return zero, fmt.Errorf("signal/logtree: proof has %d hashes, expected %d for %d->%d",
			len(proof), len(ids), m, n)
	}

	calc := &rootCalculator{}
	path, err := fullSubtrees(treeRoot(m), m)
	if err != nil {
		return zero, err
	}

	var next int
	if len(path) == 1 {
		// m is a power of two: the old tree is itself a full subtree, so its
		// root is used directly and the whole proof describes the extension.
		calc.insert(level(treeRoot(m)), mRoot)
	} else {
		for i, elem := range path {
			if i >= len(ids) || ids[i] != elem {
				return zero, fmt.Errorf("signal/logtree: proof node %d does not match expected path element", i)
			}
			calc.insert(level(elem), proof[i])
			next = i + 1
		}
		got, err := calc.root()
		if err != nil {
			return zero, err
		}
		if got != mRoot {
			return zero, fmt.Errorf("signal/logtree: proof does not reconstruct the witnessed root at size %d", m)
		}
	}

	for j := next; j < len(ids); j++ {
		calc.insert(level(ids[j]), proof[j])
	}
	return calc.root()
}

// verifyConsistency checks that a tree of n leaves with root nRoot extends a
// tree of m leaves with root mRoot.
func verifyConsistency(m, n uint64, proof []hash, mRoot, nRoot hash) error {
	got, err := deriveRoot(m, n, proof, mRoot)
	if err != nil {
		return err
	}
	if got != nRoot {
		return fmt.Errorf("signal/logtree: tree at size %d (root %x) does not extend size %d (root %x)",
			n, nRoot, m, mRoot)
	}
	return nil
}
