package signal

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"slices"
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

func parentStep(x uint64) uint64 {
	k := uint(level(x))
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1))
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

// --- batch inclusion ---------------------------------------------------------

// parent is the parent of x in a tree of n leaves, skipping past node ids that
// the partially filled right side does not actually contain.
func parent(x, n uint64) (uint64, error) {
	if x == treeRoot(n) {
		return 0, fmt.Errorf("signal/logtree: root node %d has no parent", x)
	}
	w := nodeWidth(n)
	p := parentStep(x)
	for p >= w {
		p = parentStep(p)
	}
	return p, nil
}

func sibling(x, n uint64) (uint64, error) {
	p, err := parent(x, n)
	if err != nil {
		return 0, err
	}
	if x < p {
		return rightChild(p, n)
	}
	return leftChild(p)
}

// batchCopath lists the nodes needed to reconstruct the root from a *set* of
// leaves at once. Where two requested leaves are siblings, neither sibling is
// needed — which is why a batch proof is much smaller than one inclusion proof
// per leaf, and why the proof length is fully determined by the leaf indices.
// That last property is what makes the check meaningful: the server cannot pad
// the proof to make an arbitrary root come out.
//
// leaves are leaf indices (not node ids) and must be sorted and distinct.
func batchCopath(leaves []uint64, n uint64) ([]uint64, error) {
	nodes := make([]uint64, len(leaves))
	for i, x := range leaves {
		nodes[i] = 2 * x
	}

	var out []uint64
	root := treeRoot(n)
	for !(len(nodes) == 1 && nodes[0] == root) {
		var next []uint64
		for len(nodes) > 1 {
			p, err := parent(nodes[0], n)
			if err != nil {
				return nil, err
			}
			r, err := rightChild(p, n)
			if err != nil {
				return nil, err
			}
			if r == nodes[1] {
				nodes = nodes[2:] // both children present; no sibling needed
			} else {
				s, err := sibling(nodes[0], n)
				if err != nil {
					return nil, err
				}
				out = append(out, s)
				nodes = nodes[1:]
			}
			next = append(next, p)
		}
		if len(nodes) == 1 {
			p, err := parent(nodes[0], n)
			if err != nil {
				return nil, err
			}
			if len(next) > 0 && level(p) > level(next[0]) {
				// Carrying a node up unchanged: its parent is higher than the
				// level we are assembling, so it joins the next level as is.
				next = append(next, nodes[0])
			} else {
				s, err := sibling(nodes[0], n)
				if err != nil {
					return nil, err
				}
				out = append(out, s)
				next = append(next, p)
			}
		}
		nodes = next
	}
	slices.Sort(out)
	return out, nil
}

// evaluateBatchProof returns the root implied by a batch inclusion proof for the
// given leaf indices and their leaf hashes.
func evaluateBatchProof(leaves []uint64, n uint64, values, proof []hash) (hash, error) {
	var zero hash
	if len(leaves) != len(values) {
		return zero, fmt.Errorf("signal/logtree: %d leaf ids but %d values", len(leaves), len(values))
	}
	if len(leaves) == 0 {
		return zero, fmt.Errorf("signal/logtree: empty batch inclusion proof")
	}
	for i := 1; i < len(leaves); i++ {
		if leaves[i-1] >= leaves[i] {
			return zero, fmt.Errorf("signal/logtree: leaf ids must be sorted and distinct")
		}
	}
	if leaves[len(leaves)-1] >= n {
		return zero, fmt.Errorf("signal/logtree: leaf id %d is beyond tree size %d",
			leaves[len(leaves)-1], n)
	}

	copath, err := batchCopath(leaves, n)
	if err != nil {
		return zero, err
	}
	if len(proof) != len(copath) {
		return zero, fmt.Errorf("signal/logtree: batch proof has %d hashes, expected %d",
			len(proof), len(copath))
	}

	// Both sequences are sorted by node id, so a merge visits every node in
	// left-to-right order, which is what the calculator requires.
	calc := &rootCalculator{}
	i, j := 0, 0
	for i < len(leaves) && j < len(copath) {
		if 2*leaves[i] < copath[j] {
			calc.insert(0, values[i])
			i++
		} else {
			calc.insert(level(copath[j]), proof[j])
			j++
		}
	}
	for ; i < len(leaves); i++ {
		calc.insert(0, values[i])
	}
	for ; j < len(copath); j++ {
		calc.insert(level(copath[j]), proof[j])
	}
	return calc.root()
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
