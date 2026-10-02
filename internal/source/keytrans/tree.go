package keytrans

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"sort"
)

// The log tree of draft-ietf-keytrans-protocol-05 §3.2/§11.8/§12.1.
//
// It is the same tree Signal's adapter verifies: left-balanced, with a node
// hashed as H(tag || left || tag || right), tag 0 for a leaf and 1 for an
// interior node. What differs is the proof. IETF proofs carry only the heads
// of balanced subtrees and batch inclusion with consistency, so they are
// verified by one recursion (walk) that decides, node by node, whether the
// verifier already knows a value, can compute it, or must take the next
// proof element.

// leafHash is Hash(LogEntry{timestamp, prefix_tree}).
func leafHash(timestamp uint64, prefixRoot [32]byte) [32]byte {
	var b [40]byte
	binary.BigEndian.PutUint64(b[:8], timestamp)
	copy(b[8:], prefixRoot[:])
	return sha256.Sum256(b[:])
}

func parentHash(l [32]byte, lLeaf bool, r [32]byte, rLeaf bool) [32]byte {
	tag := func(leaf bool) byte {
		if leaf {
			return 0
		}
		return 1
	}
	h := sha256.New()
	h.Write([]byte{tag(lLeaf)})
	h.Write(l[:])
	h.Write([]byte{tag(rLeaf)})
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// span is the half-open range of leaves [lo, hi) under one node.
type span struct{ lo, hi uint64 }

func (s span) size() uint64   { return s.hi - s.lo }
func (s span) balanced() bool { return bits.OnesCount64(s.size()) == 1 }

func (s span) split() (span, span) {
	k := uint64(1) << (bits.Len64(s.size()-1) - 1)
	return span{s.lo, s.lo + k}, span{s.lo + k, s.hi}
}

// fullSubtrees are the maximal balanced subtrees of a tree of n leaves.
func fullSubtrees(n uint64) []span {
	var out []span
	var lo uint64
	for n > 0 {
		k := uint64(1) << (bits.Len64(n) - 1)
		out = append(out, span{lo, lo + k})
		lo += k
		n -= k
	}
	return out
}

func rootOf(n uint64, heads [][32]byte) ([32]byte, error) {
	spans := fullSubtrees(n)
	if n == 0 || len(spans) != len(heads) {
		return [32]byte{}, errors.New("keytrans: wrong number of full subtrees")
	}
	i := len(heads) - 1
	v, leaf := heads[i], spans[i].size() == 1
	for i--; i >= 0; i-- {
		v = parentHash(heads[i], spans[i].size() == 1, v, leaf)
		leaf = false
	}
	return v, nil
}

// batch describes what an inclusion proof must let the verifier compute.
type batch struct {
	size     uint64
	leaves   map[uint64][32]byte
	oldSize  uint64
	retained [][32]byte // full subtree heads of oldSize
	auditor  uint64     // a size whose root is also needed, or 0
}

type batchResult struct {
	root         [32]byte
	auditorRoot  [32]byte
	fullSubtrees [][32]byte
}

var errProof = errors.New("keytrans: log tree proof does not verify")

// verify recomputes the root from leaves, retained heads and elements, and
// requires every element to be used exactly once.
func (b *batch) verify(elements [][32]byte) (*batchResult, error) {
	if b.size == 0 || b.oldSize > b.size || b.auditor > b.size {
		return nil, errProof
	}
	old := fullSubtrees(b.oldSize)
	if len(old) != len(b.retained) {
		return nil, errors.New("keytrans: retained view does not match its size")
	}
	retained := map[span][32]byte{}
	for i, s := range old {
		retained[s] = b.retained[i]
	}
	ids := make([]uint64, 0, len(b.leaves))
	for x := range b.leaves {
		if x >= b.size {
			return nil, errProof
		}
		ids = append(ids, x)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	hasLeaf := func(s span) bool {
		i := sort.Search(len(ids), func(i int) bool { return ids[i] >= s.lo })
		return i < len(ids) && ids[i] < s.hi
	}
	retainedInside := func(s span) bool {
		for t := range retained {
			if s.lo <= t.lo && t.hi <= s.hi {
				return true
			}
		}
		return false
	}
	crossesAuditor := func(s span) bool { return b.auditor != 0 && s.lo < b.auditor && b.auditor < s.hi }

	computed := map[span][32]byte{}
	next := 0
	var walk func(s span) ([32]byte, error)
	walk = func(s span) ([32]byte, error) {
		v, err := func() ([32]byte, error) {
			leaf := hasLeaf(s)
			_, isRetained := retained[s]
			switch {
			case s.size() == 1 && leaf:
				return b.leaves[s.lo], nil
			case isRetained && !leaf && !crossesAuditor(s):
				return retained[s], nil
			case s.balanced() && !leaf && !crossesAuditor(s) && !retainedInside(s):
				if next >= len(elements) {
					return [32]byte{}, errProof
				}
				next++
				return elements[next-1], nil
			}
			l, r := s.split()
			lv, err := walk(l)
			if err != nil {
				return [32]byte{}, err
			}
			rv, err := walk(r)
			if err != nil {
				return [32]byte{}, err
			}
			v := parentHash(lv, l.size() == 1, rv, r.size() == 1)
			// A retained head recomputed from below must match (§12.1).
			if want, ok := retained[s]; ok && want != v {
				return [32]byte{}, errProof
			}
			return v, nil
		}()
		if err == nil {
			computed[s] = v
		}
		return v, err
	}
	root, err := walk(span{0, b.size})
	if err != nil {
		return nil, err
	}
	if next != len(elements) {
		return nil, errProof
	}
	res := &batchResult{root: root}
	for _, s := range fullSubtrees(b.size) {
		res.fullSubtrees = append(res.fullSubtrees, computed[s])
	}
	if b.auditor != 0 {
		var heads [][32]byte
		for _, s := range fullSubtrees(b.auditor) {
			h, ok := computed[s]
			if !ok {
				return nil, errProof
			}
			heads = append(heads, h)
		}
		if res.auditorRoot, err = rootOf(b.auditor, heads); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// The implicit binary search tree over log entries (§4.1, Appendix A).

func ibstRoot(n uint64) uint64 { return (uint64(1) << (bits.Len64(n) - 1)) - 1 }

func level(x uint64) int { return bits.TrailingZeros64(^x) }

func left(x uint64) uint64 { return x ^ (1 << (level(x) - 1)) }

func hasRight(x, n uint64) bool { return level(x) > 0 && x+1 < n }

func right(x, n uint64) uint64 {
	x ^= 3 << (level(x) - 1)
	for x >= n {
		x = left(x)
	}
	return x
}

func frontierFrom(x, n uint64) []uint64 {
	out := []uint64{x}
	for hasRight(x, n) {
		x = right(x, n)
		out = append(out, x)
	}
	return out
}

func frontier(n uint64) []uint64 { return frontierFrom(ibstRoot(n), n) }

// directPath is x's ancestors, parent first.
func directPath(x, n uint64) []uint64 {
	var path []uint64
	for cur := ibstRoot(n); cur != x; {
		path = append(path, cur)
		if x < cur {
			cur = left(cur)
		} else {
			cur = right(cur, n)
		}
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// updateView lists the entries whose timestamps a user receives when moving
// from a tree of m entries to one of n (§4.2).
func updateView(m, n uint64) []uint64 {
	if m == 0 {
		return frontier(n)
	}
	if m >= n {
		return nil
	}
	var out []uint64
	for _, x := range directPath(m-1, n) {
		if x >= m {
			out = append(out, x)
		}
	}
	from := m - 1
	if len(out) > 0 {
		from = out[len(out)-1]
	}
	return append(out, frontierFrom(from, n)[1:]...)
}
