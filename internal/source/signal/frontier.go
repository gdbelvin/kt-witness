package signal

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// LogFrontier is the part of the log tree an auditor has to keep: the roots of
// the maximal full subtrees, and nothing else.
//
// A full subtree never changes once it is complete — appends only ever land to
// its right — so its descendants can be forgotten the moment it fills. What
// remains is one hash per set bit of the tree size, which is why an auditor of
// a log with a billion entries holds at most a few dozen hashes. The sizes of
// those subtrees are exactly the set bits of the tree size, highest first, so
// they are implied and not stored; a frontier whose hash count disagrees with
// its size is therefore detectably corrupt rather than silently wrong.
//
// It lives here, next to treeHash, so the auditor replay and the client-side
// proof checks hash log nodes with one function and cannot drift apart.
type LogFrontier struct {
	size     uint64
	subtrees []hash // left to right, largest first
}

// NewLogFrontier rebuilds a frontier from its persisted form, refusing one
// whose number of subtree roots does not match the size.
func NewLogFrontier(size uint64, subtrees [][32]byte) (LogFrontier, error) {
	if want := bits.OnesCount64(size); len(subtrees) != want {
		return LogFrontier{}, fmt.Errorf("signal/frontier: size %d needs %d subtree roots, got %d",
			size, want, len(subtrees))
	}
	out := LogFrontier{size: size, subtrees: make([]hash, len(subtrees))}
	copy(out.subtrees, subtrees)
	return out, nil
}

// Size is the number of leaves appended so far.
func (f *LogFrontier) Size() uint64 { return f.size }

// Subtrees returns a copy of the maximal full subtree roots, largest first.
func (f *LogFrontier) Subtrees() [][32]byte {
	out := make([][32]byte, len(f.subtrees))
	copy(out, f.subtrees)
	return out
}

// Clone returns an independent copy.
func (f *LogFrontier) Clone() LogFrontier {
	return LogFrontier{size: f.size, subtrees: append([]hash(nil), f.subtrees...)}
}

// Append adds a leaf on the right. Each trailing one bit of the old size is a
// full subtree exactly as large as what is being carried, so the two merge and
// the carry moves up — binary addition, with hashing as the carry.
func (f *LogFrontier) Append(leaf [32]byte) error {
	if f.size == math.MaxUint64 {
		return errors.New("signal/frontier: log size would overflow")
	}
	carry := node{interior: false, value: leaf}
	for s, lvl := f.size, 0; s&1 == 1; s, lvl = s>>1, lvl+1 {
		last := f.subtrees[len(f.subtrees)-1]
		f.subtrees = f.subtrees[:len(f.subtrees)-1]
		// The subtree being absorbed has 2^lvl leaves; only a single leaf
		// (lvl 0) is marshalled with the leaf flag.
		carry = treeHash(node{interior: lvl > 0, value: last}, carry)
	}
	f.subtrees = append(f.subtrees, carry.value)
	f.size++
	return nil
}

// Root is the root of the left-balanced tree over every leaf appended. In that
// layout the right spine is exactly the frontier, smallest subtree deepest, so
// folding the subtrees right to left rebuilds it.
func (f *LogFrontier) Root() ([32]byte, error) {
	if f.size == 0 {
		return hash{}, errors.New("signal/frontier: empty log has no root")
	}
	n := len(f.subtrees)
	// The smallest subtree is a bare leaf exactly when the size is odd.
	acc := node{interior: f.size&1 == 0, value: f.subtrees[n-1]}
	for i := n - 2; i >= 0; i-- {
		// Every subtree left of the smallest has at least two leaves.
		acc = treeHash(node{interior: true, value: f.subtrees[i]}, acc)
	}
	return acc.value, nil
}
