package proton

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
)

// Proton's key directory, reimplemented from ProtonMail/kt-auditor's C verifier
// and pm-key-transparency-go-client.
//
// # Why this exists
//
// Tier A+ proves the published epoch chain is continuous. It cannot prove that
// each epoch's tree was derived from the previous one by legal mutations — the
// directory is a *map*, and a map is mutable. An operator can remove a binding,
// overwrite one without bumping its revision, or insert at a skipped revision,
// and the chain of signed epoch hashes stays perfectly consistent throughout.
// Recomputing the tree from its published leaves is what closes that gap.
//
// # The construction
//
//   - A 256-level sparse binary Merkle tree.
//   - The path is the 32-byte label: VRF(email)[0:28] || uint32be(revision).
//     Bits are read MSB-first, so level 1 uses bit 7 of byte 0.
//   - A leaf's hash is SHA-256 of its 36-byte value, which is itself
//     SHA-256(signed key list) || uint32be(minEpochID).
//   - An interior node is SHA-256(left || right), where an absent child
//     contributes 32 zero bytes.
//
// That last point is the expensive one, and it is not a detail: an empty subtree
// hashes to zero at *every* depth, so a lonely leaf is still hashed against zero
// once per level down to the leaf. With ~200M leaves the tree costs ~46 billion
// compressions to rebuild, which is why Proton's own auditor is a C program.

const (
	labelSize = 32
	valueSize = 36
	entrySize = labelSize + valueSize // 68; the dump has no framing beyond this
	treeDepth = labelSize * 8         // 256
	hashSize  = 32
)

// emptyNode is the hash of an empty subtree — at any depth.
var emptyNode = make([]byte, hashSize)

// bitAt reports the path bit for the given level (1-based, as the tree is walked
// from the root downwards). Level L is decided by bit (L-1), MSB-first.
func bitAt(label []byte, level int) int {
	i := level - 1
	return int(label[i/8]>>(7-(i%8))) & 1
}

// combine folds a subtree root one level upwards, against an empty sibling.
func combine(h []byte, label []byte, level int) []byte {
	var buf [hashSize * 2]byte
	if bitAt(label, level) == 0 {
		copy(buf[:hashSize], h)
	} else {
		copy(buf[hashSize:], h)
	}
	sum := sha256.Sum256(buf[:])
	return sum[:]
}

func join(left, right []byte) []byte {
	// Two empty children make an empty parent, not a hash of zeros. Proton's C
	// verifier gets this by skipping empty nodes entirely; here it has to be
	// explicit, because sharding evaluates subtrees that may be wholly empty.
	// The recursive path never splits a range into two empty halves, so this
	// only bites when the tree is divided for parallelism — which is precisely
	// the kind of difference that would otherwise show up as a wrong root only
	// at full scale.
	if isEmpty(left) && isEmpty(right) {
		return emptyNode
	}
	var buf [hashSize * 2]byte
	copy(buf[:hashSize], left)
	copy(buf[hashSize:], right)
	sum := sha256.Sum256(buf[:])
	return sum[:]
}

func isEmpty(h []byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// Leaves is a sorted, immutable view of a tree dump: `count` records of
// (label[32], value[36]), ascending by label.
//
// It is an interface so the root can be computed straight off a memory-mapped
// file without loading 13 GB into the heap.
type Leaves interface {
	Len() int
	// Label and Value return views valid until the next call; callers must not
	// retain them.
	Label(i int) []byte
	Value(i int) []byte
}

// SliceLeaves is a Leaves backed by one contiguous buffer, which is what a
// memory-mapped dump gives us.
type SliceLeaves []byte

func (s SliceLeaves) Len() int { return len(s) / entrySize }
func (s SliceLeaves) Label(i int) []byte {
	return s[i*entrySize : i*entrySize+labelSize]
}
func (s SliceLeaves) Value(i int) []byte {
	return s[i*entrySize+labelSize : (i+1)*entrySize]
}

// leafHash is SHA-256 over the 36-byte value.
func leafHash(v []byte) []byte {
	sum := sha256.Sum256(v)
	return sum[:]
}

// TreeRoot recomputes the directory root from its sorted leaves.
//
// The leaves must be ascending by label, which is how Proton publishes them —
// the whole design depends on it, since sorted order is what lets the tree be
// rebuilt by recursive range splitting instead of by random access.
func TreeRoot(leaves Leaves) ([]byte, error) {
	n := leaves.Len()
	if n == 0 {
		return emptyNode, nil
	}
	if err := checkSorted(leaves); err != nil {
		return nil, err
	}
	return subtree(leaves, 0, n, 0), nil
}

func checkSorted(leaves Leaves) error {
	prev := append([]byte(nil), leaves.Label(0)...)
	for i := 1; i < leaves.Len(); i++ {
		cur := leaves.Label(i)
		if compare(prev, cur) >= 0 {
			return fmt.Errorf("proton/tree: leaves not strictly ascending at index %d", i)
		}
		copy(prev, cur)
	}
	return nil
}

func compare(a, b []byte) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// subtree computes the root of the subtree covering leaves [lo, hi) whose labels
// all share the first `depth` bits.
func subtree(leaves Leaves, lo, hi, depth int) []byte {
	switch {
	case lo == hi:
		return emptyNode

	case hi-lo == 1:
		// A lonely leaf. Fold it straight to `depth` rather than recursing and
		// re-partitioning a single element at every one of the remaining levels
		// — for a 200M-leaf tree that shortcut is most of the running time.
		label := append([]byte(nil), leaves.Label(lo)...)
		h := leafHash(leaves.Value(lo))
		for level := treeDepth; level > depth; level-- {
			h = combine(h, label, level)
		}
		return h
	}

	mid := partition(leaves, lo, hi, depth)
	return join(
		subtree(leaves, lo, mid, depth+1),
		subtree(leaves, mid, hi, depth+1),
	)
}

// partition finds the first index in [lo, hi) whose bit at `depth` is 1. The
// leaves are sorted, so that boundary is found by binary search.
func partition(leaves Leaves, lo, hi, depth int) int {
	level := depth + 1
	for lo < hi {
		mid := lo + (hi-lo)/2
		if bitAt(leaves.Label(mid), level) == 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// TreeRootParallel is TreeRoot, sharded across cores.
//
// The top `shardDepth` levels are split into independent subtrees — the ranges
// are contiguous because the leaves are sorted — and the small top of the tree
// is joined afterwards. Rebuilding costs tens of billions of hashes, so this is
// the difference between minutes and an hour.
func TreeRootParallel(leaves Leaves, shardDepth int) ([]byte, error) {
	if shardDepth < 1 || shardDepth > 16 {
		return nil, fmt.Errorf("proton/tree: shard depth %d out of range", shardDepth)
	}
	n := leaves.Len()
	if n == 0 {
		return emptyNode, nil
	}
	if err := checkSorted(leaves); err != nil {
		return nil, err
	}

	shards := 1 << shardDepth
	bounds := make([]int, shards+1)
	bounds[0], bounds[shards] = 0, n
	// Each boundary is the first leaf whose top `shardDepth` bits reach a given
	// prefix; binary search keeps this cheap regardless of tree size.
	for s := 1; s < shards; s++ {
		bounds[s] = lowerBound(leaves, uint(s), shardDepth)
	}

	roots := make([][]byte, shards)
	sem := make(chan struct{}, treeWorkers())
	var wg sync.WaitGroup
	for s := 0; s < shards; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			roots[s] = subtree(leaves, bounds[s], bounds[s+1], shardDepth)
		}(s)
	}
	wg.Wait()

	// Join the shard roots into the top of the tree.
	for level := shardDepth; level > 0; level-- {
		next := make([][]byte, len(roots)/2)
		for i := range next {
			next[i] = join(roots[2*i], roots[2*i+1])
		}
		roots = next
	}
	return roots[0], nil
}

// lowerBound finds the first leaf whose top `bits` bits are >= prefix.
func lowerBound(leaves Leaves, prefix uint, bits int) int {
	lo, hi := 0, leaves.Len()
	for lo < hi {
		mid := lo + (hi-lo)/2
		if topBits(leaves.Label(mid), bits) < prefix {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

func topBits(label []byte, bits int) uint {
	var v uint
	for i := 1; i <= bits; i++ {
		v = v<<1 | uint(bitAt(label, i))
	}
	return v
}

// --- incremental updates ---------------------------------------------------

// Diff record layout, as Proton publishes it at epoch.N.diff: an operation byte
// followed by the same label and value as a tree record. Diffs are sorted by
// label, like the tree itself, which is what lets them be merged in one pass.
const (
	diffEntrySize = 1 + labelSize + valueSize // 69

	OpAdd    = 1
	OpRemove = 2
)

// ApplyDiff merges a published epoch diff into a sorted tree, writing the new
// sorted tree to out.
//
// This is what makes construction auditing affordable to run continuously: a
// full dump is ~13.6 GB, while one epoch's changes are a few megabytes. Both
// inputs are sorted by label, so this is a single linear merge.
//
// It also reports the mutations, because they are the audit's real subject. A
// removal is exactly the event an append-only chain of epoch hashes cannot show
// you, so the caller gets to judge whether each one was legitimate rather than
// having it silently folded into a new root.
func ApplyDiff(tree Leaves, diff []byte, out func(label, value []byte) error) (*DiffStats, error) {
	if len(diff)%diffEntrySize != 0 {
		return nil, fmt.Errorf("proton/tree: diff is %d bytes, not a whole number of %d-byte records",
			len(diff), diffEntrySize)
	}
	stats := &DiffStats{}

	nd := len(diff) / diffEntrySize
	dLabel := func(i int) []byte { return diff[i*diffEntrySize+1 : i*diffEntrySize+1+labelSize] }
	dValue := func(i int) []byte { return diff[i*diffEntrySize+1+labelSize : (i+1)*diffEntrySize] }
	dOp := func(i int) byte { return diff[i*diffEntrySize] }

	for i := 1; i < nd; i++ {
		if compare(dLabel(i-1), dLabel(i)) >= 0 {
			return nil, fmt.Errorf("proton/tree: diff not strictly ascending at record %d", i)
		}
	}

	i, j := 0, 0
	n := tree.Len()
	for i < n && j < nd {
		switch compare(tree.Label(i), dLabel(j)) {
		case -1:
			if err := out(tree.Label(i), tree.Value(i)); err != nil {
				return nil, err
			}
			i++
		case 0:
			// The label already exists. A remove drops it; an add here would be
			// an overwrite in place, which is not a legal mutation of an
			// append-only directory.
			switch dOp(j) {
			case OpRemove:
				stats.Removed++
				// The *tree's* value is recorded, not the diff record's. The tree
				// came out of a dump whose root was matched against a hash Proton
				// committed to, so its bytes are bound to something verified; the
				// diff is unaudited input that has not been checked against
				// anything yet. Dating a removal from the tree's copy therefore
				// keeps the judgement resting on verified data.
				stats.Removals = append(stats.Removals, Removal{
					Label: append([]byte(nil), tree.Label(i)...),
					Value: append([]byte(nil), tree.Value(i)...),
				})
				// The diff carries a value on a removal too, and it should be the
				// value being removed. When it is not, Proton's two publications
				// disagree with each other about what left the tree. That is a
				// discrepancy worth naming rather than an accusation: nothing here
				// says which of the two is wrong.
				if compare(tree.Value(i), dValue(j)) != 0 {
					stats.ValueMismatches++
				}
			case OpAdd:
				stats.Overwritten++
				if err := out(tree.Label(i), tree.Value(i)); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("proton/tree: unknown diff operation %d", dOp(j))
			}
			i++
			j++
		default: // tree label > diff label
			switch dOp(j) {
			case OpAdd:
				stats.Added++
				if err := out(dLabel(j), dValue(j)); err != nil {
					return nil, err
				}
			case OpRemove:
				// Removing something that is not there. Only the diff's own copy
				// of the value exists in this case, so anything derived from it is
				// weaker evidence than a real removal's — there is no tree entry to
				// corroborate it.
				stats.PhantomRemovals++
				stats.PhantomRemoved = append(stats.PhantomRemoved, Removal{
					Label: append([]byte(nil), dLabel(j)...),
					Value: append([]byte(nil), dValue(j)...),
				})
			default:
				return nil, fmt.Errorf("proton/tree: unknown diff operation %d", dOp(j))
			}
			j++
		}
	}
	for ; i < n; i++ {
		if err := out(tree.Label(i), tree.Value(i)); err != nil {
			return nil, err
		}
	}
	for ; j < nd; j++ {
		switch dOp(j) {
		case OpAdd:
			stats.Added++
			if err := out(dLabel(j), dValue(j)); err != nil {
				return nil, err
			}
		case OpRemove:
			stats.PhantomRemovals++
			stats.PhantomRemoved = append(stats.PhantomRemoved, Removal{
				Label: append([]byte(nil), dLabel(j)...),
				Value: append([]byte(nil), dValue(j)...),
			})
		}
	}
	return stats, nil
}

// DiffStats summarises one epoch's mutations.
//
// Added is ordinary. The other three are not: an overwrite in place, a removal,
// or a removal of something absent are all things a well-behaved append-only
// directory should not do, and none of them are visible from the epoch chain.
type DiffStats struct {
	Added           int
	Removed         int
	Overwritten     int
	PhantomRemovals int

	// ValueMismatches counts removals where the diff record's value differs from
	// the value actually sitting in the tree under that label — Proton's two
	// publications disagreeing about what was removed.
	ValueMismatches int

	// Removals are retained whole so each one can be judged rather than only
	// counted: Proton permits deletion within a retention window, and the value
	// carries the epoch the entry entered the tree, which is what makes that
	// judgement possible. See JudgeRemovals.
	Removals []Removal

	// PhantomRemoved are the removals of labels the tree did not contain, kept
	// apart because their values come from the diff alone.
	PhantomRemoved []Removal
}

// Removal is one leaf that left the tree, kept label and value together because
// the value is what dates it.
type Removal struct {
	Label []byte
	Value []byte
}

// Suspicious reports whether this epoch did anything an append-only directory
// should not.
func (d *DiffStats) Suspicious() bool {
	return d.Removed > 0 || d.Overwritten > 0 || d.PhantomRemovals > 0 || d.ValueMismatches > 0
}

// treeWorkers bounds how much of the machine a tree rebuild may take.
//
// This used to be runtime.NumCPU(), which meant the rebuild ran completely
// outside the CPU governor that paces everything else. The effect was visible
// the moment the history replay started: the governor measured total CPU at the
// budget, concluded it was over, and throttled the AKD backlog sweep from ~3.9
// permits to 1.4 — the paced work yielding all of its allowance to the unpaced
// work beside it. Two consumers, one governed, and the governed one loses.
//
// A static share rather than a governor permit, because the two are not the
// same shape. A permit bounds a ~37-second verification; a Proton rebuild runs
// for ~19 minutes, and holding a permit that long would starve the sweep just
// as thoroughly from the other direction. Capping the parallelism instead lets
// both run, with the rebuild taking a predictable slice.
//
// PROTON_TREE_WORKERS overrides it for an operator who wants the replay to
// finish sooner and is willing to give it the machine.
func treeWorkers() int {
	if v := os.Getenv("PROTON_TREE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	// A fixed four cores, not a fraction of the machine.
	//
	// A fraction looks more adaptive and scales the wrong way: the AKD sweep is
	// what benefits from a bigger box, while Proton's replay is a fixed amount
	// of work that finishes when it finishes. At 16 cores a quarter is 4; at 32
	// it would quietly become 8, handing the extra hardware to the one consumer
	// that cannot use it to reduce the backlog — and taking it from the one that
	// can. Four cores keeps a ~19-minute step at ~19 minutes on any host.
	const share = 4
	if n := runtime.NumCPU(); n < share {
		return maxInt(1, n)
	}
	return share
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
