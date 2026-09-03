package proton

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"sort"
	"testing"
)

// referenceRoot mirrors Proton's own C verifier (kt-auditor, compute_proof_level):
// build every node at level 256, then repeatedly combine each level into the one
// above, pairing a node with the next entry only when they are true siblings and
// otherwise hashing against 32 zero bytes.
//
// It is deliberately a different shape from the implementation under test —
// level-by-level and materialised, rather than recursive over ranges — so
// agreement between them is evidence rather than a restatement.
func referenceRoot(t *testing.T, leaves Leaves) []byte {
	t.Helper()

	type node struct {
		label []byte
		value []byte
	}
	n := leaves.Len()
	if n == 0 {
		return emptyNode
	}
	cur := make([]node, n)
	for i := 0; i < n; i++ {
		cur[i] = node{
			label: append([]byte(nil), leaves.Label(i)...),
			value: leafHash(leaves.Value(i)),
		}
	}

	for level := treeDepth; level > 0; level-- {
		var next []node
		for i := 0; i < len(cur); i++ {
			var buf [hashSize * 2]byte // zero-initialised: an absent sibling is zero
			if bitAt(cur[i].label, level) == 0 {
				copy(buf[:hashSize], cur[i].value)
				if i+1 < len(cur) && sharePrefix(cur[i].label, cur[i+1].label, level-1) {
					i++
					copy(buf[hashSize:], cur[i].value)
				}
			} else {
				copy(buf[hashSize:], cur[i].value)
			}
			sum := sha256.Sum256(buf[:])
			next = append(next, node{label: cur[i].label, value: sum[:]})
		}
		cur = next
	}
	if len(cur) != 1 {
		t.Fatalf("reference tree collapsed to %d roots, want 1", len(cur))
	}
	return cur[0].value
}

// sharePrefix reports whether two labels agree on their first `bits` bits.
func sharePrefix(a, b []byte, bits int) bool {
	full := bits / 8
	if !bytes.Equal(a[:full], b[:full]) {
		return false
	}
	if rem := bits % 8; rem != 0 {
		return a[full]>>(8-rem) == b[full]>>(8-rem)
	}
	return true
}

// buildLeaves makes a sorted, deduplicated leaf set in the published layout.
func buildLeaves(t *testing.T, rng *rand.Rand, n int, prefixBits int) SliceLeaves {
	t.Helper()
	seen := map[string]bool{}
	labels := make([][]byte, 0, n)
	for len(labels) < n {
		l := make([]byte, labelSize)
		rng.Read(l)
		// Optionally force a shared prefix so deep, dense subtrees get exercised
		// rather than only the sparse random case.
		for i := 0; i < prefixBits/8; i++ {
			l[i] = 0
		}
		if seen[string(l)] {
			continue
		}
		seen[string(l)] = true
		labels = append(labels, l)
	}
	sort.Slice(labels, func(i, j int) bool { return bytes.Compare(labels[i], labels[j]) < 0 })

	buf := make([]byte, 0, n*entrySize)
	for i, l := range labels {
		v := make([]byte, valueSize)
		rng.Read(v[:32])
		binary.BigEndian.PutUint32(v[32:], uint32(i))
		buf = append(buf, l...)
		buf = append(buf, v...)
	}
	return SliceLeaves(buf)
}

// The central check: the recursive implementation must agree with a
// level-by-level rebuild that follows Proton's C verifier.
func TestTreeRootMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, tc := range []struct {
		name       string
		n          int
		prefixBits int
	}{
		{"single leaf", 1, 0},
		{"two leaves", 2, 0},
		{"sparse", 17, 0},
		{"dense shared prefix", 40, 16},
		{"deeper shared prefix", 33, 24},
		{"larger", 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaves := buildLeaves(t, rng, tc.n, tc.prefixBits)
			want := referenceRoot(t, leaves)
			got, err := TreeRoot(leaves)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("root mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// Sharding must not change the answer.
func TestParallelRootMatchesSerial(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	leaves := buildLeaves(t, rng, 500, 0)
	want, err := TreeRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, depth := range []int{1, 4, 8} {
		got, err := TreeRootParallel(leaves, depth)
		if err != nil {
			t.Fatalf("shard depth %d: %v", depth, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shard depth %d changed the root\n got %x\nwant %x", depth, got, want)
		}
	}
}

// An empty subtree is zero at every depth — the property that makes a lonely
// leaf cost a hash per level, and the easiest thing to get wrong.
func TestEmptyTreeIsZero(t *testing.T) {
	got, err := TreeRoot(SliceLeaves(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, hashSize)) {
		t.Fatalf("empty tree root is %x, want 32 zero bytes", got)
	}
}

// Changing any leaf must change the root; a construction audit that misses a
// mutated binding would be worthless.
func TestEveryLeafAffectsTheRoot(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	leaves := buildLeaves(t, rng, 24, 0)
	base, err := TreeRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < leaves.Len(); i++ {
		mutated := append(SliceLeaves(nil), leaves...)
		mutated[i*entrySize+labelSize] ^= 0xFF // flip a byte of the value
		got, err := TreeRoot(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, base) {
			t.Fatalf("mutating leaf %d left the root unchanged", i)
		}
	}
}

// Removing a leaf must change the root. This is the attack an append-only chain
// of epoch hashes cannot see: the map is mutable, so a binding can be dropped
// while the chain stays perfectly consistent.
func TestRemovingALeafChangesTheRoot(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	leaves := buildLeaves(t, rng, 30, 0)
	base, err := TreeRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, drop := range []int{0, 13, 29} {
		short := append(SliceLeaves(nil), leaves[:drop*entrySize]...)
		short = append(short, leaves[(drop+1)*entrySize:]...)
		got, err := TreeRoot(short)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, base) {
			t.Fatalf("removing leaf %d left the root unchanged", drop)
		}
	}
}

// Unsorted input must be rejected rather than silently producing a wrong root:
// the whole method depends on ordering.
func TestUnsortedLeavesRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	leaves := buildLeaves(t, rng, 8, 0)
	swapped := append(SliceLeaves(nil), leaves...)
	a := swapped[0:entrySize]
	b := swapped[entrySize : 2*entrySize]
	tmp := append([]byte(nil), a...)
	copy(a, b)
	copy(b, tmp)

	if _, err := TreeRoot(swapped); err == nil {
		t.Fatal("unsorted leaves must be rejected")
	}
}

// Pins the bit order. Level 1 is the most significant bit of byte 0; getting
// this backwards produces a plausible-looking but entirely wrong tree.
func TestBitOrderIsMSBFirst(t *testing.T) {
	label, _ := hex.DecodeString("80" + "00000000000000000000000000000000000000000000000000000000000000")
	if bitAt(label, 1) != 1 {
		t.Fatal("level 1 must read the most significant bit of byte 0")
	}
	if bitAt(label, 2) != 0 {
		t.Fatal("level 2 must read the next bit down")
	}
	label2, _ := hex.DecodeString("01" + "00000000000000000000000000000000000000000000000000000000000000")
	if bitAt(label2, 8) != 1 {
		t.Fatal("level 8 must read the least significant bit of byte 0")
	}
}

// helper: run ApplyDiff into a fresh SliceLeaves
func applyDiff(t *testing.T, tree SliceLeaves, diff []byte) (SliceLeaves, *DiffStats) {
	t.Helper()
	var out []byte
	stats, err := ApplyDiff(tree, diff, func(label, value []byte) error {
		out = append(out, label...)
		out = append(out, value...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return SliceLeaves(out), stats
}

func diffRecord(op byte, label, value []byte) []byte {
	r := []byte{op}
	r = append(r, label...)
	return append(r, value...)
}

// An added leaf must land in the merged tree and change the root — otherwise a
// construction audit would confirm a tree that does not contain the update.
func TestApplyDiffAddsLeaves(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	tree := buildLeaves(t, rng, 20, 0)
	extra := buildLeaves(t, rng, 3, 0)

	var diff []byte
	for i := 0; i < extra.Len(); i++ {
		diff = append(diff, diffRecord(OpAdd, extra.Label(i), extra.Value(i))...)
	}

	merged, stats := applyDiff(t, tree, diff)
	if stats.Added != 3 || stats.Suspicious() {
		t.Fatalf("want 3 clean additions, got %+v", stats)
	}
	if merged.Len() != 23 {
		t.Fatalf("merged tree has %d leaves, want 23", merged.Len())
	}
	if _, err := TreeRoot(merged); err != nil {
		t.Fatalf("merged tree is not well formed: %v", err)
	}
}

// The mutation an append-only chain of epoch hashes cannot reveal. It must be
// reported, not silently folded into a new root.
func TestApplyDiffReportsRemovals(t *testing.T) {
	rng := rand.New(rand.NewSource(22))
	tree := buildLeaves(t, rng, 12, 0)

	diff := diffRecord(OpRemove, tree.Label(4), tree.Value(4))
	merged, stats := applyDiff(t, tree, diff)

	if stats.Removed != 1 || !stats.Suspicious() {
		t.Fatalf("a removal must be reported as suspicious, got %+v", stats)
	}
	if merged.Len() != 11 {
		t.Fatalf("merged tree has %d leaves, want 11", merged.Len())
	}
	if len(stats.Removals) != 1 || !bytes.Equal(stats.Removals[0].Label, tree.Label(4)) {
		t.Fatal("the removed label must be retained so it can be examined")
	}
	// The value comes from the tree, which is the copy bound to a verified root.
	if !bytes.Equal(stats.Removals[0].Value, tree.Value(4)) {
		t.Fatal("the removed leaf's value must be retained so the removal can be dated")
	}
	if stats.ValueMismatches != 0 {
		t.Fatal("the diff named the value that was actually there; that is not a mismatch")
	}

	before, _ := TreeRoot(tree)
	after, _ := TreeRoot(merged)
	if bytes.Equal(before, after) {
		t.Fatal("removing a binding must change the root")
	}
}

// Re-adding an existing label is an overwrite in place, which a well-behaved
// append-only directory should never do.
func TestApplyDiffReportsOverwrite(t *testing.T) {
	rng := rand.New(rand.NewSource(23))
	tree := buildLeaves(t, rng, 10, 0)

	newValue := make([]byte, valueSize)
	rng.Read(newValue)
	diff := diffRecord(OpAdd, tree.Label(3), newValue)

	_, stats := applyDiff(t, tree, diff)
	if stats.Overwritten != 1 || !stats.Suspicious() {
		t.Fatalf("an in-place overwrite must be reported, got %+v", stats)
	}
}

func TestApplyDiffRejectsMalformed(t *testing.T) {
	rng := rand.New(rand.NewSource(24))
	tree := buildLeaves(t, rng, 5, 0)

	if _, err := ApplyDiff(tree, make([]byte, 7), func([]byte, []byte) error { return nil }); err == nil {
		t.Fatal("a diff of the wrong length must be rejected")
	}

	// Out-of-order diff records would silently corrupt the merge.
	bad := append(diffRecord(OpAdd, tree.Label(4), tree.Value(4)),
		diffRecord(OpAdd, tree.Label(1), tree.Value(1))...)
	if _, err := ApplyDiff(tree, bad, func([]byte, []byte) error { return nil }); err == nil {
		t.Fatal("an unsorted diff must be rejected")
	}
}

// The merged tree must still be sorted, or the next epoch's audit silently
// computes a wrong root.
func TestApplyDiffKeepsTreeSorted(t *testing.T) {
	rng := rand.New(rand.NewSource(25))
	tree := buildLeaves(t, rng, 40, 0)
	extra := buildLeaves(t, rng, 15, 0)

	var recs [][]byte
	for i := 0; i < extra.Len(); i++ {
		recs = append(recs, diffRecord(OpAdd, extra.Label(i), extra.Value(i)))
	}
	sort.Slice(recs, func(i, j int) bool { return bytes.Compare(recs[i][1:33], recs[j][1:33]) < 0 })
	var diff []byte
	for _, r := range recs {
		diff = append(diff, r...)
	}

	merged, _ := applyDiff(t, tree, diff)
	if err := checkSorted(merged); err != nil {
		t.Fatalf("merged tree is not sorted: %v", err)
	}
}
