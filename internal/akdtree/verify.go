// Package akdtree verifies AKD append-only proofs — the construction audit for
// Meta's and WhatsApp's key transparency logs.
//
// # Why a second implementation exists
//
// The witness already verifies these proofs with a Rust sidecar built on
// Meta's own `akd` crate, which is the reference and stays the authority. This
// package is not here to replace that judgement. It is here because the
// reference is slow in a way that is structural rather than incidental, and
// because the backlog it has to chew through is measured in hundreds of
// thousands of epochs.
//
// The reference builds the tree through a generic storage abstraction meant for
// a real database: every node is an object, written through an async in-memory
// map behind a mutex. Profiling one Meta epoch put the time in
// `recursive_batch_insert_nodes` → `TreeNode::write_to_storage` →
// `AsyncInMemoryDatabase::set`. Measured, that epoch costs ~13 microseconds per
// node against a hash costing 0.13 — a hundred to one on bookkeeping that
// verification does not need. The ratio test in docs/gpu_notes.md put the
// hashing at 6-7% of the runtime.
//
// So the arithmetic here is identical and the data structure is not: one sorted
// array, recursion over index ranges, no per-node allocation, no map.
//
// # What this must never be trusted to do alone
//
// A verifier that is wrong in the accepting direction approves a forged proof;
// one that is wrong in the rejecting direction accuses an honest operator of a
// fork, publicly and permanently. Both failures are worse than being slow.
//
// This runs alongside the reference, not instead of it. The witness compares
// the two and the reference decides, until this one has a long enough clean
// record to be worth arguing about. There is precedent: the Proton GPU rebuild
// shipped the same way, racing the GPU against the CPU and trusting agreement.
//
// # The algorithm, as the reference defines it
//
// An append-only proof between epochs carries two node sets: `unchanged`, which
// must rebuild the previous root, and `inserted`, which added to the first must
// rebuild the current one. Each set builds a compressed binary trie over node
// labels, hashed bottom-up. Auditor mode does not mix leaf epochs into node
// hashes, so an epoch only enters through the commitment applied to inserted
// values before the second build.
package akdtree

import (
	"encoding/binary"
	"fmt"
	"sort"

	"lukechampine.com/blake3"
)

// Digest is one hash. BLAKE3, not SHA-256: the configuration these logs use is
// akd's WhatsAppV1, whose hash function is blake3, and both Meta and WhatsApp
// publish under it.
type Digest = [32]byte

// Element is one (label, value) pair from a proof.
//
// Flat and copyable on purpose. The reference's equivalent is a heap object
// registered in a map; this is 40 bytes that sorts in place, and that
// difference is most of why this package exists.
type Element struct {
	Label [32]byte
	Len   uint32
	Value Digest
}

func hash(parts ...[]byte) Digest {
	h := blake3.New(32, nil)
	for _, p := range parts {
		h.Write(p)
	}
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

var (
	emptyValue = []byte{0}
	// emptyLabel is (0x01 repeated, length 0) — deliberately unequal to the
	// root label, which is zeros of length 0, so a missing child is
	// distinguishable from the root.
	emptyLabelVal = func() [32]byte {
		var b [32]byte
		for i := range b {
			b[i] = 1
		}
		return b
	}()
)

// labelValue is the hashed form of a label, which is what goes into a parent's
// hash: blake3(len_be32 || label_bytes).
func labelValue(label [32]byte, l uint32) Digest {
	var buf [36]byte
	binary.BigEndian.PutUint32(buf[0:4], l)
	copy(buf[4:], label[:])
	return hash(buf[:])
}

// parentHash combines two children: blake3( blake3(lv||ll) || blake3(rv||rl) ).
func parentHash(lv, ll, rv, rl Digest) Digest {
	left := hash(lv[:], ll[:])
	right := hash(rv[:], rl[:])
	return hash(left[:], right[:])
}

// HashLeafWithCommitment is applied to every inserted value before the second
// build: blake3(value || epoch_be64).
func HashLeafWithCommitment(v Digest, epoch uint64) Digest {
	var buf [40]byte
	copy(buf[:32], v[:])
	binary.BigEndian.PutUint64(buf[32:], epoch)
	return hash(buf[:])
}

func emptyRootValue() Digest { return hash(emptyValue) }

func emptyNodeHash() Digest {
	inner := hash(emptyValue)
	lv := labelValue(emptyLabelVal, 0)
	return hash(inner[:], lv[:])
}

func rootLabelValue() Digest {
	var zero [32]byte
	return labelValue(zero, 0)
}

// bitAt reads bit i of a label, most significant bit of byte 0 first.
func bitAt(label *[32]byte, i uint32) int {
	return int((label[i/8] >> (7 - i%8)) & 1)
}

// commonPrefixLen counts the leading bits two labels share, bounded by the
// shorter length.
func commonPrefixLen(a *Element, b *Element) uint32 {
	shorter := a.Len
	if b.Len < shorter {
		shorter = b.Len
	}
	var i uint32
	for i < shorter {
		// Whole-byte comparison while it is safe: labels are 32 bytes and most
		// pairs diverge late, so this is the difference between 256 bit tests
		// and a handful of byte compares.
		if i%8 == 0 && i+8 <= shorter {
			if a.Label[i/8] == b.Label[i/8] {
				i += 8
				continue
			}
		}
		if bitAt(&a.Label, i) != bitAt(&b.Label, i) {
			break
		}
		i++
	}
	return i
}

// prefixOf returns label truncated to len bits, with the remainder zeroed —
// the same normalisation the reference applies, and necessary because a label's
// bits beyond its length are not guaranteed to be zero.
func prefixOf(label [32]byte, l uint32) [32]byte {
	if l >= 256 {
		return label
	}
	var out [32]byte
	if l == 0 {
		return out
	}
	last := int((l - 1) / 8)
	rem := (l - 1) % 8
	copy(out[:last], label[:last])
	out[last] = (label[last] >> (7 - rem)) << (7 - rem)
	return out
}

// Sort orders elements the way the trie does: by label bits, then by length.
//
// The reference does not sort a mixed-length set at all — it re-partitions an
// unsorted vector at every level, allocating two new vectors each time. Sorting
// once turns the whole build into index arithmetic over one array, which is the
// single largest difference between the two implementations.
func Sort(elems []Element) {
	sort.Slice(elems, func(i, j int) bool {
		a, b := &elems[i], &elems[j]
		for k := 0; k < 32; k++ {
			if a.Label[k] != b.Label[k] {
				return a.Label[k] < b.Label[k]
			}
		}
		return a.Len < b.Len
	})
}

// Root builds the trie over elems and returns the tree's root hash.
//
// elems must be sorted by Sort. It is not copied and its order is relied upon:
// for a sorted set the longest common prefix of any range is the common prefix
// of its first and last element, which is what makes the recursion allocation-free.
func Root(elems []Element) (Digest, error) {
	if len(elems) == 0 {
		// An empty tree keeps the root's initial value rather than combining
		// two absent children.
		v := emptyRootValue()
		rl := rootLabelValue()
		return hash(v[:], rl[:]), nil
	}

	// The root's label is zero-length, so the split is on bit 0.
	split := sort.Search(len(elems), func(i int) bool {
		return bitAt(&elems[i].Label, 0) == 1
	})
	lv, ll, err := subtree(elems[:split], 0)
	if err != nil {
		return Digest{}, err
	}
	rv, rl, err := subtree(elems[split:], 0)
	if err != nil {
		return Digest{}, err
	}
	rootVal := parentHash(lv, ll, rv, rl)
	rlv := rootLabelValue()
	return hash(rootVal[:], rlv[:]), nil
}

// subtree returns the hash and hashed label of the node covering elems, which
// all share at least depth leading bits.
func subtree(elems []Element, depth uint32) (val, lab Digest, err error) {
	switch len(elems) {
	case 0:
		// No child on this side. The reference substitutes a fixed hash and the
		// empty label rather than skipping the term, so the shape of the parent
		// hash does not depend on how many children a node has.
		return emptyNodeHash(), labelValue(emptyLabelVal, 0), nil
	case 1:
		e := &elems[0]
		// A leaf's hash is its value: auditor mode does not mix in the epoch.
		return e.Value, labelValue(e.Label, e.Len), nil
	}

	lcp := commonPrefixLen(&elems[0], &elems[len(elems)-1])

	// An element whose label ends exactly at this node's label has no bit to
	// steer it left or right. The reference silently drops such an element
	// while partitioning and then rejects the proof for having dropped it,
	// because a dropped node is a committed value that never reached the tree —
	// which would let an append-only violation pass. Sorted, it can only be the
	// first element in the range.
	if elems[0].Len == lcp {
		return Digest{}, Digest{}, fmt.Errorf(
			"akdtree: element with label length %d sits on the interior node covering it; "+
				"a committed value would be dropped", lcp)
	}

	split := sort.Search(len(elems), func(i int) bool {
		return bitAt(&elems[i].Label, lcp) == 1
	})
	if split == 0 || split == len(elems) {
		// Impossible for a genuine longest common prefix: the elements must
		// differ at bit lcp by construction. Reaching here means the input was
		// not sorted as claimed.
		return Digest{}, Digest{}, fmt.Errorf(
			"akdtree: %d elements share %d bits but do not split there; input is not sorted",
			len(elems), lcp)
	}

	lv, ll, err := subtree(elems[:split], lcp+1)
	if err != nil {
		return Digest{}, Digest{}, err
	}
	rv, rl, err := subtree(elems[split:], lcp+1)
	if err != nil {
		return Digest{}, Digest{}, err
	}
	return parentHash(lv, ll, rv, rl), labelValue(prefixOf(elems[0].Label, lcp), lcp), nil
}

// VerifyAppendOnly checks one epoch transition.
//
// unchanged must rebuild prevRoot on its own, and unchanged plus inserted —
// each inserted value first committed to endEpoch — must rebuild currRoot. Both
// slices are modified in place (sorted, and inserted values replaced).
//
// It reports whether the proof holds. An error means this implementation could
// not reach a verdict, which is not the same as a proof being bad and must
// never be reported as one.
func VerifyAppendOnly(unchanged, inserted []Element, prevRoot, currRoot Digest, endEpoch uint64) (bool, error) {
	Sort(unchanged)
	got, err := Root(unchanged)
	if err != nil {
		return false, fmt.Errorf("rebuilding the previous root: %w", err)
	}
	if got != prevRoot {
		return false, nil
	}

	both := make([]Element, 0, len(unchanged)+len(inserted))
	both = append(both, unchanged...)
	for i := range inserted {
		e := inserted[i]
		e.Value = HashLeafWithCommitment(e.Value, endEpoch)
		both = append(both, e)
	}
	Sort(both)
	got, err = Root(both)
	if err != nil {
		return false, fmt.Errorf("rebuilding the current root: %w", err)
	}
	return got == currRoot, nil
}
