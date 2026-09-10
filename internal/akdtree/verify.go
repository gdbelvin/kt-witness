// Package akdtree verifies AKD append-only proofs — the construction audit for
// Meta's and WhatsApp's key transparency logs.
//
// # Why a second implementation exists
//
// The witness used to verify these proofs with a Rust subprocess built on
// Meta's own `akd` crate — the reference implementation, and still the
// definition of what a correct answer is. This package was not written to
// dispute that definition. It was written because the reference is slow in a
// way that is structural rather than incidental, and because the backlog it
// had to chew through is measured in hundreds of thousands of epochs.
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
// # What it cost to be trusted alone
//
// A verifier that is wrong in the accepting direction approves a forged proof;
// one that is wrong in the rejecting direction accuses an honest operator of a
// fork, publicly and permanently. Both failures are worse than being slow.
//
// So this ran alongside the reference first, not instead of it: the witness
// compared the two and the reference decided, until the clean record was long
// enough to argue from. It is the only verifier left now, and the evidence it
// was promoted on is set out on internal/audit.GoVerifier — 104 epochs
// agreeing with roots Meta and WhatsApp published, 1000 mutation trials, 8.2
// million fuzz executions, and a shadow record in production. There is
// precedent for the shape of that promotion: the Proton GPU rebuild shipped
// the same way, racing the GPU against the CPU and trusting agreement.
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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/zeebo/blake3"
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

// The hash implementation is zeebo/blake3 rather than lukechampine's, measured
// rather than assumed — and the measurement was the opposite of the guess.
//
// Both ship assembly for amd64 and fall back to portable Go on arm64, so the
// expectation was that the x86 witness would be the quick one. It is not: a
// 64-byte hash costs 89 ns on an M4 in portable Go and 266 ns on the witness's
// 2.3 GHz Xeon with AVX2. The laptop is three times faster per hash than the
// server, which is worth remembering whenever a figure from one is quoted at
// the other.
//
// Between the two libraries, zeebo is 15% quicker on the laptop and 45% quicker
// on the Xeon — and the Xeon is where nearly all of this runs.

// hash is one-shot and allocation-free.
//
// The streaming form — New, Write, Sum(nil) — allocates a hasher and a result
// slice per call, and this is called four times per node. On a Meta proof that
// is fifteen million allocations, and the profile showed the cost not in the
// hashing but in the garbage collector's threads: kevent and pthread_cond_wait
// were 36% of the runtime, ahead of blake3 itself at 7%.
func hash2(a, b []byte) Digest {
	var buf [64]byte
	copy(buf[:32], a)
	copy(buf[32:], b)
	return blake3.Sum256(buf[:])
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
	return blake3.Sum256(buf[:])
}

// parentHash combines two children: blake3( blake3(lv||ll) || blake3(rv||rl) ).
func parentHash(lv, ll, rv, rl Digest) Digest {
	left := hash2(lv[:], ll[:])
	right := hash2(rv[:], rl[:])
	return hash2(left[:], right[:])
}

// HashLeafWithCommitment is applied to every inserted value before the second
// build: blake3(value || epoch_be64).
func HashLeafWithCommitment(v Digest, epoch uint64) Digest {
	var buf [40]byte
	copy(buf[:32], v[:])
	binary.BigEndian.PutUint64(buf[32:], epoch)
	return blake3.Sum256(buf[:])
}

// These three are constants of the configuration, so they are computed once.
//
// emptyNodeHash in particular is asked for at every childless branch — the
// commonest event in a sparse tree — and computing its three hashes each time
// was pure repetition of a fixed answer.
var (
	emptyRootValueV = blake3.Sum256(emptyValue)
	emptyNodeHashV  = func() Digest {
		inner := blake3.Sum256(emptyValue)
		lv := labelValue(emptyLabelVal, 0)
		return hash2(inner[:], lv[:])
	}()
	emptyLabelValueV = labelValue(emptyLabelVal, 0)
	rootLabelValueV  = func() Digest {
		var zero [32]byte
		return labelValue(zero, 0)
	}()
)

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
	slices.SortFunc(elems, func(a, b Element) int {
		c := bytes.Compare(a.Label[:], b.Label[:])
		if c != 0 {
			return c
		}
		return int(a.Len) - int(b.Len)
	})
}

// less is the same order, for the merge.
func less(a, b *Element) bool {
	c := bytes.Compare(a.Label[:], b.Label[:])
	if c != 0 {
		return c < 0
	}
	return a.Len < b.Len
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
		return hash2(emptyRootValueV[:], rootLabelValueV[:]), nil
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
	return hash2(rootVal[:], rootLabelValueV[:]), nil
}

// subtree returns the hash and hashed label of the node covering elems, which
// all share at least depth leading bits.
func subtree(elems []Element, depth uint32) (val, lab Digest, err error) {
	switch len(elems) {
	case 0:
		// No child on this side. The reference substitutes a fixed hash and the
		// empty label rather than skipping the term, so the shape of the parent
		// hash does not depend on how many children a node has.
		return emptyNodeHashV, emptyLabelValueV, nil
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

// A Verifier holds the scratch space for the merged node set.
//
// Reused across epochs on purpose. The merged set for a Meta proof is about
// 3.6 million elements — a quarter of a gigabyte — and allocating it per epoch
// put the garbage collector's madvise at 15% of the runtime. A worker verifies
// thousands of epochs in a row; it should allocate that buffer once.
//
// Not safe for concurrent use. Give each goroutine its own.
type Verifier struct {
	scratch []Element
}

// VerifyAppendOnly checks one epoch transition.
//
// unchanged must rebuild prevRoot on its own, and unchanged plus inserted —
// each inserted value first committed to endEpoch — must rebuild currRoot. Both
// slices are sorted in place.
//
// It reports whether the proof holds. An error means this implementation could
// not reach a verdict, which is not the same as a proof being bad and must
// never be reported as one.
func (v *Verifier) VerifyAppendOnly(unchanged, inserted []Element, prevRoot, currRoot Digest, endEpoch uint64) (bool, error) {
	prev, curr, err := v.Roots(unchanged, inserted, endEpoch)
	if err != nil {
		return false, err
	}
	return prev == prevRoot && curr == currRoot, nil
}

// Roots rebuilds both roots the proof asserts, and reports them rather than a
// verdict.
//
// This is the shape the distributed audit needs and VerifyAppendOnly is not.
// A machine that is handed the published roots and answers yes or no has been
// told the answer; a machine that reports what it computed has not, and cannot
// produce a credible result without doing the work. Every remote worker already
// works this way. The witness's own local worker did not — it called
// VerifyAppendOnly and then reported the PUBLISHED current root as both of its
// computed roots, so every epoch it verified successfully came back as a
// mismatch against the published previous root, was recorded unverified, and
// was re-queued. Days of the witness's own Meta verification produced nothing
// but false negatives, at the cost of the bandwidth that is the scarce resource
// here.
//
// prev is the root of the unchanged nodes alone; curr is the root of those plus
// the inserted nodes with each value committed to endEpoch. That pair IS the
// append-only assertion, and comparing it to what the operator published is the
// caller's job — which is the point.
//
// inserted is modified in place: its values are replaced by their commitments.
func (v *Verifier) Roots(unchanged, inserted []Element, endEpoch uint64) (prev, curr Digest, err error) {
	Sort(unchanged)
	prev, err = Root(unchanged)
	if err != nil {
		return Digest{}, Digest{}, fmt.Errorf("rebuilding the previous root: %w", err)
	}

	// Commit each inserted value to the epoch, then MERGE rather than
	// concatenate and re-sort. Both inputs are sorted by this point, so the
	// combined order costs one linear pass instead of a second n log n over a
	// set that is mostly the same elements in the same order.
	for i := range inserted {
		inserted[i].Value = HashLeafWithCommitment(inserted[i].Value, endEpoch)
	}
	Sort(inserted)

	n := len(unchanged) + len(inserted)
	if cap(v.scratch) < n {
		v.scratch = make([]Element, n)
	}
	both := v.scratch[:n]
	merge(both, unchanged, inserted)

	curr, err = Root(both)
	if err != nil {
		return Digest{}, Digest{}, fmt.Errorf("rebuilding the current root: %w", err)
	}
	return prev, curr, nil
}

// VerifyAppendOnly is the one-shot form, for callers that verify a single
// epoch and do not want to hold scratch space.
func VerifyAppendOnly(unchanged, inserted []Element, prevRoot, currRoot Digest, endEpoch uint64) (bool, error) {
	var v Verifier
	return v.VerifyAppendOnly(unchanged, inserted, prevRoot, currRoot, endEpoch)
}

// merge writes the ordered union of two sorted slices into out.
func merge(out, a, b []Element) {
	i, j, k := 0, 0, 0
	for i < len(a) && j < len(b) {
		if less(&a[i], &b[j]) {
			out[k] = a[i]
			i++
		} else {
			out[k] = b[j]
			j++
		}
		k++
	}
	k += copy(out[k:], a[i:])
	copy(out[k:], b[j:])
}

// ParseDigest reads a 64-character hex root.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != 64 {
		return d, fmt.Errorf("akdtree: root is %d hex chars, want 64", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return d, fmt.Errorf("akdtree: root is not hex: %w", err)
	}
	copy(d[:], b)
	return d, nil
}
