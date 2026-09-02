package signal

import (
	"fmt"
	"sort"

	"github.com/gdbsecurity/kt-witness/internal/vrf"
)

// Search-proof verification, reimplemented from libsignal
// (rust/keytrans/src/verify.rs, verify_search_internal).
//
// # What this adds over witnessing tree heads
//
// Everything else in this package establishes that Signal's log is one
// append-only history that Signal and its auditors agree on. That is real, and
// it is what catches equivocation — but it is entirely about the *shape* of the
// log. It would hold just as well if the log's contents were nonsense, because
// nothing so far has opened a single entry.
//
// A search proof opens one. It chains four independent facts:
//
//  1. VRF: the identifier maps to exactly one index, and Signal cannot choose
//     which. (RFC 9381; see internal/vrf.)
//  2. Prefix tree: at that index, and only that index, sits a leaf recording
//     how many versions the key has and where it first appeared.
//  3. Log tree: the entries the search visited are genuinely in the log, at the
//     positions the search — which we recompute, not Signal — says to visit.
//  4. Commitment: the entry we landed on opens to the value Signal claims, for
//     the key we asked about.
//
// Break any link and the chain fails. Together they promote "Signal's log is
// consistent" to "Signal's log genuinely says X about this identifier".
//
// # What it is not
//
// This is a *spot check*, not a construction audit. Signal's proofs are
// per-label: they answer questions about identifiers the asker can already
// name, and the whole design goal of the VRF is that a third party cannot
// enumerate the rest. So verifying every search proof we can obtain still
// leaves the vast majority of the directory unexamined — unlike Proton, where
// the full leaf set is published and the entire tree can be rebuilt.
//
// The witness therefore does not claim tier B for Signal on the strength of
// this. It claims tier A plus a continuously verified spot check, which is what
// the evidence supports. Full coverage needs Signal's auditor feed.

// SearchResult is a verified answer about one identifier.
type SearchResult struct {
	// Index is the VRF output: the identifier's position in the prefix tree.
	Index hash
	// Root is the log root the proof implies. Callers must compare it against a
	// root authenticated some other way — deriving a root is not the same as
	// verifying one.
	Root hash
	// Pos is where the identifier first appears in the log.
	Pos uint64
	// Version is the version counter of the entry the search landed on.
	Version uint32
	// Value is the committed value: for KT, a serialized public key.
	Value []byte
	// Entries is how many log entries the search had to open.
	Entries int
}

// verifySearch checks a CondensedTreeSearchResponse for searchKey against a log
// of treeSize entries, and returns the log root the proof implies.
//
// version selects which version of the key to search for; nil means the most
// recent. No root is checked here on purpose: this function's job is to say
// what root the proof *demands*, and the caller compares that against the root
// it has independently authenticated.
func verifySearch(vrfKey *vrf.PublicKey, searchKey []byte, version *uint32,
	condensed message, treeSize uint64) (*SearchResult, error) {

	if treeSize == 0 || treeSize > 1<<62 {
		// Above 2^62 the node arithmetic (2*(n-1)+1) overflows, so a server
		// could pick a size that makes the tree math misbehave rather than fail.
		return nil, fmt.Errorf("signal/search: tree size %d out of range", treeSize)
	}

	vrfProof := first(condensed, 1)
	if len(vrfProof) == 0 {
		return nil, fmt.Errorf("signal/search: response has no VRF proof")
	}
	out, err := vrfKey.ProofToHash(searchKey, vrfProof)
	if err != nil {
		return nil, fmt.Errorf("signal/search: VRF proof for %q: %w", searchKey, err)
	}
	var index hash
	copy(index[:], out)

	searchRaw := first(condensed, 2)
	if searchRaw == nil {
		return nil, fmt.Errorf("signal/search: response has no search proof")
	}
	sp := parse(searchRaw)
	pos := varintOf(sp, 1)
	if pos >= treeSize {
		return nil, fmt.Errorf("signal/search: first position %d is beyond tree size %d", pos, treeSize)
	}

	steps := sp[2]
	guide, err := newProofGuide(version, pos, treeSize)
	if err != nil {
		return nil, fmt.Errorf("signal/search: %w", err)
	}

	// Walk the search. The guide decides which entries to open; the response
	// only supplies the proofs. A response with more steps than the search asks
	// for is rejected below, so the server cannot smuggle in extra leaves to
	// steer the batch proof.
	type opened struct {
		id         uint64
		leaf       hash
		commitment []byte
		counter    uint32
	}
	var visited []opened
	i := 0
	for {
		done, err := guide.poll()
		if err != nil {
			return nil, fmt.Errorf("signal/search: %w", err)
		}
		if done {
			break
		}
		if i >= len(steps) {
			return nil, fmt.Errorf("signal/search: proof ended after %d steps but the search needs more", i)
		}
		id := guide.nextID()

		step := parse(steps[i])
		prefixRaw := first(step, 1)
		if prefixRaw == nil {
			return nil, fmt.Errorf("signal/search: step %d has no prefix proof", i)
		}
		pp := parse(prefixRaw)
		ctr := uint32(varintOf(pp, 2))
		proof := make([]hash, 0, len(pp[1]))
		for _, p := range pp[1] {
			if len(p) != 32 {
				return nil, fmt.Errorf("signal/search: step %d prefix hash is %d bytes, want 32", i, len(p))
			}
			var h hash
			copy(h[:], p)
			proof = append(proof, h)
		}
		prefixRoot, err := evaluatePrefixProof(index, ctr, pos, proof)
		if err != nil {
			return nil, fmt.Errorf("signal/search: step %d: %w", i, err)
		}

		commitment := first(step, 2)
		if len(commitment) != 32 {
			return nil, fmt.Errorf("signal/search: step %d commitment is %d bytes, want 32", i, len(commitment))
		}
		var c hash
		copy(c[:], commitment)

		guide.insert(id, ctr)
		visited = append(visited, opened{id: id, leaf: logLeafHash(prefixRoot, c), commitment: commitment, counter: ctr})
		i++
	}
	if i != len(steps) {
		return nil, fmt.Errorf("signal/search: proof has %d steps but the search visits %d entries",
			len(steps), i)
	}

	// The batch inclusion proof: every entry the search opened is genuinely in
	// the log of treeSize entries. The proof's length is fixed by the entry ids,
	// so there is no room to pad it into producing a chosen root.
	byID := append([]opened(nil), visited...)
	sort.Slice(byID, func(a, b int) bool { return byID[a].id < byID[b].id })
	ids := make([]uint64, len(byID))
	values := make([]hash, len(byID))
	for n, v := range byID {
		ids[n], values[n] = v.id, v.leaf
	}
	inclusion := make([]hash, 0, len(sp[3]))
	for _, p := range sp[3] {
		if len(p) != 32 {
			return nil, fmt.Errorf("signal/search: inclusion hash is %d bytes, want 32", len(p))
		}
		var h hash
		copy(h[:], p)
		inclusion = append(inclusion, h)
	}
	root, err := evaluateBatchProof(ids, treeSize, values, inclusion)
	if err != nil {
		return nil, fmt.Errorf("signal/search: inclusion: %w", err)
	}

	resultIdx, _, ok := guide.result()
	if !ok {
		return nil, fmt.Errorf("signal/search: the log does not contain the requested version of %q", searchKey)
	}
	if resultIdx >= len(visited) {
		return nil, fmt.Errorf("signal/search: result index %d out of range", resultIdx)
	}
	answer := visited[resultIdx]

	// Finally, open the commitment. Until this passes, everything above is about
	// an opaque index; this is what ties it to the identifier and the value.
	valueRaw := first(condensed, 4)
	if valueRaw == nil {
		return nil, fmt.Errorf("signal/search: response has no value")
	}
	value := first(parse(valueRaw), 1)
	opening := first(condensed, 3)
	if !verifyCommitment(searchKey, answer.commitment, marshalUpdateValue(value), opening) {
		return nil, fmt.Errorf("signal/search: the commitment at entry %d does not open to the value served for %q",
			answer.id, searchKey)
	}

	return &SearchResult{
		Index:   index,
		Root:    root,
		Pos:     pos,
		Version: answer.counter,
		Value:   value,
		Entries: len(visited),
	}, nil
}
