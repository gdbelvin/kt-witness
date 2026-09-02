package signal

import (
	"fmt"
	"sort"
)

// Signal's Implicit Binary Search Tree and proof guide, reimplemented from
// libsignal (rust/keytrans/src/implicit.rs and guide.rs).
//
// # Why a search needs a guide at all
//
// The log records every update in order, so all versions of one key are spread
// through it. Finding a particular version means a binary search over log
// entries — but a binary search the *server* drives is worthless, because a
// dishonest server would simply walk you to whichever entry it preferred.
//
// So the search path is not sent; it is *recomputed*. The client knows the
// key's first position and the tree size, which fix the search's root, and each
// step's direction is decided by the version counter found in the previous
// step's prefix proof. Given the same responses, everyone walks the same path.
// The server chooses the answers, never the questions.
//
// The tree is "implicit" because it is not stored anywhere: it is the same
// left-balanced numbering as the log tree, reinterpreted as a search tree over
// the range [pos, n). A node's children are found by stepping and then sliding
// back into range, which is what move_within does.

func isLeafNode(x uint64) bool { return x&1 == 0 }

// moveWithin slides x into [start, n) by descending: a node left of the range
// is replaced by its right child, one past the range by its left child.
func moveWithin(x, start, n uint64) (uint64, error) {
	for x < start || x >= n {
		var err error
		if x < start {
			x, err = rightStep(x)
		} else {
			x, err = leftStep(x)
		}
		if err != nil {
			return 0, err
		}
	}
	return x, nil
}

// searchRoot is the node a search over [start, n) begins at.
func searchRoot(start, n uint64) (uint64, error) {
	if start >= n {
		return 0, fmt.Errorf("signal/implicit: start %d must be less than n %d", start, n)
	}
	return moveWithin((1<<log2(n))-1, start, n)
}

func searchLeft(x, start, n uint64) (uint64, error) {
	s, err := leftStep(x)
	if err != nil {
		return 0, err
	}
	return moveWithin(s, start, n)
}

func searchRight(x, start, n uint64) (uint64, error) {
	s, err := rightStep(x)
	if err != nil {
		return 0, err
	}
	return moveWithin(s, start, n)
}

// frontier is the path down the right edge of the search tree, ending at the
// last entry. A search for the *most recent* version starts by reading the
// whole frontier, because the newest version is whatever the rightmost entries
// say it is.
func frontier(start, n uint64) ([]uint64, error) {
	last, err := searchRoot(start, n)
	if err != nil {
		return nil, err
	}
	out := []uint64{last}
	for last != n-1 {
		if last, err = searchRight(last, start, n); err != nil {
			return nil, err
		}
		out = append(out, last)
		if len(out) > 8*64 {
			// The frontier descends one level per step, so it cannot be longer
			// than the tree is deep; a longer one means the arithmetic is not
			// converging and looping forever would be worse than failing.
			return nil, fmt.Errorf("signal/implicit: frontier did not terminate")
		}
	}
	return out, nil
}

// proofGuide drives the binary search. Callers loop: poll, then look up the id
// it asks for, then insert the version counter found there.
type proofGuide struct {
	pos     uint64 // first occurrence of the key in the log
	n       uint64 // log size
	version uint32
	ids     []uint64 // ids the search has asked for, in order
	sorted  []versionedID
	// isFrontier is true while ids holds the frontier rather than a search path.
	isFrontier bool
}

type versionedID struct {
	id      uint64
	version uint32
}

// newProofGuide starts a search. version nil means "most recent".
func newProofGuide(version *uint32, pos, n uint64) (*proofGuide, error) {
	g := &proofGuide{pos: pos, n: n}
	if version == nil {
		f, err := frontier(pos, n)
		if err != nil {
			return nil, err
		}
		g.ids, g.isFrontier = f, true
		return g, nil
	}
	r, err := searchRoot(pos, n)
	if err != nil {
		return nil, err
	}
	g.version, g.ids = *version, []uint64{r}
	return g, nil
}

// poll reports whether the search is finished, and otherwise extends ids with
// the next node to look up.
func (g *proofGuide) poll() (bool, error) {
	if len(g.ids) > len(g.sorted) {
		return false, nil
	}
	sort.Slice(g.sorted, func(i, j int) bool { return g.sorted[i].id < g.sorted[j].id })

	// Version counters must not decrease as the log advances. A server that
	// serves a lower counter at a later entry is claiming a version was
	// un-published, which the format does not permit.
	for i := 1; i < len(g.sorted); i++ {
		if g.sorted[i-1].version > g.sorted[i].version {
			return false, fmt.Errorf("signal/implicit: version counters are not monotonic " +
				"(a later log entry reports fewer versions than an earlier one)")
		}
	}

	var last uint64
	if g.isFrontier {
		// The frontier is read first; the newest version is the one the
		// rightmost entry reports, and the search then looks for its earliest
		// occurrence.
		g.version = g.sorted[len(g.sorted)-1].version
		g.isFrontier = false
		found := false
		for _, v := range g.sorted {
			if v.version == g.version {
				last, found = v.id, true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("signal/implicit: no frontier entry matches the newest version")
		}
	} else {
		last = g.ids[len(g.ids)-1]
	}
	if isLeafNode(last) {
		return true, nil
	}

	var ctr uint32
	found := false
	for _, v := range g.sorted {
		if v.id == last {
			ctr, found = v.version, true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("signal/implicit: no proof step for node %d", last)
	}

	var next uint64
	var err error
	if ctr < g.version {
		// Not yet enough versions here: the one we want is further right.
		if last == g.n-1 {
			return true, nil
		}
		next, err = searchRight(last, g.pos, g.n)
	} else {
		if last == g.pos {
			return true, nil
		}
		next, err = searchLeft(last, g.pos, g.n)
	}
	if err != nil {
		return false, err
	}
	g.ids = append(g.ids, next)
	return false, nil
}

// nextID is the node the caller must supply a proof step for.
func (g *proofGuide) nextID() uint64 { return g.ids[len(g.sorted)] }

func (g *proofGuide) insert(id uint64, ctr uint32) {
	g.sorted = append(g.sorted, versionedID{id: id, version: ctr})
}

// result returns the index into ids of the step holding the answer, and that
// step's node id. It reports false when no entry has the version searched for,
// which means the key does not have it.
func (g *proofGuide) result() (int, uint64, bool) {
	// sorted is ordered by id and counters are monotonic in id, so the first
	// entry at or above the target version is the earliest occurrence of it.
	var smallest uint64
	found := false
	for _, v := range g.sorted {
		if v.version >= g.version {
			if v.version == g.version {
				smallest, found = v.id, true
			}
			break
		}
	}
	if !found {
		return 0, 0, false
	}
	for i, id := range g.ids {
		if id == smallest {
			return i, id, true
		}
	}
	return 0, 0, false
}
