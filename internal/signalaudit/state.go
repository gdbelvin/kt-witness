package signalaudit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/gdbsecurity/kt-witness/internal/source/signal"
)

// ProofError is an update that is well formed but does not follow from the
// state before it: its proof does not reproduce our prefix root, or it claims
// a transition the protocol forbids at this point (a second NewTree, say).
//
// That is not noise. Signal signs tree heads over exactly this history, so an
// update that contradicts the previous root is Signal presenting two different
// directories — the event an auditor exists to catch. The spec's instruction
// is to stop: process nothing further and sign nothing further.
type ProofError struct {
	Pos    uint64    // log position the update would have occupied
	Proof  ProofKind // which proof variant it carried
	Reason string
}

func (e *ProofError) Error() string {
	return fmt.Sprintf("signalaudit: update %d (%v) contradicts the log: %s", e.Pos, e.Proof, e.Reason)
}

// State is everything an auditor has to remember between updates: how many
// updates it has applied, the prefix-tree root after the last of them, and the
// log tree's frontier. The zero value is the empty log, ready for NewTree.
type State struct {
	prefixRoot [HashSize]byte
	log        signal.LogFrontier // its size is the update count
}

// Size is the number of updates applied, which is also the log tree size.
func (s *State) Size() uint64 { return s.log.Size() }

// PrefixRoot is the prefix-tree root after the last applied update; ok is
// false for the empty state, which has none.
func (s *State) PrefixRoot() (root [HashSize]byte, ok bool) {
	return s.prefixRoot, s.Size() > 0
}

// LogRoot is the log-tree root over every applied update — the value Signal
// signs, and that an auditor countersigns.
func (s *State) LogRoot() ([HashSize]byte, error) {
	if s.Size() == 0 {
		return [HashSize]byte{}, errors.New("signalaudit: no updates applied, so no log root")
	}
	return s.log.Root()
}

// Clone returns an independent copy.
func (s *State) Clone() State {
	return State{prefixRoot: s.prefixRoot, log: s.log.Clone()}
}

// Apply checks u against the current state and, only if every check passes,
// advances the state by one entry. On any error the state is unchanged: the
// new roots are computed into locals and committed together at the end, so a
// rejected update cannot leave half of itself behind.
func (s *State) Apply(u Update) error {
	if err := u.validate(); err != nil {
		return err
	}
	pos := s.Size()
	fail := func(format string, args ...any) error {
		return &ProofError{Pos: pos, Proof: u.Proof, Reason: fmt.Sprintf(format, args...)}
	}

	var next [HashSize]byte
	switch u.Proof {
	case NewTree:
		// Spec, "newTree proofs": there is no previous root, so the update is
		// accepted unconditionally — but only "as long as the auditor agrees
		// that the tree is, indeed, empty". A NewTree later on would discard
		// every key in the directory. Reference: prefix/mod.rs apply_update.
		if pos != 0 {
			return fail("new_tree proof for a tree that already has %d entries", pos)
		}
		// The first leaf: counter 0, first seen at position 0, every sibling
		// a stand-in from the update's seed.
		next = realRoot(u.Index, 0, 0, nil, u.Seed)

	case DifferentKey:
		// Reference: prefix/mod.rs, PrefixTreeUpdate::DifferentKey.
		if pos == 0 {
			return fail("first update must be new_tree")
		}
		// Non-inclusion: walking the new index's path down the copath ends at
		// a stand-in, regenerated from old_seed at that depth. If that walk
		// reproduces our root, the index had no leaf — the path left the
		// explored part of the tree before reaching one. Spec, "Calculating
		// previous prefix tree root hashes / differentKey proofs".
		if got := fakeRoot(u.Index, u.Copath, u.OldSeed); got != s.prefixRoot {
			return fail("non-inclusion proof gives prefix root %x, ours is %x", got, s.prefixRoot)
		}
		if u.Real {
			// The stand-in becomes a fresh subtree holding the new leaf:
			// counter 0, first seen at this very position, with stand-ins from
			// the new seed below the point of divergence. The position comes
			// from our own count, not from Signal, so a leaf cannot claim to
			// have been inserted anywhere else. Spec, "Calculating new prefix
			// tree root hashes / differentKey proofs".
			next = realRoot(u.Index, 0, pos, u.Copath, u.Seed)
		} else {
			// A fake update swaps the stand-in for another stand-in at the same
			// depth: the tree's explored shape is unchanged, and an observer of
			// roots alone cannot tell this entry from a real insert.
			next = fakeRoot(u.Index, u.Copath, u.Seed)
		}

	case SameKey:
		// Reference: prefix/mod.rs, PrefixTreeUpdate::SameKey.
		if pos == 0 {
			return fail("first update must be new_tree")
		}
		// Inclusion: the existing leaf (index, counter, position) under the
		// copath, padded below the explored part with stand-ins from the
		// update's seed. The seed is the one the key was inserted with — an
		// update to an existing key never regenerates stand-ins — so the same
		// padded copath serves the old root and the new. Spec, "sameKey
		// proofs".
		path := padCopath(u.Copath, u.Seed)
		if got := fold(signal.PrefixLeafHash(u.Index, u.Counter, u.Position), u.Index, path[:]); got != s.prefixRoot {
			return fail("inclusion proof for counter %d at position %d gives prefix root %x, ours is %x",
				u.Counter, u.Position, got, s.prefixRoot)
		}
		// Proven to be at the maximum, the counter has nowhere to go; a
		// wrapped counter would collide with the key's first version.
		if u.Counter == math.MaxUint32 {
			return fail("counter would overflow")
		}
		// The position stays: it records where the key *first* appeared,
		// which is what lets a client bound its binary search.
		next = fold(signal.PrefixLeafHash(u.Index, u.Counter+1, u.Position), u.Index, path[:])
	}

	// Spec, "Log tree": the leaf binds the new prefix root to the commitment.
	// The commitment cannot be opened here (that needs the search key), so it
	// is not checked — but it is fixed, and a client who later opens it is
	// checking it against the root we countersigned.
	// Reference: transparency/mod.rs, log_leaf.
	//
	// Append fails only when the size would overflow, and then before it
	// changes anything, so committing the prefix root after it is atomic.
	if err := s.log.Append(signal.LogLeafHash(next, u.Commitment)); err != nil {
		return fail("%v", err)
	}
	s.prefixRoot = next
	return nil
}

// bit is bit i of the index, most significant bit of each byte first: the
// direction taken at depth i on the way down.
func bit(index *[IndexSize]byte, i int) byte { return index[i/8] >> (7 - i%8) & 1 }

// fold hashes value, which sits at depth len(copath) on the index's path, up to
// the root. copath[i] is the sibling at depth i+1 and goes on the side bit i
// does not.
func fold(value [HashSize]byte, index [IndexSize]byte, copath [][HashSize]byte) [HashSize]byte {
	for i := len(copath) - 1; i >= 0; i-- {
		if bit(&index, i) == 0 {
			value = signal.PrefixParentHash(value, copath[i])
		} else {
			value = signal.PrefixParentHash(copath[i], value)
		}
	}
	return value
}

// fakeRoot is the root with a stand-in at depth len(copath) on the index's
// path. Its level byte is depth-1 (spec, "Stand-in hashes"). Callers have
// ensured 1 <= len(copath) <= 256.
func fakeRoot(index [IndexSize]byte, copath [][HashSize]byte, seed [SeedSize]byte) [HashSize]byte {
	return fold(signal.PrefixStandInHash(seed, uint8(len(copath)-1)), index, copath)
}

// padCopath extends an explored copath to the full depth with stand-ins: the
// sibling at depth i+1 that nobody has explored is PrefixStandInHash(seed, i).
func padCopath(copath [][HashSize]byte, seed [SeedSize]byte) (out [MaxCopath][HashSize]byte) {
	n := copy(out[:], copath)
	for i := n; i < MaxCopath; i++ {
		out[i] = signal.PrefixStandInHash(seed, uint8(i))
	}
	return out
}

// realRoot is the root with a leaf for (index, ctr, pos) at depth 256.
func realRoot(index [IndexSize]byte, ctr uint32, pos uint64, copath [][HashSize]byte, seed [SeedSize]byte) [HashSize]byte {
	path := padCopath(copath, seed)
	return fold(signal.PrefixLeafHash(index, ctr, pos), index, path[:])
}

// stateJSON is the persisted form. Hex rather than base64 so an operator can
// compare a root against Signal's or another auditor's by eye.
type stateJSON struct {
	Size        uint64   `json:"size"`
	PrefixRoot  string   `json:"prefix_root,omitempty"`
	LogFrontier []string `json:"log_frontier,omitempty"` // largest subtree first
}

// MarshalJSON persists the state. At Signal's scale it is well under 2 KiB.
func (s State) MarshalJSON() ([]byte, error) {
	j := stateJSON{Size: s.Size()}
	if j.Size > 0 {
		j.PrefixRoot = hex.EncodeToString(s.prefixRoot[:])
	}
	for _, h := range s.log.Subtrees() {
		j.LogFrontier = append(j.LogFrontier, hex.EncodeToString(h[:]))
	}
	return json.Marshal(j)
}

// UnmarshalJSON restores a state, refusing one whose parts disagree — a
// frontier whose length does not match the size, or a prefix root on an empty
// log. It cannot detect a substituted root; the spec's advice to sign the
// persisted state is for the caller that stores it.
func (s *State) UnmarshalJSON(b []byte) error {
	var j stateJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return fmt.Errorf("signalaudit: state: %w", err)
	}
	var out State
	if j.Size == 0 {
		if j.PrefixRoot != "" || len(j.LogFrontier) != 0 {
			return errors.New("signalaudit: state: empty log with a prefix root or frontier")
		}
		*s = out
		return nil
	}
	if err := decodeHash(j.PrefixRoot, &out.prefixRoot); err != nil {
		return fmt.Errorf("signalaudit: state: prefix_root: %w", err)
	}
	frontier := make([][HashSize]byte, len(j.LogFrontier))
	for i, h := range j.LogFrontier {
		if err := decodeHash(h, &frontier[i]); err != nil {
			return fmt.Errorf("signalaudit: state: log_frontier[%d]: %w", i, err)
		}
	}
	log, err := signal.NewLogFrontier(j.Size, frontier)
	if err != nil {
		return fmt.Errorf("signalaudit: state: %w", err)
	}
	out.log = log
	*s = out
	return nil
}

func decodeHash(s string, out *[HashSize]byte) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != HashSize {
		return fmt.Errorf("%d bytes, want %d", len(b), HashSize)
	}
	copy(out[:], b)
	return nil
}
