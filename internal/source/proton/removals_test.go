package proton

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// leafValue builds a 36-byte value carrying the given minEpochID, which is the
// field the whole judgement rests on.
func leafValue(rng *rand.Rand, minEpoch uint32) []byte {
	v := make([]byte, valueSize)
	rng.Read(v[:hashSize])
	binary.BigEndian.PutUint32(v[hashSize:], minEpoch)
	return v
}

func labelWithRevision(rng *rand.Rand, rev uint32) []byte {
	l := make([]byte, labelSize)
	rng.Read(l)
	binary.BigEndian.PutUint32(l[labelSize-4:], rev)
	return l
}

func TestMinEpochIDAndRevision(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	v := leafValue(rng, 6208)
	got, err := MinEpochID(v)
	if err != nil || got != 6208 {
		t.Fatalf("MinEpochID = %d, %v; want 6208", got, err)
	}
	l := labelWithRevision(rng, 3)
	rev, err := Revision(l)
	if err != nil || rev != 3 {
		t.Fatalf("Revision = %d, %v; want 3", rev, err)
	}

	// Negative control: a value of the wrong length must not be read as if the
	// last four bytes were a minEpochID, because a misparsed date would judge a
	// removal against a number that means nothing.
	if _, err := MinEpochID(v[:valueSize-1]); err == nil {
		t.Fatal("a short value must be refused, not decoded")
	}
	if _, err := Revision(l[:labelSize-1]); err == nil {
		t.Fatal("a short label must be refused, not decoded")
	}
}

// The rule as observed on production: a leaf that entered before the oldest
// retained epoch has fallen out of the window, and its removal is explained.
func TestJudgeRemovalsExplainsPrunedLeaves(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	stats := &DiffStats{}
	for _, min := range []uint32{1, 3571, 6035, 6208} {
		stats.Removals = append(stats.Removals, Removal{
			Label: labelWithRevision(rng, 1),
			Value: leafValue(rng, min),
		})
		stats.Removed++
	}

	rep := JudgeRemovals(stats, 6709, 6209)
	if !rep.Clean() {
		t.Fatalf("every leaf predates the window; want clean, got %s", rep.Summary())
	}
	if rep.Explained != 4 {
		t.Fatalf("explained %d removals, want 4", rep.Explained)
	}
	if rep.OldestRemoved != 1 || rep.NewestRemoved != 6208 {
		t.Fatalf("bounds %d..%d, want 1..6208", rep.OldestRemoved, rep.NewestRemoved)
	}
}

// The negative control that matters: a leaf removed from *inside* the window is
// the thing this check exists to catch, and it must not be swallowed.
func TestJudgeRemovalsSurfacesInWindowRemoval(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	stats := &DiffStats{Removed: 2}
	stats.Removals = []Removal{
		{Label: labelWithRevision(rng, 1), Value: leafValue(rng, 6100)},
		{Label: labelWithRevision(rng, 2), Value: leafValue(rng, 6700)},
	}

	rep := JudgeRemovals(stats, 6709, 6209)
	if rep.Clean() {
		t.Fatal("a leaf that entered inside the retained window must not be reported as explained")
	}
	if len(rep.Unexplained) != 1 || rep.Unexplained[0].MinEpochID != 6700 {
		t.Fatalf("want exactly the epoch-6700 leaf unexplained, got %+v", rep.Unexplained)
	}
	if rep.Explained != 1 {
		t.Fatalf("the epoch-6100 leaf is explained; explained = %d", rep.Explained)
	}
	if rep.Unexplained[0].Describe() == "" {
		t.Fatal("an unexplained removal must render for publication")
	}
}

// The boundary is exactly StartEpochID: production shows the largest minEpochID
// removed in an epoch is StartEpochID-1, so an off-by-one here would either
// excuse a removal it should not or flag the ordinary case.
func TestJudgeRemovalsBoundaryIsExclusive(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	at := &DiffStats{Removed: 1, Removals: []Removal{
		{Label: labelWithRevision(rng, 1), Value: leafValue(rng, 6209)},
	}}
	if JudgeRemovals(at, 6709, 6209).Clean() {
		t.Fatal("a leaf that entered at StartEpochID is still retained; removing it is not explained")
	}
	below := &DiffStats{Removed: 1, Removals: []Removal{
		{Label: labelWithRevision(rng, 1), Value: leafValue(rng, 6208)},
	}}
	if !JudgeRemovals(below, 6709, 6209).Clean() {
		t.Fatal("a leaf that entered at StartEpochID-1 has fallen out of the window")
	}
}

// Without a published window there is nothing to judge against, and reporting a
// clean result would be a false clean bill of health.
func TestJudgeRemovalsWithoutWindowWithholds(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	stats := &DiffStats{Removed: 1, Removals: []Removal{
		{Label: labelWithRevision(rng, 1), Value: leafValue(rng, 1)},
	}}
	rep := JudgeRemovals(stats, 6709, 0)
	if rep.Judged() || rep.Clean() {
		t.Fatal("with no StartEpochID the removals are unjudged, not clean")
	}
	if rep.Summary() == "" {
		t.Fatal("an unjudged report must still say so")
	}
}

// A value that cannot be dated is counted apart from one that was dated and
// failed: not being able to check something is not evidence about it.
func TestJudgeRemovalsCountsUndatableApart(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	stats := &DiffStats{Removed: 1, Removals: []Removal{
		{Label: labelWithRevision(rng, 1), Value: make([]byte, valueSize-1)},
	}}
	rep := JudgeRemovals(stats, 6709, 6209)
	if rep.Undatable != 1 || len(rep.Unexplained) != 0 {
		t.Fatalf("an undatable removal must not be reported as unexplained: %+v", rep)
	}
	if rep.Clean() {
		t.Fatal("an undatable removal leaves the epoch unaccounted for")
	}
}

// A removal of a label the tree did not hold is judged too, but marked, since
// its value came from the diff alone and corroborates nothing.
func TestJudgeRemovalsMarksPhantoms(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	stats := &DiffStats{PhantomRemovals: 1, PhantomRemoved: []Removal{
		{Label: labelWithRevision(rng, 1), Value: leafValue(rng, 6700)},
	}}
	rep := JudgeRemovals(stats, 6709, 6209)
	if len(rep.Unexplained) != 1 || !rep.Unexplained[0].Phantom {
		t.Fatalf("a phantom removal must be judged and marked: %+v", rep.Unexplained)
	}
}

// ApplyDiff must notice when the diff's removal record names a value other than
// the one the tree holds — Proton's two publications disagreeing about what left.
func TestApplyDiffNoticesRemovalValueMismatch(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	tree := buildLeaves(t, rng, 12, 0)

	other := leafValue(rng, 99)
	diff := diffRecord(OpRemove, tree.Label(4), other)
	_, stats := applyDiff(t, tree, diff)

	if stats.ValueMismatches != 1 {
		t.Fatalf("a removal naming a different value must be reported, got %+v", stats)
	}
	// The recorded value is still the tree's, because that is the one bound to a
	// verified root.
	if got, _ := MinEpochID(stats.Removals[0].Value); got == 99 {
		t.Fatal("the removal was dated from the diff's value rather than the tree's")
	}
}

func lbl(prefix byte, rev uint32) []byte {
	l := make([]byte, 32)
	for i := 0; i < 28; i++ {
		l[i] = prefix
	}
	binary.BigEndian.PutUint32(l[28:], rev)
	return l
}

// TestGroupRemovalsByLabel checks the grouping that makes Proton's deletion
// rules inspectable: removals are keyed by VRF(email)[0:28] || revision, so an
// address's revisions can be gathered without the address ever being knowable.
func TestGroupRemovalsByLabel(t *testing.T) {
	stats := &DiffStats{Removals: []Removal{
		{Label: lbl(0xaa, 3)}, {Label: lbl(0xaa, 1)}, {Label: lbl(0xaa, 2)},
		{Label: lbl(0xbb, 1)}, {Label: lbl(0xbb, 4)}, // gap: 2 and 3 absent
		{Label: lbl(0xcc, 7)}, // does not start at 1
	}}
	got := GroupRemovalsByLabel(stats)
	if len(got) != 3 {
		t.Fatalf("grouped into %d addresses, want 3", len(got))
	}
	by := map[string]LabelRemovals{}
	for _, g := range got {
		by[g.Prefix[:2]] = g
	}
	if a := by["aa"]; !a.Contiguous || !a.FromOne || len(a.Revisions) != 3 {
		t.Errorf("aa should be a contiguous run from 1: %+v", a)
	}
	if b := by["bb"]; b.Contiguous {
		t.Errorf("bb has a gap at revisions 2-3 and must not read as contiguous: %+v", b)
	}
	if c := by["cc"]; c.FromOne {
		t.Errorf("cc starts at revision 7, not 1: %+v", c)
	}
	// Revisions must be sorted, or contiguity is judged against arrival order.
	a := by["aa"]
	for i := 1; i < len(a.Revisions); i++ {
		if a.Revisions[i] < a.Revisions[i-1] {
			t.Fatalf("revisions not sorted: %v", a.Revisions)
		}
	}

	irr := IrregularRemovals(stats)
	if len(irr) != 1 || irr[0].Prefix[:2] != "bb" {
		t.Fatalf("expected only bb to be irregular, got %+v", irr)
	}
}

// TestGroupRemovalsIgnoresMalformed keeps a short or unparseable label from
// silently becoming an address group of its own.
func TestGroupRemovalsIgnoresMalformed(t *testing.T) {
	stats := &DiffStats{Removals: []Removal{
		{Label: []byte{1, 2, 3}},
		{Label: lbl(0xaa, 1)},
	}}
	if got := GroupRemovalsByLabel(stats); len(got) != 1 {
		t.Fatalf("malformed label was grouped: %+v", got)
	}
	if GroupRemovalsByLabel(nil) != nil {
		t.Error("nil stats should group to nothing")
	}
}
