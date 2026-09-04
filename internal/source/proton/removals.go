package proton

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// Judging removals against Proton's retention window.
//
// # Why a count is not an answer
//
// Replaying an epoch's diff shows that leaves left the tree — 9,337 of them in
// epoch 6709 alone — and nothing in the chain of signed epoch hashes can show
// that. But a removal is not misbehaviour: Proton retains roughly 90 days of
// epochs and prunes what falls out the back of that window, so the honest
// question is not "how many" but "was each one inside the rule".
//
// # What makes dating possible
//
// The 36-byte leaf value is SHA-256(signed key list) || uint32be(minEpochID),
// and minEpochID is the epoch at which that revision entered the directory. Every
// epoch also publishes StartEpochID, the oldest epoch it still retains. So a leaf
// can be dated in the operator's own units — epochs — without any extra data and
// without trusting a timestamp anyone could have chosen freely.
//
// # The rule
//
// A removal is explained by retention when the leaf entered the tree before the
// oldest retained epoch:
//
//	minEpochID < StartEpochID(epoch performing the removal)
//
// This was established by observation rather than from a specification, which is
// the reason for the wording below. Across epochs 6300, 6650, 6700, 6709 and
// 6712 — 45,816 removals in total — every removed leaf satisfied it, and the
// largest minEpochID removed in each epoch was exactly StartEpochID-1, landing on
// the boundary rather than merely under it. Additions in those same epochs
// carried minEpochID equal to the epoch making them, without exception.
//
// # What this may and may not conclude
//
// It may not accuse. The window rule is inferred from Proton's behaviour, not
// signed by Proton, so a removal that fails it is a removal this witness cannot
// explain — which is a reason to withhold and to publish what was seen, never a
// reason to call it a fork. Accusation requires positive contradiction; an
// unexplained removal is the absence of an explanation. See docs/design.md.

// MinEpochID reads the epoch at which a leaf's revision entered the directory,
// carried in the last four bytes of the 36-byte value.
func MinEpochID(value []byte) (int64, error) {
	if len(value) != valueSize {
		return 0, fmt.Errorf("proton: leaf value is %d bytes, want %d", len(value), valueSize)
	}
	return int64(binary.BigEndian.Uint32(value[hashSize:])), nil
}

// Revision reads the revision counter from the last four bytes of a label, which
// is VRF(email)[0:28] || uint32be(revision).
func Revision(label []byte) (int64, error) {
	if len(label) != labelSize {
		return 0, fmt.Errorf("proton: label is %d bytes, want %d", len(label), labelSize)
	}
	return int64(binary.BigEndian.Uint32(label[labelSize-4:])), nil
}

// RemovalVerdict is one removal, dated.
type RemovalVerdict struct {
	Label      []byte
	MinEpochID int64
	Revision   int64

	// Explained is true when the leaf entered the tree before the oldest epoch
	// the removing epoch still retains.
	Explained bool

	// Phantom marks a removal of a label the tree did not contain, whose value
	// therefore comes from the diff alone and corroborates nothing.
	Phantom bool
}

// RemovalReport is the judgement over one epoch's removals.
type RemovalReport struct {
	EpochID      int64
	StartEpochID int64

	Explained int

	// Unexplained are removals of leaves that entered the tree *inside* the
	// retained window. They are reported in full, since they are few by
	// construction whenever the rule holds at all.
	Unexplained []RemovalVerdict

	// Undatable are removals whose value was the wrong length to read a
	// minEpochID out of. Not being able to date something is not evidence about
	// it, so these are counted apart from the ones that were dated and failed.
	Undatable int

	// OldestRemoved and NewestRemoved bound the minEpochIDs seen, so the margin
	// against the window boundary is visible rather than implied.
	OldestRemoved int64
	NewestRemoved int64
}

// Judged reports whether the report could actually reach a conclusion. Without
// a StartEpochID there is no window to judge against, and reporting "0
// unexplained" in that case would be a false clean bill of health.
func (r *RemovalReport) Judged() bool { return r.StartEpochID > 0 }

// Clean reports that every removal was explained by the retention window.
func (r *RemovalReport) Clean() bool {
	return r.Judged() && len(r.Unexplained) == 0 && r.Undatable == 0
}

// JudgeRemovals dates each removal from an epoch's diff and checks it against
// that epoch's own retention window.
//
// startEpochID must be the StartEpochID published by the epoch that performed
// the removals, not the current tip's: it is stored per epoch and moves with the
// window, so using today's value to judge a historical epoch would call
// perfectly ordinary pruning unexplained.
func JudgeRemovals(stats *DiffStats, epochID, startEpochID int64) *RemovalReport {
	rep := &RemovalReport{EpochID: epochID, StartEpochID: startEpochID}

	judge := func(rm Removal, phantom bool) {
		min, err := MinEpochID(rm.Value)
		if err != nil {
			rep.Undatable++
			return
		}
		rev, err := Revision(rm.Label)
		if err != nil {
			rep.Undatable++
			return
		}
		if rep.OldestRemoved == 0 || min < rep.OldestRemoved {
			rep.OldestRemoved = min
		}
		if min > rep.NewestRemoved {
			rep.NewestRemoved = min
		}
		v := RemovalVerdict{
			Label:      rm.Label,
			MinEpochID: min,
			Revision:   rev,
			Explained:  startEpochID > 0 && min < startEpochID,
			Phantom:    phantom,
		}
		if v.Explained {
			rep.Explained++
			return
		}
		rep.Unexplained = append(rep.Unexplained, v)
	}

	for _, rm := range stats.Removals {
		judge(rm, false)
	}
	for _, rm := range stats.PhantomRemoved {
		judge(rm, true)
	}

	// Reported oldest-first, so a reader sees the removals nearest the window
	// boundary — the ones most likely to be an off-by-one in this rule rather
	// than anything of Proton's — before the ones deep inside it.
	sort.Slice(rep.Unexplained, func(i, j int) bool {
		return rep.Unexplained[i].MinEpochID < rep.Unexplained[j].MinEpochID
	})
	return rep
}

// Summary is a one-line rendering for an audit log.
func (r *RemovalReport) Summary() string {
	if !r.Judged() {
		return fmt.Sprintf("epoch %d: retention window unknown, %d removals left unjudged",
			r.EpochID, r.Explained+len(r.Unexplained)+r.Undatable)
	}
	return fmt.Sprintf("epoch %d: window starts at epoch %d; %d removals explained by it, "+
		"%d not explained, %d undatable; removed entries date from epochs %d..%d",
		r.EpochID, r.StartEpochID, r.Explained, len(r.Unexplained), r.Undatable,
		r.OldestRemoved, r.NewestRemoved)
}

// Describe renders an unexplained removal for publication. Labels are VRF
// outputs, so this identifies a leaf without naming the account behind it —
// which is the right level of detail for evidence anyone can check.
func (v RemovalVerdict) Describe() string {
	kind := "removed"
	if v.Phantom {
		kind = "removed but absent from the tree"
	}
	return fmt.Sprintf("label %s revision %d entered at epoch %d, %s",
		hex.EncodeToString(v.Label), v.Revision, v.MinEpochID, kind)
}

// Proton's deletion rules, and which of them a diff can actually settle.
//
// The white paper gives an auditor three conditions on deletions:
//
//  1. a label's latest revision is never deleted
//  2. only revisions superseded more than 90 days ago may be deleted
//  3. revisions are deleted contiguously from revision 1
//
// JudgeRemovals settles (2): the retention window is published per epoch and
// each removed leaf carries the epoch it entered, so a removal inside the window
// is a positive contradiction.
//
// (1) and (3) are about a label's revisions as a set, and a single epoch's diff
// does not contain that set. A gap in the revisions removed *this* epoch is
// equally consistent with the missing revision having been removed legitimately
// in an earlier epoch. Reporting a gap as a violation would therefore accuse
// Proton of something the evidence does not show — the failure mode this
// project exists to avoid.
//
// So the analysis below reports shape rather than judging it: it groups removals
// by address and names the ones whose revision runs look irregular, which is
// what a human would want to look at first. Turning that into a finding needs
// the label's full revision set, which means the rebuilt tree, and is left for
// when the incremental auditor can supply it.

// LabelRemovals is one address's removals within a single epoch.
//
// The address itself is never recoverable: the label is VRF(email)[0:28], and
// the VRF is precisely what stops a third party enumerating who is in the
// directory. Grouping by it is possible; naming it is not.
type LabelRemovals struct {
	// Prefix is VRF(email)[0:28], hex-encoded.
	Prefix string
	// Revisions removed this epoch, ascending.
	Revisions []int64
	// Contiguous reports whether Revisions form a run with no gaps. A gap is
	// not evidence on its own; see the note above.
	Contiguous bool
	// FromOne reports whether the run starts at revision 1, which is what rule
	// (3) requires of a complete deletion history.
	FromOne bool
}

// GroupRemovalsByLabel summarises an epoch's removals per address.
func GroupRemovalsByLabel(stats *DiffStats) []LabelRemovals {
	if stats == nil {
		return nil
	}
	byPrefix := map[string][]int64{}
	for _, rm := range stats.Removals {
		if len(rm.Label) < 32 {
			continue
		}
		rev, err := Revision(rm.Label)
		if err != nil {
			continue
		}
		p := hex.EncodeToString(rm.Label[:28])
		byPrefix[p] = append(byPrefix[p], rev)
	}

	out := make([]LabelRemovals, 0, len(byPrefix))
	for p, revs := range byPrefix {
		sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
		lr := LabelRemovals{Prefix: p, Revisions: revs, Contiguous: true, FromOne: revs[0] == 1}
		for i := 1; i < len(revs); i++ {
			if revs[i] != revs[i-1]+1 {
				lr.Contiguous = false
				break
			}
		}
		out = append(out, lr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// IrregularRemovals returns the addresses whose removals this epoch are not a
// contiguous run, for a human to look at.
//
// Deliberately not called "violations". See the note above.
func IrregularRemovals(stats *DiffStats) []LabelRemovals {
	var out []LabelRemovals
	for _, lr := range GroupRemovalsByLabel(stats) {
		if !lr.Contiguous {
			out = append(out, lr)
		}
	}
	return out
}
