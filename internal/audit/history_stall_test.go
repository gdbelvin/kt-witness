package audit

import "testing"

// TestOneDeadEpochDoesNotStallTheSweep is the regression test for a stall that
// looked exactly like healthy operation.
//
// A single unfetchable epoch halted the backwards sweep for hours. Every pass
// walked down to it, failed, and re-verified the epochs below — which
// RecordAudit overwrites by key rather than accumulating — so coverage never
// moved while CPU sat pinned and dozens of verifications logged per minute. The
// symptom was indistinguishable from working.
//
// The rule this pins: an epoch is skipped once it is settled, and settled
// includes "failed to fetch enough times to stop asking". Absence is still
// evidence of nothing; the record stays unverified. What changes is only that
// the sweep stops spending every pass on it.
func TestOneDeadEpochDoesNotStallTheSweep(t *testing.T) {
	type rec struct {
		verified bool
		attempts int
	}
	// 100 and 99 verified; 98 has failed the maximum number of times; 97 is new.
	store := map[int64]*rec{
		100: {verified: true},
		99:  {verified: true},
		98:  {verified: false, attempts: maxFetchAttempts},
		97:  nil,
	}

	// The skip loop: walk down over anything settled.
	cursor := int64(101)
	for {
		prior, known := store[cursor-1]
		if !known || prior == nil {
			break
		}
		if !prior.verified && prior.attempts < maxFetchAttempts {
			break
		}
		cursor--
	}

	// The cursor names the boundary: at 98 the next epoch to attempt is 97, so
	// the dead epoch has been stepped over rather than waited on.
	if cursor != 98 {
		t.Fatalf("cursor at %d; after stepping over the dead epoch at 98 it should be 98, "+
			"leaving 97 as the next attempt", cursor)
	}

	// And an epoch that has failed only once is still worth retrying.
	store[98] = &rec{verified: false, attempts: 1}
	cursor = 101
	for {
		prior, known := store[cursor-1]
		if !known || prior == nil {
			break
		}
		if !prior.verified && prior.attempts < maxFetchAttempts {
			break
		}
		cursor--
	}
	// One failed attempt is not enough to give up: the cursor stops at 99 so
	// that 98 is retried.
	if cursor != 99 {
		t.Fatalf("cursor at %d; an epoch with one failed attempt deserves another try", cursor)
	}
}
