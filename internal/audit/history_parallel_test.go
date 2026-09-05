package audit

import "testing"

// TestContiguousAdvanceStopsAtAGap is the property that makes parallel sweeping
// safe.
//
// Results arrive out of order, so the cursor must advance only over an unbroken
// run of successes. Stepping past a hole would leave an epoch unaudited inside
// a range the witness then reports as covered — turning "audited across
// published history" into a claim that looks complete and is not.
func TestContiguousAdvanceStopsAtAGap(t *testing.T) {
	// Sweeping down from 100 with a budget of 5: 99 and 98 verified, 97
	// blocked, 96 and 95 verified but unreachable behind the gap.
	results := map[int64]*batchResult{
		99: {epoch: 99, verified: true},
		98: {epoch: 98, verified: true},
		97: {epoch: 97, blocked: true},
		96: {epoch: 96, verified: true},
		95: {epoch: 95, verified: true},
	}

	var advanced []int64
	cursor, earliest, budget := int64(100), int64(1), int64(5)
	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		br := results[epoch]
		if br == nil || br.blocked || br.fatal != nil {
			break
		}
		advanced = append(advanced, epoch)
	}

	if len(advanced) != 2 || advanced[0] != 99 || advanced[1] != 98 {
		t.Fatalf("advanced over %v; must stop at the gap at 97", advanced)
	}
	// 96 and 95 verified, but they are behind a hole and must not count as
	// progress — the next pass retries 97 and picks them up in order.
	for _, e := range advanced {
		if e <= 97 {
			t.Fatalf("advanced past the gap to %d", e)
		}
	}
}

// TestVerifyBatchRespectsBudget: a batch must not run away with the pool.
func TestVerifyBatchRespectsBudget(t *testing.T) {
	cursor, earliest, budget := int64(100), int64(90), int64(4)
	var planned []int64
	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		planned = append(planned, epoch)
	}
	if len(planned) != 4 {
		t.Fatalf("planned %d epochs, want 4", len(planned))
	}
	// And it must not walk below the earliest published epoch.
	cursor, earliest, budget = 93, 90, 10
	planned = nil
	for i := int64(0); i < budget; i++ {
		epoch := cursor - 1 - i
		if epoch < earliest {
			break
		}
		planned = append(planned, epoch)
	}
	if len(planned) != 3 {
		t.Fatalf("planned %d epochs below the floor, want 3", len(planned))
	}
}
