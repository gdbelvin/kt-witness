package store

import (
	"testing"
	"time"
)

// TestAnExhaustedHoleWithNoScheduleIsDue.
//
// HolesDue used to key ownership off RetryAfter: zero meant "the ordinary sweep
// still owns this". That conflated "not exhausted yet" with "nobody ever wrote
// the field", and the second was the state of every hole recorded while the
// field had no writer — which was all of them, for as long as the repair pass
// was gone. 436 Meta epochs sat at attempts=5 with a zero timestamp, invisible
// here forever, having failed on a disk-full condition that no longer existed.
//
// Ownership is the attempt count. The timestamp only says how long to wait
// once the attempts are spent.
func TestAnExhaustedHoleWithNoScheduleIsDue(t *testing.T) {
	s := testStore(t)
	const origin = "whatsapp.kt/v2"
	now := time.Now().UTC()

	write := func(epoch int64, attempts int, retry time.Time) {
		t.Helper()
		if err := s.RecordAudit(&Audit{Origin: origin, Epoch: epoch, Sampled: true,
			Rate: 1, Verified: false, Attempts: attempts, DecidedAt: now,
			RetryAfter: retry}); err != nil {
			t.Fatal(err)
		}
	}
	write(10, MaxFetchAttempts+2, time.Time{})       // exhausted, never scheduled
	write(20, 1, time.Time{})                        // still the sweep's
	write(30, MaxFetchAttempts, now.Add(-time.Hour)) // exhausted, backoff elapsed
	write(40, MaxFetchAttempts, now.Add(time.Hour))  // exhausted, still waiting

	due, err := s.HolesDue(origin, 0, 1000, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, e := range due {
		got[e] = true
	}
	if !got[10] {
		t.Error("epoch 10 is exhausted with no schedule and was not due; " +
			"nothing will ever retry it")
	}
	if got[20] {
		t.Error("epoch 20 still has attempts left; the ordinary sweep owns it")
	}
	if !got[30] {
		t.Error("epoch 30's backoff has elapsed and it was not due")
	}
	if got[40] {
		t.Error("epoch 40 is still inside its backoff and was offered anyway")
	}
}
