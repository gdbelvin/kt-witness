package audit

import (
	"testing"
	"time"
)

// The round must be a pure function of the timestamp, or the grinding hole it
// exists to close is still open: rounds are three seconds apart, and a witness
// free to pick one could re-decide until an epoch it wanted to skip came up
// unselected, cheaply and without a trace.
func TestRoundAtIsDeterministicAndStrictlyAfter(t *testing.T) {
	genesis := time.Unix(quicknetGenesis, 0)

	// At genesis, round 1 is the current one.
	if got := RoundAt(genesis); got != 1 {
		t.Errorf("RoundAt(genesis) = %d, want 1", got)
	}
	// One period later, round 2 is current.
	if got := RoundAt(genesis.Add(quicknetPeriod * time.Second)); got != 2 {
		t.Errorf("RoundAt(genesis+period) = %d, want 2", got)
	}
	// The round must already exist, or it cannot be fetched. A round derived
	// from "now" must never be in the future.
	if RoundAt(time.Now()) > RoundAt(time.Now().Add(quicknetPeriod*time.Second)) {
		t.Error("RoundAt(now) reaches into the future and would 500")
	}
	// Determinism: the same instant must always give the same round.
	at := genesis.Add(123456 * time.Second)
	if RoundAt(at) != RoundAt(at) {
		t.Fatal("RoundAt is not deterministic")
	}
	// Monotonic: later never yields an earlier round.
	prev := uint64(0)
	for i := 0; i < 200; i++ {
		r := RoundAt(genesis.Add(time.Duration(i) * time.Second))
		if r < prev {
			t.Fatalf("RoundAt went backwards at +%ds: %d then %d", i, prev, r)
		}
		prev = r
	}
	// Before genesis cannot underflow into a huge round.
	if got := RoundAt(genesis.Add(-time.Hour)); got != 1 {
		t.Errorf("RoundAt(before genesis) = %d, want 1", got)
	}
}

// Within one period the round must not change — otherwise a witness could
// simply wait a moment and get a different draw.
func TestRoundAtIsStableWithinAPeriod(t *testing.T) {
	base := time.Unix(quicknetGenesis+3000, 0)
	want := RoundAt(base)
	for _, off := range []time.Duration{0, 500 * time.Millisecond, 2 * time.Second, 2900 * time.Millisecond} {
		if got := RoundAt(base.Add(off)); got != want {
			t.Errorf("round changed within a period at +%v: %d != %d", off, got, want)
		}
	}
}
