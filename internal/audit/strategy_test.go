package audit

import "testing"

// The tip must be audited exhaustively. An attack only accomplishes anything if
// the forged binding is served to a victim, which means recent epochs — so
// detection there has to be certain, not probabilistic.
func TestTipIsAuditedExhaustively(t *testing.T) {
	for _, age := range []int64{0, 1, 100, TipWindow - 1} {
		rate, strat := SelectionRate(age, 0.1)
		if rate != 1 {
			t.Errorf("age %d: rate %v, want 1 — the tip must not be sampled", age, rate)
		}
		if strat != StrategyLive {
			t.Errorf("age %d: strategy %q, want live", age, strat)
		}
	}
}

// Beyond the tip the rate must decay, and must keep decaying — reaching
// arbitrarily far back with diminishing density rather than cutting off.
func TestBacklogDecaysLogarithmically(t *testing.T) {
	base := 1.0
	prev := 2.0
	for _, age := range []int64{TipWindow, TipWindow + 1, TipWindow + 15, TipWindow + 1023, TipWindow + 1_000_000} {
		rate, strat := SelectionRate(age, base)
		if strat != StrategyBacklog {
			t.Errorf("age %d: strategy %q, want backlog", age, strat)
		}
		if rate <= 0 {
			t.Errorf("age %d: rate fell to %v — decay must never reach zero", age, rate)
		}
		if rate > prev {
			t.Errorf("age %d: rate %v rose above the previous %v", age, rate, prev)
		}
		prev = rate
	}
	// Logarithmic, not exponential: a millionfold older epoch should still be
	// sampled at a meaningful fraction, not effectively never.
	far, _ := SelectionRate(TipWindow+1_000_000, 1.0)
	if far < 0.03 {
		t.Errorf("rate at 1M epochs back is %v — that is exponential decay, not logarithmic", far)
	}
}

// The rate must be a pure function of published inputs, or a third party cannot
// recompute what we were obliged to sample and the claimed coverage is merely
// asserted.
func TestSelectionRateIsDeterministic(t *testing.T) {
	for _, age := range []int64{0, TipWindow, TipWindow + 5000} {
		a, _ := SelectionRate(age, 0.1)
		b, _ := SelectionRate(age, 0.1)
		if a != b {
			t.Fatalf("age %d: not deterministic (%v vs %v)", age, a, b)
		}
	}
	if r, _ := SelectionRate(-5, 0.1); r != 1 {
		t.Errorf("a negative age must clamp to the tip, got %v", r)
	}
}
