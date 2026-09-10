package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// stubVerifier declares a width and a footprint and does nothing else.
type stubVerifier struct {
	w   int
	mem uint64
}

func (s stubVerifier) width() int             { return s.w }
func (s stubVerifier) memoryPerEpoch() uint64 { return s.mem }
func (s stubVerifier) verify(context.Context, string, int64, string) (string, string, error) {
	return "", "", nil
}

// TestTheBudgetIsSplitByWhatAVerificationActuallyCosts pins the fix for a bug
// that ran in production for a day: a literal 4 cores per epoch, measured
// against a Rust sidecar the worker no longer runs, divided every machine's
// budget by four. A ten-core laptop verified two epochs at a time instead of
// eight, and a thirty-two core box four instead of thirty.
//
// The property is that the number comes from the verifier. If somebody makes
// akdtree parallel, this test does not need editing — width() changes and the
// division follows.
func TestTheBudgetIsSplitByWhatAVerificationActuallyCosts(t *testing.T) {
	single := map[string]verifier{"a": stubVerifier{w: 1}}
	if w, p := epochsAtOnce(30, single); w != 1 || p != 30 {
		t.Errorf("single-threaded verifier on 30 cores: width %d, parallel %d; want 1 and 30", w, p)
	}
	if w, p := epochsAtOnce(8, single); w != 1 || p != 8 {
		t.Errorf("single-threaded verifier on 8 cores: width %d, parallel %d; want 1 and 8", w, p)
	}

	// The widest sets the divisor: oversubscribing the CPU is the failure this
	// exists to prevent, and running a narrow verifier under-subscribed is not.
	mixed := map[string]verifier{"a": stubVerifier{w: 1}, "b": stubVerifier{w: 4}}
	if w, p := epochsAtOnce(30, mixed); w != 4 || p != 7 {
		t.Errorf("mixed widths on 30 cores: width %d, parallel %d; want 4 and 7", w, p)
	}

	// A verifier wider than the whole machine still gets to run.
	if w, p := epochsAtOnce(2, map[string]verifier{"a": stubVerifier{w: 8}}); w != 2 || p != 1 {
		t.Errorf("verifier wider than the machine: width %d, parallel %d; want 2 and 1", w, p)
	}

	// So does a machine with no budget worth speaking of.
	if _, p := epochsAtOnce(0, single); p != 1 {
		t.Errorf("zero budget: parallel %d, want 1", p)
	}
}

// TestMemoryNarrowsButOnlyOnceSomethingIsKnown covers the other half. A Meta
// proof is nearly three hundred megabytes and a WhatsApp one a few, and the
// same worker takes both — so the cap has to follow what has actually been
// handed to this machine, and must not exist before anything has.
func TestMemoryNarrowsButOnlyOnceSomethingIsKnown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Nothing decoded yet: no cap, or a worker would idle on its first
	// assignment for want of a measurement it can only get by working.
	w := &worker{parallel: 8, log: log,
		verifiers: map[string]verifier{"a": stubVerifier{w: 1, mem: 0}}}
	if got := w.parallelNow(); got != 8 {
		t.Errorf("with nothing observed: %d epochs, want the full CPU budget of 8", got)
	}

	// A footprint so large that half of any plausible machine's free memory
	// holds one at most. The worker keeps going rather than refusing.
	w.verifiers["a"] = stubVerifier{w: 1, mem: 1 << 50}
	if got := w.parallelNow(); got != 1 {
		t.Errorf("with an enormous footprint: %d epochs, want 1", got)
	}

	// A tiny one must not raise the count above what the CPU allows.
	w.verifiers["a"] = stubVerifier{w: 1, mem: 1024}
	if got := w.parallelNow(); got > 8 {
		t.Errorf("with a tiny footprint: %d epochs, want no more than the CPU budget of 8", got)
	}
}
