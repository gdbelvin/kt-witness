package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/hostmem"
)

// stubVerifier declares a width and a per-origin footprint and does nothing
// else.
type stubVerifier struct {
	w   int
	mem map[string]uint64
}

func (s stubVerifier) width() int                     { return s.w }
func (s stubVerifier) memoryPerEpoch(o string) uint64 { return s.mem[o] }
func (s stubVerifier) verify(context.Context, string, int64, string) (string, string, error) {
	return "", "", nil
}

// TestTheBudgetIsSplitByWhatAVerificationActuallyCosts pins the fix for a bug
// that ran in production for a day: a literal 4 cores per epoch, measured
// against a Rust subprocess the worker no longer runs, divided every machine's
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
	v := stubVerifier{w: 1, mem: map[string]uint64{}}
	w := &worker{parallel: 8, log: log, verifiers: map[string]verifier{"meta": v, "wa": v}}

	// Nothing decoded yet: no cap, or a worker would idle on its first
	// assignment for want of a measurement it can only get by working.
	if got := w.parallelNow("meta"); got != 8 {
		t.Errorf("with nothing observed: %d epochs, want the full CPU budget of 8", got)
	}

	// A footprint so large that half of any plausible machine's free memory
	// holds one at most. The worker keeps going rather than refusing.
	v.mem["meta"] = 1 << 50
	if got := w.parallelNow("meta"); got != 1 {
		t.Errorf("with an enormous footprint: %d epochs, want 1", got)
	}

	// And here is why the origin is an argument. Meta is now known to be
	// enormous; WhatsApp is not, and must be unaffected. Held in common these
	// would be the same number, and a worker that had seen one Meta proof would
	// run WhatsApp one at a time forever.
	if got := w.parallelNow("wa"); got != 8 {
		t.Errorf("WhatsApp after a huge Meta proof: %d epochs, want the full 8", got)
	}

	// The conservative answer when there is no origin to ask about — the
	// capacity report and the gate before requesting work. It must take the
	// worst case, because promising the width of the smallest log and being
	// handed the largest is how a machine swaps.
	if got := w.parallelNow(""); got != 1 {
		t.Errorf("with no origin: %d epochs, want the worst case of 1", got)
	}

	// A tiny footprint must not raise the count above what the CPU allows.
	v.mem["wa"] = 1024
	if got := w.parallelNow("wa"); got > 8 {
		t.Errorf("with a tiny footprint: %d epochs, want no more than the CPU budget of 8", got)
	}
}

// TestARealisticFootprintLeavesRealisticRoom is the case between the extremes,
// and the one that would actually regress. A Meta proof is about 280 MB and the
// structures built from it about three times that; on a laptop with a few
// gigabytes spare the answer should be several epochs, not one.
//
// It exists because the two tests above pass just as happily against a
// hostmem implementation that only counted free pages — which on macOS is a few
// hundred megabytes on a perfectly healthy machine, and would quietly hold
// every Mac in the fleet at one epoch at a time.
func TestARealisticFootprintLeavesRealisticRoom(t *testing.T) {
	free, ok := hostmem.Available()
	if !ok {
		t.Skip("this machine does not report available memory")
	}
	const metaProof = 280 << 20
	w := &worker{parallel: 8, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		verifiers: map[string]verifier{
			"meta": stubVerifier{w: 1, mem: map[string]uint64{"meta": metaProof * 3}},
		}}
	got := w.parallelNow("meta")
	t.Logf("%.1f GiB available, %d MB per epoch, %d epochs at once",
		float64(free)/(1<<30), metaProof*3>>20, got)
	if free > 4<<30 && got < 2 {
		t.Errorf("%.1f GiB available but only %d Meta epoch at a time; either the "+
			"cap is too tight or hostmem is under-reporting what the machine has",
			float64(free)/(1<<30), got)
	}
}

// stubPacer puts the controller in a stated condition directly.
type stubPacer struct {
	measured bool
	spare    float64
}

func (p stubPacer) Measured() bool               { return p.measured }
func (p stubPacer) Spare() float64               { return p.spare }
func (p stubPacer) Ready(want float64) bool      { return p.spare >= want }
func (p stubPacer) Observed() (float64, float64) { return 0, 0 }

// TestWidthNeverReachesZeroOnceARangeIsLeased pins the one case the guard used
// to miss.
//
// The gate and the width are asked at different moments. BeforeNext passes
// while there is room, then Next blocks on the assignment channel — for minutes
// on a quiet queue, watched happening — and by the time an assignment arrives
// the machine may have filled up. The earlier version tested "spare > 0" and
// fell through to the full width when spare was zero, which is precisely the
// case it was written for: it would have run eight epochs on a machine the
// controller had just said had no room at all.
//
// One rather than zero because by this point the range is leased. Declining to
// work it frees nothing and strands the lease until it expires; the decision
// not to take a range at all belongs in BeforeNext, where it is still free to
// be made.
func TestWidthNeverReachesZeroOnceARangeIsLeased(t *testing.T) {
	newWorker := func(p pacer) *worker {
		return &worker{
			parallel:  8,
			log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			verifiers: map[string]verifier{"wa": stubVerifier{w: 1, mem: map[string]uint64{}}},
			gov:       p,
		}
	}

	for _, c := range []struct {
		name string
		p    stubPacer
		want int
	}{
		// Before any measurement the operator's figure stands: narrowing is a
		// claim, and there is no evidence for it yet. The controller holds at
		// one permit while blind, which read as a width would be an eighth of
		// the machine for a whole twenty-minute lease.
		{"nothing measured yet", stubPacer{measured: false, spare: 1}, 8},
		{"measured and idle", stubPacer{measured: true, spare: 8}, 8},
		{"more room than we can use", stubPacer{measured: true, spare: 20}, 8},
		{"the owner is compiling", stubPacer{measured: true, spare: 3}, 3},
		{"no room at all", stubPacer{measured: true, spare: 0}, 1},
		{"less than none", stubPacer{measured: true, spare: -2}, 1},
	} {
		if got := newWorker(c.p).width("wa"); got != c.want {
			t.Errorf("%s: width %d, want %d", c.name, got, c.want)
		}
	}
}
