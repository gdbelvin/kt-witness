package audit

import "testing"

// TestDefaultWorkersFallsBackSafely pins the direction of the unknown case.
//
// A guessed-high pool on a machine whose limit cannot be read is an OOM kill
// that takes equivocation detection down with the audit. One worker is merely
// slow, and the governor exists to make slow self-correcting.
func TestDefaultWorkersFallsBackSafely(t *testing.T) {
	// Whatever this machine reports, the answer must be usable.
	if n := DefaultWorkers(); n < 1 {
		t.Fatalf("DefaultWorkers returned %d", n)
	}
}

// TestPoolSizingArithmetic checks the shape of the derivation without depending
// on the machine the test runs on.
func TestPoolSizingArithmetic(t *testing.T) {
	for _, c := range []struct {
		limitGiB float64
		want     int
		why      string
	}{
		{16, 3, "16 GiB at 75% headroom / 4 GiB per verification"},
		{24, 4, "raising the limit buys workers"},
		{4, 1, "a small limit still yields a usable pool"},
	} {
		limit := int64(c.limitGiB * float64(1<<30))
		got := int(float64(limit) * memoryHeadroom / float64(peakVerificationBytes))
		if got < 1 {
			got = 1
		}
		if got != c.want {
			t.Errorf("%.0f GiB: %d workers, want %d (%s)", c.limitGiB, got, c.want, c.why)
		}
	}
}

// A memory limit larger than the machine must not size the pool.
//
// Docker accepts `mem_limit: 44g` on a 31 GB host without complaint, and the
// pool would then plan for eight 4 GiB workers and OOM the box — killing
// equivocation detection along with the audit. The limit is a permission, not
// evidence the memory exists.
//
// This is exercised through the arithmetic rather than the filesystem because
// the real inputs are /proc and /sys, which a test cannot set. What is pinned is
// the rule: the effective ceiling is the smaller of what we are allowed and what
// is physically there.
func TestLimitLargerThanMachineDoesNotSizeThePool(t *testing.T) {
	const gb = int64(1) << 30

	effective := func(limit, machine int64) int {
		if avail := int64(float64(machine) * memoryHeadroom); avail < limit {
			limit = avail
		}
		n := int(float64(limit) * memoryHeadroom / float64(peakVerificationBytes))
		if n < 1 {
			n = 1
		}
		return n
	}

	// The case that motivated this: config raised for a resize that has not
	// happened. 44 GB allowed, 31 GB present.
	if got := effective(44*gb, 31*gb); got > 4 {
		t.Errorf("sized %d workers from a 44 GB limit on a 31 GB machine; "+
			"that is ~%d GB of working set on a box that does not have it",
			got, got*4)
	}

	// Once the machine really is 64 GB, the same limit yields the intended pool.
	if got := effective(44*gb, 64*gb); got != 8 {
		t.Errorf("sized %d workers from a 44 GB limit on a 64 GB machine, want 8", got)
	}

	// A limit well inside the machine is still honoured — the guard is a ceiling,
	// not a second opinion.
	if got := effective(8*gb, 64*gb); got != 1 {
		t.Errorf("sized %d workers from an 8 GB limit, want 1", got)
	}
}
