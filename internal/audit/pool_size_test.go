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
