package hostmem

import (
	"os"
	"testing"
)

// TestScratchMeasuresSomethingReal. The point of this function is to catch a
// scratch filesystem that is too small, so the failure that matters is it
// reporting plenty when there is none — a silent pass on the exact condition it
// exists to find.
func TestScratchMeasuresSomethingReal(t *testing.T) {
	n, ok := Scratch(os.TempDir())
	if !ok {
		t.Skip("statfs is unavailable on this platform")
	}
	if n == 0 {
		t.Fatalf("%s reports zero bytes free; the check would fire on every start",
			os.TempDir())
	}
	t.Logf("%s: %.1f GiB free", os.TempDir(), float64(n)/(1<<30))

	// An empty argument means the temp dir, so the caller need not repeat it.
	if m, ok := Scratch(""); !ok || m == 0 {
		t.Errorf(`Scratch("") = %d, %v; want the temp dir's figure`, m, ok)
	}

	// A path that is not there must report unknown rather than zero. Zero would
	// read as "no space" and produce a warning about a filesystem that does not
	// exist, which is worse than saying nothing.
	if got, ok := Scratch("/definitely/not/a/directory/here"); ok {
		t.Errorf("measured a directory that does not exist: %d bytes", got)
	}
}
