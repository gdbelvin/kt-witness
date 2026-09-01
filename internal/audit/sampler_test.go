package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
)

func TestSelectedIsDeterministic(t *testing.T) {
	r := hex.EncodeToString([]byte("some randomness"))
	first, err := Selected(r, 12345, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		got, err := Selected(r, 12345, 0.5)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatal("selection must be deterministic: a third party has to reproduce it exactly")
		}
	}
}

func TestSelectedRateIsApproximatelyHonoured(t *testing.T) {
	// The rate we publish is the rate we must actually sample at; a systematic
	// bias here would silently overstate coverage.
	for _, rate := range []float64{0.01, 0.1, 0.5} {
		r := hex.EncodeToString([]byte("beacon"))
		const n = 20000
		hits := 0
		for e := int64(0); e < n; e++ {
			ok, err := Selected(r, e, rate)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				hits++
			}
		}
		got := float64(hits) / n
		// Generous tolerance: this is a smoke test for bias, not a statistics
		// exam. 4 sigma on a binomial at n=20000.
		sigma := math.Sqrt(rate * (1 - rate) / n)
		if math.Abs(got-rate) > 4*sigma+0.002 {
			t.Errorf("rate %v: sampled %v (%d/%d), outside tolerance", rate, got, hits, n)
		}
	}
}

func TestSelectedBoundaryRates(t *testing.T) {
	r := hex.EncodeToString([]byte("x"))
	for e := int64(0); e < 50; e++ {
		if ok, _ := Selected(r, e, 0); ok {
			t.Fatal("rate 0 must select nothing")
		}
		if ok, _ := Selected(r, e, 1); !ok {
			t.Fatal("rate 1 must select everything")
		}
	}
}

// Different beacon values must produce different samples, or the operator could
// predict the selection from one observed round and cheat in the rest.
func TestSelectionDependsOnBeacon(t *testing.T) {
	a := hex.EncodeToString([]byte("round one"))
	b := hex.EncodeToString([]byte("round two"))
	diff := 0
	for e := int64(0); e < 1000; e++ {
		x, _ := Selected(a, e, 0.5)
		y, _ := Selected(b, e, 0.5)
		if x != y {
			diff++
		}
	}
	if diff < 300 {
		t.Fatalf("selection barely depends on the beacon (%d/1000 differ)", diff)
	}
}

func TestSelectedRejectsBadRandomness(t *testing.T) {
	if _, err := Selected("not hex!!", 1, 0.5); err == nil {
		t.Fatal("want error for non-hex randomness")
	}
}

// The published rule must match the implementation, or the /audits note tells
// third parties to compute something we do not do.
func TestSelectionMatchesPublishedRule(t *testing.T) {
	rnd := []byte{0xde, 0xad, 0xbe, 0xef}
	rndHex := hex.EncodeToString(rnd)
	const epoch = int64(624700)

	h := sha256.New()
	h.Write(rnd)
	h.Write([]byte(":"))
	h.Write([]byte{0, 0, 0, 0, 0x00, 0x09, 0x88, 0x3c}) // big-endian 624700
	sum := h.Sum(nil)

	var draw uint64
	for _, b := range sum[:8] {
		draw = draw<<8 | uint64(b)
	}
	want := float64(draw) < 0.25*math.Pow(2, 64)

	got, err := Selected(rndHex, epoch, 0.25)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("implementation disagrees with the published rule: got %v want %v (draw %s)",
			got, want, fmt.Sprintf("%x", draw))
	}
}
