// Package pace decides how much of a machine a background job may take.
//
// It lives outside internal/audit because every participant needs it, not just
// this one. Verification is handed out to whatever machines the operator owns,
// and each of them has to answer the same question about ITS OWN host: how much
// of this can I take without making the machine unpleasant for whoever is
// actually using it.
//
// That question cannot be answered centrally. A witness has no idea what else
// a laptop is doing, and a laptop that took its concurrency from a 32-core
// server would either idle or make its owner's machine crawl. So the queue
// decides what to work on and this decides how fast, once per host.
package pace

import "testing"

// TestPermitsNeverReachZero is what keeps the backlog finite.
//
// Live auditing does not ask this governor, so it can hold the machine at its
// budget by itself. The error term then goes to zero, permits decay, and the
// backwards sweep stops — observed in production as permits at 0.47 with
// coverage flat while the sweep was visibly running.
//
// The backlog should yield to the tip. It should not yield forever.
func TestPermitsNeverReachZero(t *testing.T) {
	g := &Governor{ReserveCores: 1, MaxConcurrent: 4}
	g.permits = 4

	// The machine is pinned by OUR OWN live auditing, which this governor does
	// not control: self and machine are both 15.9, so nothing else is running.
	for i := 0; i < 200; i++ {
		g.step(sample(15.9, 15.9, 16))
	}
	if p := g.Permits(); p < 1 {
		t.Fatalf("permits fell to %.2f; the backlog would never finish", p)
	}
	if p := g.Permits(); p > 1.01 {
		t.Fatalf("permits %.2f under sustained pressure; it should yield to the floor", p)
	}

	// An explicit floor is honoured.
	g2 := &Governor{ReserveCores: 1, MaxConcurrent: 6, MinPermits: 2}
	g2.permits = 6
	for i := 0; i < 200; i++ {
		g2.step(sample(15.9, 15.9, 16))
	}
	if p := g2.Permits(); p < 2 {
		t.Fatalf("explicit floor ignored: %.2f", p)
	}

	// But the floor does not apply when the pressure is somebody else's: 15.9
	// busy of which only 0.1 is ours means the box has no room for us at all.
	g3 := &Governor{ReserveCores: 1, MaxConcurrent: 4}
	g3.permits = 4
	for i := 0; i < 200; i++ {
		g3.step(sample(0.1, 15.9, 16))
	}
	if p := g3.Permits(); p > 0.5 {
		t.Fatalf("permits %.2f while the neighbours hold the machine; the floor must not apply", p)
	}
}
