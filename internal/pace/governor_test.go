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

import (
	"context"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/cpuload"
)

func sample(self, machine, total float64) cpuload.Sample {
	return cpuload.Sample{
		SelfCores: self, MachineCores: machine, TotalCores: total,
		Interval: 15 * time.Second, Complete: true,
	}
}

// TestGovernorConvergesToTarget: under-use raises permits, over-use lowers them.
func TestGovernorConvergesToTarget(t *testing.T) {
	g := &Governor{ReserveCores: 11, MaxConcurrent: 6} // 16-11 = 5 core budget
	g.permits = 1

	// Idle machine, well under target: permits should climb.
	for i := 0; i < 40; i++ {
		g.step(sample(0.5, 1.0, 16))
	}
	if p := g.Permits(); p < 5 {
		t.Fatalf("permits %.2f after sustained under-use, expected to climb toward the cap", p)
	}

	// Now over target: permits should fall back.
	for i := 0; i < 40; i++ {
		g.step(sample(9.0, 10.0, 16))
	}
	if p := g.Permits(); p > 1 {
		t.Fatalf("permits %.2f while using 9 cores against a 5-core target", p)
	}
}

// TestGovernorYieldsToABusyMachine is the property that keeps this from being a
// nuisance: even when our own usage is below target, a busy host must hold us
// back. This box also runs home automation and a baby monitor.
func TestGovernorYieldsToABusyMachine(t *testing.T) {
	g := &Governor{ReserveCores: 11, MaxConcurrent: 6} // 16-11 = 5 core budget
	g.permits = 5

	// We are using almost nothing, but the machine is nearly saturated by work
	// that is not ours: 15.5 of 16 cores, with only 0.2 of it ours. The backlog
	// must get out of the way entirely — the floor protects it from our own
	// live auditing, not from the neighbours.
	for i := 0; i < 60; i++ {
		g.step(sample(0.2, 15.5, 16))
	}
	if p := g.Permits(); p > 0.5 {
		t.Fatalf("permits %.2f while others hold the machine; the sweep must yield", p)
	}
}

// TestGovernorHoldsWhenBlind pins the failure direction. An unreadable sample
// must not be treated as an idle machine — that would speed up precisely when
// the controller cannot see — nor as a reason to stop, which would freeze the
// backlog silently.
func TestGovernorHoldsWhenBlind(t *testing.T) {
	g := &Governor{ReserveCores: 11, MaxConcurrent: 6} // 16-11 = 5 core budget
	g.permits = 4
	for i := 0; i < 10; i++ {
		g.step(cpuload.Sample{TotalCores: 16}) // Complete == false
	}
	if p := g.Permits(); p != 1 {
		t.Fatalf("permits %.2f with no usable measurement, want a conservative 1", p)
	}
}

// TestGovernorNeverExceedsPoolSize: permits above the sidecar pool buy nothing
// and would wind the controller up against a limit it cannot reach.
func TestGovernorNeverExceedsPoolSize(t *testing.T) {
	g := &Governor{ReserveCores: 1, MaxConcurrent: 3}
	g.permits = 1
	for i := 0; i < 200; i++ {
		g.step(sample(0.1, 0.5, 64))
	}
	if p := g.Permits(); p > 3 {
		t.Fatalf("permits %.2f exceeds the pool size of 3", p)
	}
}

// TestAcquireRespectsPermits checks the gate itself, including that zero
// permits pauses the sweep rather than letting it through.
func TestAcquireRespectsPermits(t *testing.T) {
	g := &Governor{ReserveCores: 11, MaxConcurrent: 4}
	g.permits = 2

	ctx := context.Background()
	if err := g.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	// Third must block: 2 in flight against 2 permits.
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if err := g.Acquire(short); err == nil {
		t.Fatal("acquired a third permit when only two were allowed")
	}

	g.Release()
	if err := g.Acquire(ctx); err != nil {
		t.Fatalf("a released permit was not reusable: %v", err)
	}

	// Zero permits pauses entirely.
	g2 := &Governor{ReserveCores: 11, MaxConcurrent: 4}
	g2.permits = 0
	short2, cancel2 := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel2()
	if err := g2.Acquire(short2); err == nil {
		t.Fatal("work started with zero permits")
	}
}

// A nil Governor must be a no-op, so pacing can be switched off in config
// without the history sweep having to know.
func TestNilGovernorIsInert(t *testing.T) {
	var g *Governor
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("nil governor blocked: %v", err)
	}
	g.Release()
}

// TestBudgetIsDerivedFromTheMachine is the property that keeps this correct
// across hardware changes.
//
// A fixed number has now been wrong three times here: a per-round budget chosen
// for a four-core box, a five-core target on a sixteen-core one, and a pool cap
// that held a thirty-two-core machine at eight. "Leave two cores free" survives
// all of them, and it is the same rule every worker uses — a machine behaves the
// same way whether it is the witness, a laptop or the GPU box.
//
// A count rather than a fraction, deliberately: a fraction reserves more as
// machines grow, which is the opposite of what a bigger machine is for.
func TestBudgetIsDerivedFromTheMachine(t *testing.T) {
	g := &Governor{} // defaults: reserve 2
	for _, c := range []struct{ cores, want float64 }{
		{16, 14}, {4, 2}, {64, 62}, {32, 30},
		{1, 1}, // a one-core box still gets to make progress
		{2, 1}, // and so does a two-core one
	} {
		if got := g.BudgetFor(c.cores); got != c.want {
			t.Errorf("%.0f cores: budget %.1f, want %.1f", c.cores, got, c.want)
		}
	}

	// An explicit target overrides the derivation.
	g2 := &Governor{TargetCores: 5}
	if got := g2.BudgetFor(64); got != 5 {
		t.Errorf("explicit target ignored: %.1f", got)
	}

	// A larger reservation yields more.
	g3 := &Governor{ReserveCores: 4}
	if got := g3.BudgetFor(16); got != 12 {
		t.Errorf("reserve 4 of 16: budget %.1f, want 12", got)
	}
}

// TestSelfAndMachineConstraintsCannotContradict: because both are measured
// against one derived budget, the machine term can only ever bind at or before
// the self term. The earlier design allowed a self target above the machine
// ceiling, which silently starved the sweep.
func TestSelfAndMachineConstraintsCannotContradict(t *testing.T) {
	g := &Governor{ReserveCores: 1, MaxConcurrent: 3}
	g.permits = 1

	// Idle box: both terms permit growth, so permits reach the cap.
	for i := 0; i < 60; i++ {
		g.step(sample(1.0, 1.5, 16))
	}
	if p := g.Permits(); p < 3 {
		t.Fatalf("permits %.2f on an idle 16-core box, expected the pool cap", p)
	}

	// Neighbours arrive and take the machine past the budget on their own —
	// 15.8 busy of which only 0.3 is ours. There is no room for us, so the
	// backlog yields completely; the floor protects it from our own live
	// auditing, not from other tenants.
	for i := 0; i < 60; i++ {
		g.step(sample(0.3, 15.8, 16))
	}
	if p := g.Permits(); p > 0.5 {
		t.Fatalf("permits %.2f while others hold 15.5 cores of a 15-core budget", p)
	}
}

// TestBudgetIgnoresWhatElseThisProcessIsDoing pins the correction to a fix that
// was deployed and had to be taken back out.
//
// Proton's tree rebuild runs in this same process, so the sampler counts it as
// our usage. Reserving its cores — subtracting them from this budget — looked
// like the way to stop the sweep competing with it. On the deployed box that
// floored permits at 1 and left fifteen of thirty-two cores idle, because the
// same cores were then counted twice: once removed from the ceiling, and again
// in the SelfCores measured against it.
//
// The budget is a statement about the machine, and nothing about what this
// process happens to be running. How the total divides between the sweep and a
// rebuild is PROTON_TREE_WORKERS' job.
func TestBudgetIgnoresWhatElseThisProcessIsDoing(t *testing.T) {
	g := &Governor{}
	want := g.BudgetFor(32)
	if want != 30 {
		t.Fatalf("budget %.1f, want 30", want)
	}
	// Whatever else the process is doing, the ceiling for the machine is the
	// same number. There is no input here for it to depend on, and that is the
	// property being pinned.
	for _, cores := range []float64{16, 32, 64} {
		if got := g.BudgetFor(cores); got != cores-2 {
			t.Errorf("%.0f cores: budget %.1f, want %.1f", cores, got, cores-2)
		}
	}
}
