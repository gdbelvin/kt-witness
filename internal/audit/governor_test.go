package audit

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
	g := &Governor{TargetCores: 5, MaxConcurrent: 6}
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
	g := &Governor{TargetCores: 5, MaxConcurrent: 6}
	g.permits = 5

	// We are using almost nothing, but the machine is nearly saturated:
	// 15.5 of 16 cores busy, against a default 0.85 limit (13.6).
	for i := 0; i < 40; i++ {
		g.step(sample(0.2, 15.5, 16))
	}
	if p := g.Permits(); p > 0.5 {
		t.Fatalf("permits %.2f on a saturated host; the sweep must yield to its neighbours", p)
	}
}

// TestGovernorHoldsWhenBlind pins the failure direction. An unreadable sample
// must not be treated as an idle machine — that would speed up precisely when
// the controller cannot see — nor as a reason to stop, which would freeze the
// backlog silently.
func TestGovernorHoldsWhenBlind(t *testing.T) {
	g := &Governor{TargetCores: 5, MaxConcurrent: 6}
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
	g := &Governor{TargetCores: 100, MaxConcurrent: 3}
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
	g := &Governor{TargetCores: 5, MaxConcurrent: 4}
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
	g2 := &Governor{TargetCores: 5, MaxConcurrent: 4}
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
