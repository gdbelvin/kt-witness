package audit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/cpuload"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Pacing the backlog sweep against measured CPU.
//
// # Why a controller rather than a number
//
// How much history can be swept per round is not a constant. It depends on the
// proof sizes a log happens to be publishing, how far behind the live sweep is,
// how many cores the box has today, and what else is running on it. Every fixed
// value is wrong somewhere: `historyBudgetPerRound = 4` was chosen when one
// verification took 94 seconds on four cores, and after a hardware change the
// same number left five cores idle while the backlog stretched to months.
//
// So the operator states an intent — "use about five cores for backlog fill" —
// and this closes the loop.
//
// # What it paces, and what it does not
//
// Only the BACKWARDS sweep. Live auditing follows the tip and is the part that
// would notice an operator misbehaving now; throttling it to save CPU would be
// trading incident detection for a completeness metric. History is a
// completeness exercise and can wait, so history is what yields.
//
// # Two signals, not one
//
// Our own usage says how hard we are pushing. The machine's says whether there
// is room. Watching only the first would hold five cores while the host
// thrashed — and this host also runs the home automation and a baby monitor.
// Watching only the second could not separate our load from the neighbours'.
// The permit count is driven by whichever of the two is more constraining.
type Governor struct {
	// TargetCores is how much CPU the backlog sweep should aim to use.
	TargetCores float64

	// MachineLimit is the fraction of the host's cores that may be busy in
	// total before the sweep yields regardless of its own usage. Defaults to
	// 0.85: leaving headroom is what stops a background task from being the
	// reason something interactive stutters.
	MachineLimit float64

	// MaxConcurrent caps permits however much headroom appears. The sidecar
	// pool is the real ceiling — permits above it buy nothing and would let the
	// controller wind up against a limit it cannot reach.
	MaxConcurrent int

	Log *slog.Logger

	mu       sync.Mutex
	permits  float64
	inFlight int
	last     cpuload.Sample
}

const (
	// defaultMachineLimit leaves ~15% of the host free.
	defaultMachineLimit = 0.85

	// governorInterval is how often the loop measures and corrects. Long enough
	// that a single 25-second verification does not dominate a sample, short
	// enough to yield promptly when the machine gets busy.
	governorInterval = 15 * time.Second

	// gain converts a core-error into a permit-change. Deliberately below 1:
	// each permit is worth several cores once a verification is running, so
	// correcting the full error at once oscillates.
	gain = 0.35
)

func (g *Governor) machineLimit() float64 {
	if g.MachineLimit > 0 {
		return g.MachineLimit
	}
	return defaultMachineLimit
}

// Run measures and adjusts until ctx is done.
func (g *Governor) Run(ctx context.Context) {
	s := cpuload.NewSampler()
	s.Sample() // establish the baseline; the first reading spans no interval

	// Start at one permit rather than zero. Zero with a broken sampler would
	// stall the sweep silently, and silence is the failure mode this project
	// keeps having to design against.
	g.mu.Lock()
	g.permits = 1
	g.mu.Unlock()

	t := time.NewTicker(governorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.step(s.Sample())
	}
}

// step applies one correction.
func (g *Governor) step(sample cpuload.Sample) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.last = sample

	maxP := float64(g.MaxConcurrent)
	if maxP <= 0 {
		maxP = 1
	}

	// Always publish what the controller sees, including when it sees nothing.
	// Emitting only on a good sample makes the controller invisible in exactly
	// the situation where you most need to know what it is doing.
	complete := 0.0
	if sample.Complete {
		complete = 1
	}
	metrics.Set("kt_witness_cpu_sample_complete", nil, complete)
	metrics.Set("kt_witness_cpu_self_cores", nil, sample.SelfCores)
	metrics.Set("kt_witness_cpu_machine_cores", nil, sample.MachineCores)
	metrics.Set("kt_witness_audit_permits", nil, g.permits)
	metrics.Set("kt_witness_audit_in_flight", nil, float64(g.inFlight))

	if !sample.Complete {
		// Cannot see. Hold at a conservative single permit rather than guessing
		// in either direction: speeding up blind is how a background task
		// becomes an incident, and stopping blind is how a metric silently
		// freezes.
		if g.permits > 1 {
			g.permits = 1
		}
		if g.permits < 1 {
			g.permits = 1
		}
		return
	}

	// Two constraints; the tighter one wins.
	selfError := g.TargetCores - sample.SelfCores
	headroom := sample.Headroom(g.machineLimit())
	err := selfError
	if headroom < err {
		err = headroom
	}

	g.permits += err * gain
	if g.permits < 0 {
		g.permits = 0
	}
	if g.permits > maxP {
		g.permits = maxP
	}

	metrics.Set("kt_witness_audit_permits", nil, g.permits)

	if g.Log != nil {
		g.Log.Debug("backlog pacing", "self_cores", fmt.Sprintf("%.2f", sample.SelfCores),
			"machine_cores", fmt.Sprintf("%.2f", sample.MachineCores),
			"headroom", fmt.Sprintf("%.2f", headroom),
			"permits", fmt.Sprintf("%.2f", g.permits), "in_flight", g.inFlight)
	}
}

// Acquire blocks until the sweep is allowed to start another verification.
//
// Permits are fractional and in-flight work is integral, so the comparison is
// "is there at least one whole permit spare". At zero permits the sweep pauses
// entirely, which is the correct response to a busy machine.
func (g *Governor) Acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	for {
		g.mu.Lock()
		if float64(g.inFlight) < g.permits {
			g.inFlight++
			g.mu.Unlock()
			return nil
		}
		g.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (g *Governor) Release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	g.mu.Unlock()
}

// Permits reports the current allowance, for logging and tests.
func (g *Governor) Permits() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.permits
}
