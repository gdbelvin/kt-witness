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
	// ReserveCores is how many cores to leave free. The target is derived from
	// the machine: aim to drive total usage to (cores - reserve).
	//
	// Expressed as a reservation rather than a target because a target is a
	// statement about hardware that will change, and this project has already
	// been bitten twice by exactly that — a fixed per-round budget chosen for a
	// four-core box, and then a fixed five-core target on a sixteen-core one.
	// "Leave one core free" stays true across both.
	//
	// Defaults to 1.
	ReserveCores float64

	// TargetCores optionally overrides the derived target, for an operator who
	// wants to use less than the machine allows. Zero means derive.
	TargetCores float64

	// MinPermits is the allowance the backlog keeps however busy the machine
	// is. Zero means the default of one.
	//
	// Without a floor the sweep starves. Live auditing does not ask this
	// governor — it follows the tip and must not be throttled — so it can hold
	// the CPU at budget on its own, at which point the error term goes to zero,
	// permits decay, and the backlog stops entirely. That was observed:
	// permits at 0.47 with the machine pinned, and coverage flat.
	//
	// One permit is a small, permanent share rather than a fair one. The
	// backlog is a completeness exercise and should yield to the tip; it should
	// not yield forever.
	MinPermits float64

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
	// defaultReserveCores leaves one core for everything else on the box. This
	// host also runs the home automation and a baby monitor.
	defaultReserveCores = 1

	// governorInterval is how often the loop measures and corrects. Long enough
	// that a single 25-second verification does not dominate a sample, short
	// enough to yield promptly when the machine gets busy.
	governorInterval = 15 * time.Second

	// gain converts a core-error into a permit-change. Deliberately below 1:
	// each permit is worth several cores once a verification is running, so
	// correcting the full error at once oscillates.
	gain = 0.35
)

func (g *Governor) minPermits() float64 {
	if g.MinPermits > 0 {
		return g.MinPermits
	}
	return 1
}

func (g *Governor) reserve() float64 {
	if g.ReserveCores > 0 {
		return g.ReserveCores
	}
	return defaultReserveCores
}

// BudgetFor exposes the derived budget for logging.
func (g *Governor) BudgetFor(totalCores float64) float64 { return g.budget(totalCores) }

// budget returns the usage ceiling for this machine, in cores.
//
// The same figure bounds both our own usage and the machine's total. They
// coincide deliberately: machine usage always includes ours, so a single
// ceiling means the two constraints can never contradict each other. The
// previous shape — a self target in cores and a machine limit as a fraction —
// could be configured so the machine term bound first and silently starved the
// sweep, which is what it did.
func (g *Governor) budget(totalCores float64) float64 {
	if g.TargetCores > 0 {
		return g.TargetCores
	}
	b := totalCores - g.reserve()
	if b < 1 {
		b = 1 // a one-core box still gets to make progress
	}
	return b
}

// Run measures and adjusts until ctx is done.
func (g *Governor) Run(ctx context.Context) {
	s := cpuload.NewSampler()
	s.Sample() // establish the baseline; the first reading spans no interval

	// Start at one permit rather than zero. Zero with a broken sampler would
	// stall the sweep silently, and silence is the failure mode this project
	// keeps having to design against.
	g.mu.Lock()
	g.permits = g.minPermits()
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

	// Two constraints against one budget; the tighter one wins. Machine usage
	// includes ours, so in an otherwise idle box they coincide and in a busy one
	// the machine term binds first — which is the yielding behaviour wanted.
	budget := g.budget(sample.TotalCores)
	selfError := budget - sample.SelfCores
	headroom := budget - sample.MachineCores
	err := selfError
	if headroom < err {
		err = headroom
	}

	g.permits += err * gain

	// The floor holds against our own load, not against the neighbours'.
	//
	// Live auditing does not ask this governor, so it can pin the machine by
	// itself; without a floor the backlog would then stop forever, which is how
	// permits reached 0.47 with coverage flat. But when the machine is busy with
	// work that is not ours, yielding is the whole point — this host also runs
	// the home automation and a baby monitor, and holding four cores against
	// them to make a completeness metric move would be the wrong trade.
	//
	// So: if everything else on the box already exceeds the budget, we get out
	// of the way entirely. Otherwise the backlog keeps its small permanent share.
	others := sample.MachineCores - sample.SelfCores
	if others < 0 {
		others = 0
	}
	if others < budget {
		if floor := g.minPermits(); g.permits < floor {
			g.permits = floor
		}
	}
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
