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

	// MaxConcurrent caps permits however much headroom appears. The verifier's
	// own concurrency limit is the real ceiling — permits above it buy nothing
	// and would let the controller wind up against a limit it cannot reach.
	MaxConcurrent int

	Log *slog.Logger

	mu       sync.Mutex
	permits  float64
	inFlight int
	last     cpuload.Sample
	// started records whether a complete sample has been applied. The first one
	// sets the permit level outright; the rest correct it.
	started bool
}

const (
	// defaultReserveCores leaves two cores for everything else on the box.
	//
	// Two rather than one, and the same rule the workers use: N-2 is the budget
	// everywhere in this project, so a machine behaves the same whether it is
	// the witness, a laptop or the GPU box. One core was enough for the
	// scheduler and not enough for the host — this box also runs the home
	// automation and a baby monitor, and the second core is what keeps them
	// responsive while thirty verifications run.
	//
	// It is a count rather than a fraction on purpose. A fraction silently
	// reserves more as machines grow, which is the opposite of what a bigger
	// machine is for.
	defaultReserveCores = 2

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
// It deliberately does NOT subtract Proton's rebuild, and an earlier version of
// this that did was wrong in a way worth writing down, because the reasoning
// that produced it is tempting.
//
// The observation was real: the rebuild runs in this process, so the sampler
// counts it as our usage, and with the rebuild taking six cores of a 31-core
// budget the sweep expanded into the other twenty-five and the rebuild crawled.
// Reserving its cores looked like the fix. It is not, for two reasons.
//
// Arithmetically it cancels. Done properly the reservation comes off both sides
// — the sweep may use (total - reserve - R) and is using (self - R) — and those
// R terms subtract out, leaving exactly this expression. Taking it off only the
// budget, as that version did, counts the same cores twice: the ceiling fell to
// 15 while Proton alone held 16, so the controller drove the sweep toward zero
// chasing a total it could never reach. Measured on the deployed box: permits
// floored at 1, and fifteen of thirty-two cores idle.
//
// And it solves the wrong problem. This governor's job is the machine's total
// load. How that total divides between the rebuild and the sweep is set by
// PROTON_TREE_WORKERS, which is a static share precisely because the two have
// incomparable shapes — a permit bounds a ~37-second verification, a rebuild
// runs for hours. The rebuild was not being starved by the governor. It was
// configured to take six cores, and six cores is what it got.
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

	// The first complete sample sets the level; every one after it corrects.
	//
	// Integrating up from zero at 0.35 of the error takes three ticks — 45
	// seconds — to reach full width on an idle machine, and during it the
	// worker reports "the machine is busy; narrowing" about a box at a load
	// average of 1.5 on forty cores. That is not a controller being careful,
	// it is a controller reporting its own startup as a property of the host.
	//
	// A measurement is not a guess, so there is nothing to approach carefully:
	// the first one says how much room there is, and the gain exists to damp
	// oscillation between corrections, not to distrust the first reading.
	if !g.started {
		g.started = true
		g.permits = err
	} else {
		g.permits += err * gain
	}

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

// Spare reports how much of the allowance nobody is using: permits less what
// Acquire currently holds.
//
// It exists because this machine has two consumers of the same budget and only
// one of them takes permits. The backwards sweep Acquires per epoch; the queue
// worker sizes a whole assignment at once and holds nothing. Reading Permits
// alone, each would size itself for the full allowance and the box would run
// two full-width sweeps — sixteen proof replays at 3.7 GB against a 44 GB
// limit, which is an OOM kill of the whole witness, equivocation detection
// included.
func (g *Governor) Spare() float64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.permits - float64(g.inFlight)
}

// Permits reports the current allowance, for logging and tests.
func (g *Governor) Permits() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.permits
}

// WaitForWork blocks until the machine has room for want concurrent
// verifications, and is how a worker paces its REQUESTS for work.
//
// It deliberately takes no permit and holds nothing. An earlier design had the
// worker Acquire around each epoch, which put the governor in the middle of an
// assignment it had already accepted: the machine would take a lease on a
// range, then refuse to work it, and the range sat on a timer while the worker
// idled. Pacing belongs at the point where more work is taken on, because that
// is the only decision that is still free to be made differently.
//
// want is the parallelism the caller is about to use, so the question asked is
// the honest one — "can this machine support the work I am about to start" —
// rather than "is there one core spare", which is true on a machine already
// saturated by this same worker.
//
// Note that permits are floored at minPermits, so a caller asking for one will
// never wait. That is intended: a worker that intends to do one thing at a time
// is not what a busy machine needs protecting from.
// Ready is WaitForWork's question without the waiting, so a caller can say out
// loud that it is holding back. A gate that blocks silently is indistinguishable
// from a broken worker, and this project keeps rediscovering that.
func (g *Governor) Ready(want float64) bool {
	if g == nil {
		return true
	}
	if want < 1 {
		want = 1
	}
	return g.Permits() >= want
}

func (g *Governor) WaitForWork(ctx context.Context, want float64) error {
	if g == nil {
		return nil
	}
	if want < 1 {
		want = 1
	}
	for {
		if g.Permits() >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(governorInterval / 3):
		}
	}
}

// Observed reports the last measured machine load and the ceiling it is being
// held to, both in cores. For telling somebody else what this machine is doing.
func (g *Governor) Observed() (load, budget float64) {
	if g == nil {
		return 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last.MachineCores, g.budget(g.last.TotalCores)
}

// Measured reports whether the controller has seen a usable sample yet.
//
// It exists because "narrow the work to what the machine can afford" and "we
// have not looked at the machine yet" are different answers, and permits alone
// cannot tell them apart: the blind branch above holds at one permit
// deliberately, which read as a width means the first assignment after a
// restart runs at an eighth of the machine for its whole twenty-minute lease.
//
// The static figure a worker starts with is the operator's own statement about
// what may be used. Narrowing below it is a claim that needs evidence, and
// before the first complete sample there is none.
func (g *Governor) Measured() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last.Complete
}
