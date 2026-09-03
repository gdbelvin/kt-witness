package audit

import (
	"math"
)

// Three auditing strategies, and why there are three.
//
// The original design sampled a fixed fraction of epochs and nothing else. That
// was a reasonable response to a cost estimate, and the cost estimate was wrong
// in a way worth recording: auditing every Meta and WhatsApp epoch is ~372
// GB/day, which sounded prohibitive until it was measured against a real
// connection and turned out to be about 35 Mbps sustained — under a tenth of
// the link, and roughly 1.7 CPU cores. Sampling the tip was never necessary.
//
// So auditing now runs three ways at once, each covering a case the others
// cannot:
//
//	LIVE      Every epoch at the tip, exhaustively. An attack only accomplishes
//	          anything if the forged binding is served to a victim, which means
//	          recent epochs, which means the tip is where detection has to be
//	          certain rather than probabilistic.
//
//	BACKLOG   When we fall behind — a restart, an outage, a slow operator — the
//	          tip window alone would leave a growing hole. Catch-up is sampled
//	          with a recency bias decaying logarithmically into the past, so the
//	          newest unaudited epochs are done first and older ones are still
//	          reached, just less densely.
//
//	HISTORY   Everything published before we started watching, swept backwards
//	          exhaustively. Those proofs are already fixed, so an operator
//	          cannot retroactively choose what we replay and sampling buys no
//	          unpredictability — it only costs coverage. See history.go.
//
// # Not duplicating work
//
// The three must never audit the same epoch twice: a re-audit is wasted
// bandwidth and CPU on a system where both are the binding constraint, and at
// 372 GB/day the waste is not academic.
//
// They are kept disjoint by construction rather than by checking afterwards:
//
//   - LIVE and BACKLOG are the same forward pass over the range
//     (auditProgress, tip]. Each epoch in that range is considered exactly once
//     and the strategy only decides WHETHER to audit it, never revisits it.
//     Progress advances past every epoch whose decision is settled, audited or
//     declined, so the forward pass never returns to it.
//   - HISTORY sweeps strictly below the forward auditor's floor, downward, and
//     records its own separate high-water mark. The two move away from each
//     other and can never meet twice.
//   - Every strategy consults the stored decision before doing any work, so an
//     epoch already settled by any of them is skipped by all of them. That is
//     the backstop for the case the invariants miss: a restart mid-pass, or a
//     config change that moves the floor.
//
// The store is the single source of truth for "has this epoch been decided",
// which is also what makes coverage measurable rather than assumed.

// Strategy describes how an epoch was chosen, and is recorded with the decision
// so the published record says which rule applied.
type Strategy string

const (
	StrategyLive    Strategy = "live"
	StrategyBacklog Strategy = "backlog"
	StrategyHistory Strategy = "history"
)

// DefaultTipWindow is how many epochs behind the tip are audited
// unconditionally when an Auditor does not choose otherwise.
//
// Sized so that an operator serving a forged binding cannot outrun it: Meta
// publishes every 120 s and WhatsApp every 30 s, so 256 epochs is roughly eight
// hours of Messenger and two of WhatsApp. A forgery that persists long enough
// to reach a victim falls inside that window.
const DefaultTipWindow = 256

// SelectionRate returns the probability that an epoch `age` behind the tip is
// audited, and the strategy that decision belongs to.
//
// Within the tip window the rate is 1: every epoch is audited, no sampling, no
// dice. Beyond it the rate decays logarithmically, which matches how the value
// of auditing an epoch actually falls off — a forged binding from months ago
// can no longer be served to anyone, but it is still worth a look, and log
// decay keeps reaching arbitrarily far back with slowly diminishing density
// rather than cutting off.
//
//	rate(age) = min(1, base / (1 + log2(1 + age - tipWindow)))
//
// It is a pure function of (age, base), both of which are published, so a third
// party recomputes exactly the rate we were obliged to use — the same property
// the beacon gives for the draw itself. A sampling rule nobody can recompute is
// a rate we are merely asserting.
func SelectionRate(age int64, base float64, tipWindow int64) (float64, Strategy) {
	if age < 0 {
		age = 0
	}
	if age < tipWindow {
		return 1, StrategyLive
	}
	if base <= 0 {
		return 0, StrategyBacklog
	}
	// An explicitly configured rate of 1 means "audit everything", and decay
	// must not quietly turn that into less. Decay describes how a PARTIAL
	// budget is spent across the backlog; it is not a reason to skip work an
	// operator has said they want done.
	if base >= 1 {
		return 1, StrategyBacklog
	}
	decay := 1 + math.Log2(1+float64(age-tipWindow))
	rate := base / decay
	if rate > 1 {
		rate = 1
	}
	return rate, StrategyBacklog
}
