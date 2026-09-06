package proton

import (
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Reporting what the replay is actually doing.
//
// # Why
//
// The replay stalled for six hours and the only way to see it was to SSH in and
// `stat` the partial tree file twice, a minute apart, to notice the byte count
// was not moving. Nothing in the metrics or the logs said anything: a step emits
// one line when it finishes and nothing at all while it runs, so a step that
// never finishes is perfectly silent.
//
// That is the worst shape a failure can take in this project, and it has now
// happened enough times to be a pattern rather than an accident. A nineteen
// minute operation that reports only on success cannot be distinguished from a
// six hour hang except by looking at the filesystem.
//
// # What is reported
//
// The phase, the epoch, and when the phase started. Phase matters because the
// two halves of a rebuild fail differently and are fixed differently: ApplyDiff
// is I/O bound and single-threaded through one writer, while TreeRootParallel is
// CPU bound and governed by the worker cap. Knowing which one is running turns
// "Proton is slow" into a specific question — and the first time this was
// diagnosed, the guess named the wrong phase.

// Phases of one rebuild.
const (
	PhaseIdle     = 0
	PhaseFetch    = 1 // downloading the published diff
	PhaseApply    = 2 // merging it into a new tree: I/O bound
	PhaseHash     = 3 // recomputing the root: CPU bound
	PhaseBootstrp = 4 // one-off full tree download
	PhaseWaiting  = 5 // blocked on stepMu, waiting for the other replay
)

var (
	progMu    sync.Mutex
	progPhase = map[string]int{}
	progSince = map[string]time.Time{}
	progEpoch = map[string]int64{}
)

// SetPhase records what a replay is doing now. The label distinguishes the tip
// replay from the history replay, which are separate trees making separate
// progress.
func SetPhase(replay string, phase int, epoch int64) {
	progMu.Lock()
	progPhase[replay] = phase
	progSince[replay] = time.Now()
	progEpoch[replay] = epoch
	progMu.Unlock()
	ReportProgress()
}

// ReportProgress publishes the current phase and how long it has been running.
//
// The elapsed time is the point. A phase value alone says what is happening; the
// duration says whether it is progressing, and a rebuild that has been hashing
// for six hours is the alert this whole file exists to make possible.
func ReportProgress() {
	progMu.Lock()
	defer progMu.Unlock()
	now := time.Now()
	for replay, phase := range progPhase {
		l := map[string]string{"replay": replay}
		metrics.Set("kt_witness_proton_phase", l, float64(phase))
		metrics.Set("kt_witness_proton_epoch", l, float64(progEpoch[replay]))
		if t, ok := progSince[replay]; ok {
			metrics.Set("kt_witness_proton_phase_seconds", l, now.Sub(t).Seconds())
		}
	}
}

// Cores claimed by a rebuild in flight.
//
// Exported as a number rather than a boolean because the consumer — the audit
// governor — needs to subtract a quantity from a core budget, and a boolean
// would force it to duplicate the worker-count decision made in tree.go.
var (
	coreMu    sync.Mutex
	coresHeld float64
)

// ClaimedCores reports the cores currently claimed by a rebuild, for a
// scheduler that has to plan around them. Zero when no rebuild is running.
func ClaimedCores() float64 {
	coreMu.Lock()
	defer coreMu.Unlock()
	return coresHeld
}

func claimCores(n int) {
	coreMu.Lock()
	coresHeld = float64(n)
	coreMu.Unlock()
	metrics.Set("kt_witness_proton_claimed_cores", nil, float64(n))
}

func releaseCores() {
	coreMu.Lock()
	coresHeld = 0
	coreMu.Unlock()
	metrics.Set("kt_witness_proton_claimed_cores", nil, 0)
}
