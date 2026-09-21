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

// Cores claimed by a rebuild in flight, published as a metric.
//
// There was a mutex and a float beside it, so that ClaimedCores() could hand
// the number to the audit governor — which never asked. The governor measures
// the machine's actual CPU rather than adding up what each component says it
// intends to use, and that is the better answer: a rebuild that claims four
// cores and uses one would have had the sweep yield to an idle box.
//
// So the only reader is the metric, and a gauge is already safe to set from
// any goroutine.
func claimCores(n int) {
	metrics.Set("kt_witness_proton_claimed_cores", nil, float64(n))
}

func releaseCores() {
	metrics.Set("kt_witness_proton_claimed_cores", nil, 0)
}
