package audit

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Choosing how many sidecar workers to run.
//
// The tempting rule is one worker per core. It is wrong here, and expensively
// so: a single verification is already multi-threaded — the Rust AKD verifier
// parallelises internally — so on this deployment three workers consume five to
// nine of sixteen cores. One per core would oversubscribe the CPU by roughly
// threefold and, far worse, ask for one 3.7 GB working set per core: about
// 55 GB on a machine with 31.
//
// So the pool is bounded by MEMORY, and the CPU governor handles the rest. That
// split matches what each thing actually constrains. Exceeding memory is not a
// slowdown but an OOM kill that takes equivocation detection down with the
// audit; exceeding CPU merely makes everything slower, which the governor
// notices and corrects.
//
// Derived rather than configured for the reason a fixed number has already been
// wrong twice in this project: a per-round budget chosen for a four-core box,
// then a five-core target on a sixteen-core one. An explicit setting still wins
// when given.

// peakVerificationBytes is one verification's high-water mark.
//
// Measured on Meta's proofs, which are the largest thing this witness verifies:
// roughly 3.7 GB resident. Deliberately not trimmed to the observed peak —
// proof sizes vary between epochs, and the cost of overestimating is one fewer
// worker while the cost of underestimating is the container being killed.
const peakVerificationBytes = 4 << 30

// memoryHeadroom is the share of the limit the pool may plan to occupy.
//
// The witness does other things with memory: the store, the tile caches, the
// retained Proton tree. Sizing the pool to the whole limit would leave those
// competing with verifications for the last gigabyte.
const memoryHeadroom = 0.75

// DefaultWorkers picks a pool size from the memory this process may use.
//
// Falls back to one when the limit cannot be read. One worker is slow; a
// guessed-high worker count on an unknown machine is an OOM kill, and this
// project would rather be slow than dead.
func DefaultWorkers() int {
	limit, ok := cgroupMemoryLimit()
	if !ok {
		return 1
	}
	n := int(float64(limit) * memoryHeadroom / float64(peakVerificationBytes))
	if n < 1 {
		n = 1
	}
	// Above roughly one worker per two cores the pool cannot keep them busy —
	// each verification is already parallel — and the extra memory buys queueing
	// rather than throughput.
	if cap := runtime.NumCPU() / 2; cap >= 1 && n > cap {
		n = cap
	}
	return n
}

// cgroupMemoryLimit reads this container's memory ceiling.
//
// cgroup v2 reports "max" when unlimited, which is not a number to divide by:
// treated as unknown so the caller falls back to one worker rather than
// computing a pool size from an absent limit.
func cgroupMemoryLimit() (int64, bool) {
	for _, p := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		// cgroup v1 reports an enormous sentinel when unlimited.
		if n > 1<<52 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
