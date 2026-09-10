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
	// A memory LIMIT is a promise about what we may use, not evidence the
	// machine has it. Docker will happily accept `mem_limit: 44g` on a 31 GB
	// host, and the pool would then size itself for eight workers and OOM the
	// box — taking equivocation detection down with the audit.
	//
	// This is the same class of mistake as a hardcoded core count: a fact about
	// hardware, written down somewhere, that stopped being true. It bites hardest
	// exactly when the config is raised in anticipation of a resize that has not
	// happened yet, which is precisely the order these changes tend to land in.
	if total, ok := machineMemory(); ok {
		if avail := int64(float64(total) * memoryHeadroom); avail < limit {
			limit = avail
		}
	}
	n := int(float64(limit) * memoryHeadroom / float64(peakVerificationBytes))
	if n < 1 {
		n = 1
	}
	// N-2, the same core budget every part of this project uses.
	//
	// It was half the cores, on the reasoning that each Rust verification is
	// internally parallel so a worker per two cores keeps them busy. That was
	// true of the sidecar and it is a fraction, which is the shape this project
	// has been bitten by three times: a fraction reserves more as machines grow,
	// which is the opposite of what a bigger machine is for. Two cores left for
	// the host is a statement that stays true from a laptop to this box.
	if cap := runtime.NumCPU() - 2; cap >= 1 && n > cap {
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

// machineMemory reports the host's total RAM.
//
// /proc/meminfo is not namespaced, so inside a container this is the machine's
// memory rather than the container's share — which is exactly what is wanted
// here: the question is whether the limit we were handed is physically backed.
func machineMemory() (int64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || kb <= 0 {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}
