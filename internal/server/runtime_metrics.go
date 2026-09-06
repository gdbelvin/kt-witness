package server

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Publishing the facts that otherwise required a shell.
//
// Every one of these was read by hand during a diagnosis this week, over SSH,
// because the witness did not publish it:
//
//   - `docker stats` for the container's memory against its limit
//   - `free -g` for the machine's
//   - `/sys/fs/cgroup/memory.events` for reclaim pressure
//   - `nproc` for how many cores the process actually has
//
// The last two mattered most. memory.events showed the cgroup had hit its
// ceiling 30,596 times — the single fact that explained a six-hour stall — and
// nothing surfaced it; it was found by guessing to look. A number that important
// should not depend on someone thinking to run `cat`.
//
// # Why memory.events in particular
//
// `max` counts how often the cgroup hit its limit and had to reclaim. It is not
// an error and never appears in a log, but sustained growth means the process is
// spending its time evicting and re-faulting pages rather than working — a
// slowdown with no error, which is this project's recurring failure shape.
// `oom_kill` is the same signal after it has stopped being survivable.

// RefreshRuntimeMetrics publishes process, container and machine resource facts.
func RefreshRuntimeMetrics() {
	metrics.Set(MProcCores, nil, float64(runtime.NumCPU()))
	metrics.Set(MProcGoroutines, nil, float64(runtime.NumGoroutine()))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	metrics.Set(MProcHeapBytes, nil, float64(ms.HeapAlloc))
	metrics.Set(MProcSysBytes, nil, float64(ms.Sys))

	if v, ok := readCgroupInt("/sys/fs/cgroup/memory.current"); ok {
		metrics.Set(MCgroupMemBytes, nil, float64(v))
	}
	if v, ok := readCgroupInt("/sys/fs/cgroup/memory.max"); ok {
		metrics.Set(MCgroupMemLimit, nil, float64(v))
	}
	for k, v := range readCgroupKV("/sys/fs/cgroup/memory.events") {
		// "max" and "oom_kill" are the ones worth alerting on; the rest are
		// exported too rather than filtered, because the next thing worth
		// knowing is rarely the one that was anticipated.
		metrics.Set(MCgroupMemEvents, map[string]string{"event": k}, float64(v))
	}
	if v, ok := readCgroupInt("/sys/fs/cgroup/cpu.max"); ok {
		metrics.Set(MCgroupCPUMax, nil, float64(v))
	}

	if total, avail, ok := readMemInfo(); ok {
		metrics.Set(MMachineMemBytes, nil, float64(total))
		metrics.Set(MMachineMemAvail, nil, float64(avail))
	}
}

func readCgroupInt(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(strings.TrimSpace(string(b)))
	if len(f) == 0 || f[0] == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func readCgroupKV(path string) map[string]int64 {
	out := map[string]int64{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			out[f[0]] = n
		}
	}
	return out
}

// readMemInfo returns the machine's total and available memory.
//
// /proc/meminfo is not namespaced, so inside a container these describe the
// host. That is deliberate: the container's own limit is already reported from
// the cgroup, and the question these answer is whether that limit is backed by
// anything.
func readMemInfo() (total, avail int64, ok bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = n * 1024
		case "MemAvailable:":
			avail = n * 1024
		}
	}
	return total, avail, total > 0
}
