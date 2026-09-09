//go:build !darwin

package hostmem

import (
	"os"
	"strconv"
	"strings"
)

// MemAvailable is the kernel's own estimate of what a new workload could use
// without swapping, which is exactly the question, and it accounts for
// reclaimable cache better than any arithmetic done out here.
//
// Inside a container this reports the HOST's memory, not the cgroup limit. That
// is deliberate for this caller: a worker's neighbours are on the host, and the
// thing to avoid is making the machine swap. Where a cgroup limit is the real
// bound — the witness's own sidecar pool — that is read separately.
func available() (uint64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || kb == 0 {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}
