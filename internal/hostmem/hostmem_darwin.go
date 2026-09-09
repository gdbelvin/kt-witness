package hostmem

import (
	"os/exec"
	"strconv"
	"strings"
)

// macOS has no MemAvailable, so this reads vm_stat and adds the page classes
// the kernel can hand out without swapping: free, inactive, speculative and
// purgeable.
//
// Inactive pages are the interesting term. They hold data that has not been
// touched recently and are reclaimed before anything swaps, so a Mac showing
// almost nothing "free" — which is the normal state — still has room. Counting
// only free pages would make every healthy laptop look full.
//
// Shelling out to vm_stat rather than calling host_statistics64, because the
// latter needs cgo and this is read once every fifteen seconds.
func available() (uint64, bool) {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0, false
	}
	var pageSize uint64 = 4096
	pages := map[string]uint64{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Mach Virtual Memory Statistics") {
			// "... (page size of 16384 bytes)"
			if i := strings.Index(line, "page size of "); i >= 0 {
				f := strings.Fields(line[i+len("page size of "):])
				if len(f) > 0 {
					if n, err := strconv.ParseUint(f[0], 10, 64); err == nil && n > 0 {
						pageSize = n
					}
				}
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), "."), 10, 64)
		if err != nil {
			continue
		}
		pages[strings.TrimSpace(k)] = n
	}
	if len(pages) == 0 {
		return 0, false
	}
	var total uint64
	for _, k := range []string{
		"Pages free",
		"Pages inactive",
		"Pages speculative",
		"Pages purgeable",
	} {
		total += pages[k]
	}
	if total == 0 {
		return 0, false
	}
	return total * pageSize, true
}
