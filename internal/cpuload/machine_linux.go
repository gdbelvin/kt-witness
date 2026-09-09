//go:build !darwin

package cpuload

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// machineState is one reading of the host's cumulative CPU counters.
type machineState = cpuTimes

func readMachine() (machineState, bool) { return readProcStat() }

// cores converts two readings into cores in use across the machine.
func (c cpuTimes) cores(prev cpuTimes, totalCores float64) (float64, bool) {
	busy, total := c.delta(prev)
	if total <= 0 {
		return 0, false
	}
	return busy / total * totalCores, true
}

// cpuTimes is the aggregate line from /proc/stat.
type cpuTimes struct {
	total, idle float64
}

func (c cpuTimes) delta(prev cpuTimes) (busy, total float64) {
	total = c.total - prev.total
	idle := c.idle - prev.idle
	busy = total - idle
	if busy < 0 {
		busy = 0
	}
	return busy, total
}

func readProcStat() (cpuTimes, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuTimes{}, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 6 || fields[0] != "cpu" {
		return cpuTimes{}, false
	}
	var t cpuTimes
	for i, f := range fields[1:] {
		v, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		t.total += v
		// Fields 3 and 4 (0-indexed) are idle and iowait. Both are time the
		// machine had nothing to do, so both count as free.
		if i == 3 || i == 4 {
			t.idle += v
		}
	}
	return t, true
}

func readSelfUsec(path string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok || k != "usage_usec" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

