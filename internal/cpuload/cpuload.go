// Package cpuload measures how much CPU this process is using and how busy the
// machine is, so background work can be paced against both.
//
// Two numbers, because they answer different questions. Our own usage says how
// hard we are pushing; the machine's says whether there is room to push. A
// controller that watched only its own usage would happily hold five cores
// while the host thrashed, and one that watched only the host could not tell
// its own load from somebody else's.
//
// # Where the numbers come from
//
// Own usage: cgroup v2's cpu.stat, whose usage_usec is cumulative CPU time for
// this container. Under a cgroup namespace it appears at /sys/fs/cgroup/cpu.stat.
// Differencing it over a known wall-clock interval gives cores.
//
// Machine usage: /proc/stat, which inside a container is NOT namespaced and so
// reports the host. That is exactly what is wanted here — the neighbours on this
// box are the thing to yield to.
//
// Both of those are Linux. The witness runs there; the machines lent to it may
// not, and a sampler that silently reports nothing on a Mac is worse than one
// that refuses to build — the governor holds at its floor when it cannot see,
// which on a worker means it never asks for work at all and never says why.
// That was not hypothetical: it cost an afternoon. So the two readers are
// per-platform, and every platform has one.
//
// Both are cumulative counters, so a Sampler must be read repeatedly; the first
// reading establishes a baseline and reports nothing.
package cpuload

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Sample is one observation of CPU usage, in cores.
type Sample struct {
	// SelfCores is CPU-seconds per second used by this container.
	SelfCores float64
	// MachineCores is CPU-seconds per second busy across the whole host,
	// excluding idle and iowait.
	MachineCores float64
	// TotalCores is how many the host has.
	TotalCores float64
	// Interval is the wall-clock time the sample covers.
	Interval time.Duration
	// Complete reports whether both figures were obtainable. A partial sample
	// is reported rather than silently zeroed: zero looks like an idle machine,
	// which would make a controller speed up exactly when it cannot see.
	Complete bool
}

// Headroom is how many cores are free before the machine reaches limit
// (a fraction of total, e.g. 0.85). Negative when already past it.
func (s Sample) Headroom(limit float64) float64 {
	return s.TotalCores*limit - s.MachineCores
}

type Sampler struct {
	mu sync.Mutex

	lastSelfUsec  uint64
	lastMachine   machineState
	lastAt        time.Time
	haveBaseline  bool
	selfStatPath  string
	totalCoresNum float64
}

func NewSampler() *Sampler {
	return &Sampler{
		selfStatPath:  "/sys/fs/cgroup/cpu.stat",
		totalCoresNum: float64(runtime.NumCPU()),
	}
}

// Sample returns usage since the previous call. The first call establishes the
// baseline and returns Complete=false.
func (s *Sampler) Sample() Sample {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	selfUsec, selfOK := readSelfUsec(s.selfStatPath)
	machine, machineOK := readMachine()

	out := Sample{TotalCores: s.totalCoresNum}
	if !s.haveBaseline {
		s.lastSelfUsec, s.lastMachine, s.lastAt = selfUsec, machine, now
		s.haveBaseline = selfOK || machineOK
		return out
	}

	elapsed := now.Sub(s.lastAt)
	out.Interval = elapsed
	if elapsed <= 0 {
		return out
	}

	ok := true
	if selfOK && selfUsec >= s.lastSelfUsec {
		out.SelfCores = float64(selfUsec-s.lastSelfUsec) / 1e6 / elapsed.Seconds()
	} else {
		ok = false
	}
	if machineOK {
		if cores, cok := machine.cores(s.lastMachine, s.totalCoresNum); cok {
			out.MachineCores = cores
		} else {
			ok = false
		}
	} else {
		ok = false
	}
	out.Complete = ok

	s.lastSelfUsec, s.lastMachine, s.lastAt = selfUsec, machine, now
	return out
}

func (s Sample) String() string {
	if !s.Complete {
		return "cpu sample incomplete"
	}
	return fmt.Sprintf("self %.2f cores, machine %.2f of %.0f cores",
		s.SelfCores, s.MachineCores, s.TotalCores)
}
