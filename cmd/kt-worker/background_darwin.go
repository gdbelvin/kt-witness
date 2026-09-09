package main

import (
	"fmt"
	"runtime"
	"syscall"
)

// How much of a Mac to take, and why it is no longer the background QoS class.
//
// The first version asked for PRIO_DARWIN_BG, which schedules every thread onto
// the efficiency cores. That is the strongest "never make this laptop feel
// slow" the OS offers, and it was the right default — but it is also a ceiling.
// The operator's instruction here is more specific and more generous: all six
// efficiency cores plus two of the four performance cores, leaving two
// performance cores for whoever is using the machine.
//
// Background QoS cannot express that. It is not a budget, it is a placement:
// asking for it confines the process to the E-cluster no matter what number is
// set beside it. So the confinement goes and a budget takes its place — a
// thread count the worker holds itself to, at a lowered scheduling priority so
// that anything the owner is waiting on preempts it.
//
// The trade is honest and worth writing down. Background QoS also throttled
// disk I/O and guaranteed the process could never occupy a performance core;
// nice does neither. What protects the machine now is arithmetic — eight of ten
// logical CPUs, and the two left over are the fast ones.
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000 // no longer used; kept so the history is legible
)

// background lowers this process's priority and returns the CPU budget it
// should hold itself to, in logical CPUs.
func background() (string, int, error) {
	// Nice rather than background QoS: still yields to the owner's work, but
	// remains eligible for the performance cores the budget below counts on.
	// Children inherit it, which matters — the sidecars do the actual work.
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
		return "", cpuBudget(), fmt.Errorf("lowering priority: %w", err)
	}
	n := cpuBudget()
	runtime.GOMAXPROCS(n)
	return fmt.Sprintf("nice 10, %d of %d logical CPUs (%d efficiency + %d performance, %d left free)",
		n, runtime.NumCPU(), efficiencyCores(), n-efficiencyCores(),
		runtime.NumCPU()-n), n, nil
}

// cpuBudget is every efficiency core plus two performance cores.
//
// Stated that way rather than as "N-2" because on this machine they are not the
// same number and the difference matters: 6 + 2 is eight of ten, and the two
// held back are performance cores, which is what makes the laptop stay
// responsive rather than merely idle.
func cpuBudget() int {
	e := efficiencyCores()
	p := performanceCores()

	spare := 2 // performance cores left for whoever is using the machine
	take := p - spare
	if take < 0 {
		take = 0
	}
	n := e + take
	if n < 1 {
		n = 1
	}
	// Never take the whole machine, whatever the cluster counts say — an Intel
	// Mac reports no clusters, and a future one might report something this
	// arithmetic did not anticipate.
	if max := runtime.NumCPU() - 2; max >= 1 && n > max {
		n = max
	}
	return n
}

// efficiencyCores reports how many E-cores this machine has.
//
// Darwin exposes perflevel1 as the efficiency cluster on Apple silicon
// (perflevel0 is performance). On an Intel Mac there are no clusters and the
// sysctl is absent, so fall back to something that leaves the machine usable
// rather than to every core.
func efficiencyCores() int {
	if n, err := syscall.SysctlUint32("hw.perflevel1.logicalcpu"); err == nil && n > 0 {
		return int(n)
	}
	if n := runtime.NumCPU() / 2; n > 0 {
		return n
	}
	return 1
}

// performanceCores reports the P-cluster, or zero where there is no cluster
// split to read — in which case cpuBudget falls back to leaving two of whatever
// the machine has.
func performanceCores() int {
	if n, err := syscall.SysctlUint32("hw.perflevel0.logicalcpu"); err == nil && n > 0 {
		return int(n)
	}
	if rest := runtime.NumCPU() - efficiencyCores(); rest > 0 {
		return rest
	}
	return 0
}
