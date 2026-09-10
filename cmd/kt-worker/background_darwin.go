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
	prioDarwinBG      = 0x1000
)

// background lowers this process's priority and returns the CPU budget it
// should hold itself to, in logical CPUs.
//
// Two modes, because macOS offers no way to reserve particular cores and the
// two things it does offer sit on either side of what was asked for.
//
// eCoresOnly is the strict one: the background QoS class, which schedules every
// thread onto the efficiency cluster and throttles disk I/O too. It cannot be
// asked for a performance core at all, so it under-uses a machine that is idle
// — but it is the only setting under which a laptop genuinely does not feel
// slower.
//
// The default is a budget instead: a nice level on this process, and N-2
// logical CPUs' worth of threads. This used to say the nice level was inherited
// by children, because the work was done by verifier subprocesses; there are
// none now, so it applies directly to the threads doing the hashing.
//
// Worth being plain about what that does and does not promise — the OS may
// still run those threads on performance cores, and nice is advisory. What is
// enforced is the count.
func background(eCoresOnly bool) (string, int, error) {
	if eCoresOnly {
		if err := syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG); err != nil {
			return "", efficiencyCores(), fmt.Errorf("entering background QoS: %w", err)
		}
		n := efficiencyCores()
		runtime.GOMAXPROCS(n)
		return fmt.Sprintf("background QoS, %d efficiency cores of %d logical",
			n, runtime.NumCPU()), n, nil
	}
	// Nice rather than background QoS: still yields to the owner's work, and
	// remains eligible for the performance cores the budget below counts on.
	// It applies to this process directly, which is what matters now that the
	// verification happens here; children inherit it too.
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
		return "", cpuBudget(), fmt.Errorf("lowering priority: %w", err)
	}
	n := cpuBudget()
	runtime.GOMAXPROCS(n)
	return fmt.Sprintf("nice 10, %d of %d logical CPUs (N-2; this machine has %d efficiency and %d performance)",
		n, runtime.NumCPU(), efficiencyCores(), performanceCores()), n, nil
}

// cpuBudget is N-2: every logical CPU but two.
//
// It was briefly expressed as "every efficiency core plus two performance
// cores", which on this laptop is the same eight of ten — but the cluster
// arithmetic was carrying an implication it could not deliver. macOS has no
// affinity API: the only way to choose which cores run something is the
// background QoS class, and that is all-or-nothing (efficiency only). So a
// budget built from cluster counts still ran wherever the scheduler liked, and
// only the total was ever enforced. N-2 says exactly what is true.
//
// The two held back are logical CPUs, not designated cores. What that buys is
// real anyway — the machine is never fully subscribed by this worker — and
// -efficiency-cores-only is there for anyone who wants the placement guarantee
// instead.
func cpuBudget() int {
	n := runtime.NumCPU() - 2
	if n < 1 {
		n = 1
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
