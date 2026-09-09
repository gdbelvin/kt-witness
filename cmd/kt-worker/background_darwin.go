package main

import (
	"fmt"
	"runtime"
	"syscall"
)

// macOS does not expose CPU affinity, so a process cannot be pinned to the
// efficiency cores directly. What it exposes instead is intent: a process in
// the background quality-of-service class is scheduled onto the E-cores, given
// throttled disk I/O, and yields to anything the user is actually waiting on.
// That is a better fit than affinity anyway — the goal is "never make this
// laptop feel slow", not "occupy exactly these cores".
//
// PRIO_DARWIN_PROCESS applies it to every thread, including the ones the Go
// runtime creates later, which per-thread QoS would miss.
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000
)

// background asks the OS to treat this process as background work and caps the
// runtime to the efficiency core count. Both matter: the QoS class decides
// WHERE threads run, and GOMAXPROCS decides how many the scheduler will try to
// keep busy — without the cap, Go spawns one per logical CPU and they all
// contend for the four E-cores.
func background() (string, error) {
	if err := syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG); err != nil {
		return "", fmt.Errorf("entering background QoS: %w", err)
	}
	n := efficiencyCores()
	runtime.GOMAXPROCS(n)
	return fmt.Sprintf("background QoS, %d efficiency cores of %d logical", n, runtime.NumCPU()), nil
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
