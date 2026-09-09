//go:build !darwin

package main

import (
	"fmt"
	"runtime"
	"syscall"
)

// Elsewhere there is no E-core cluster to ask for, so settle for being polite:
// the lowest scheduling priority the process may set for itself, and half the
// machine. A worker that makes its host unpleasant to use gets turned off, and
// a worker that is turned off verifies nothing.
func background() (string, error) {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
	n := runtime.NumCPU() / 2
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
	return fmt.Sprintf("nice 19, %d of %d cores", n, runtime.NumCPU()), nil
}
