package cpuload

import (
	"encoding/binary"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// macOS has neither /proc/stat nor cgroups, so both numbers come from
// elsewhere — and both are approximations in ways worth stating.
//
// This matters more than it looks. The governor holds at its floor whenever it
// cannot see, which on the witness merely means slow; on a worker it means the
// gate deciding whether to ask for work never opens, so the machine sits idle
// forever and says nothing about why. A Mac with no sampler was therefore a Mac
// that could not be lent to the witness at all — which is most of the hardware
// this channel was built to borrow.

// machineState is one instantaneous reading. Unlike Linux's cumulative
// counters there is nothing to difference, so the previous reading is unused —
// it stays in the signature because the Linux path genuinely needs it.
type machineState struct {
	busy float64 // cores in use, approximately
	at   time.Time
	ok   bool
}

// cores reports what the last reading saw. The previous state is ignored: this
// is a gauge, not a counter.
func (m machineState) cores(_ machineState, totalCores float64) (float64, bool) {
	if !m.ok {
		return 0, false
	}
	if m.busy > totalCores {
		return totalCores, true
	}
	return m.busy, true
}

// readMachine reads the one-minute load average.
//
// Load average is not CPU utilisation. It counts runnable threads, so it
// includes work waiting for a core as well as work using one, and it is a
// one-minute average read by a fifteen-second control loop — it lags, and it
// overstates a machine that is thrashing on I/O. Both errors point the same
// way, and it is the safe way: this number decides whether to take MORE work
// onto somebody else's laptop, and being slow to grab it is the right failure.
//
// host_processor_info would give true utilisation and needs cgo. Not worth a C
// toolchain in the build for a number whose job is to be conservative.
func readMachine() (machineState, bool) {
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return machineState{}, false
	}
	return parseLoadavg(b)
}

// struct loadavg { fixpt_t ldavg[3]; long fscale; } — three 32-bit fixed-point
// values, then the scale they are expressed in, with alignment padding between
// the array and the long.
func parseLoadavg(b []byte) (machineState, bool) {
	if len(b) < 24 {
		return machineState{}, false
	}
	ld1 := binary.LittleEndian.Uint32(b[0:4])
	scale := binary.LittleEndian.Uint64(b[16:24])
	if scale == 0 {
		return machineState{}, false
	}
	return machineState{busy: float64(ld1) / float64(scale), at: time.Now(), ok: true}, true
}

// readSelfUsec reports this process's CPU time in microseconds, including the
// children it has reaped.
//
// The children are the point. The Go worker coordinates while the sidecars it
// spawns do every expensive thing, so counting only RUSAGE_SELF would report a
// worker saturating a laptop as using almost nothing — and the governor would
// then cheerfully ask for more.
//
// The path argument is the cgroup file the Linux implementation reads. It has
// no meaning here.
func readSelfUsec(_ string) (uint64, bool) {
	var self, kids syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &self); err != nil {
		return 0, false
	}
	total := usec(self)
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &kids); err == nil {
		total += usec(kids)
	}
	return total, true
}

func usec(r syscall.Rusage) uint64 {
	return uint64(r.Utime.Sec)*1e6 + uint64(r.Utime.Usec) +
		uint64(r.Stime.Sec)*1e6 + uint64(r.Stime.Usec)
}
