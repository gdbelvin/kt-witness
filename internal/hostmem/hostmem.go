// Package hostmem reports how much memory a machine has to spare.
//
// It exists because the pacing in this project measured CPU and nothing else,
// and a worker can sit comfortably inside its core budget while pushing its
// host into swap. That is not hypothetical: two background tasks on the
// operator's laptop were killed for low memory while the worker on it was
// using two of eight permitted cores and reporting itself healthy.
//
// The witness has had memory sizing from the start — its Rust subprocess pool
// was derived from the container's cgroup limit precisely because one
// verification there peaked in gigabytes. The machines lent to it had none of
// that protection, which is the wrong way round: the server is dedicated to
// this and the laptop belongs to somebody who is using it.
package hostmem

// Available reports the bytes a new allocation could reasonably use, and
// whether the figure could be obtained at all.
//
// "Reasonably" is doing work in that sentence. On both platforms this counts
// memory that is free plus memory the kernel would reclaim rather than swap —
// page cache and inactive pages — because refusing to use a machine whose RAM
// is entirely in cache would refuse to use most machines.
//
// A false second return means unknown, and callers must treat that as "do not
// assume there is room" rather than as zero or as infinity. Guessing high here
// is how a laptop starts swapping; guessing low costs throughput on a machine
// that had capacity to give.
func Available() (uint64, bool) { return available() }
