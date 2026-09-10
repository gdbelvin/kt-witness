package hostmem

import (
	"os"
	"syscall"
)

// Scratch reports the bytes free in the filesystem holding dir.
//
// It exists because a number in a compose file went stale in exactly the way
// every other performance number in this project has. The witness's scratch
// space is a 1 GB tmpfs, sized when one verification ran at a time, and the
// sidecar writes each ~284 MB proof there before replaying it. When the pool
// widened to eight the space did not, and the witness reported
//
//	unverifiable (fetch): No space left on device (os error 28)
//
// on a host with 568 GB free — then re-queued every epoch it had just failed to
// fetch, so the coverage figure fell while nothing looked broken. The disk that
// was full was not the disk anyone was looking at.
//
// A process cannot resize its own tmpfs, so this does not fix anything by
// itself. What it does is let the witness say the true thing at startup, where
// somebody is reading, instead of a fetch error per epoch forever.
func Scratch(dir string) (uint64, bool) {
	if dir == "" {
		dir = os.TempDir()
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	// Bavail, not Bfree: the space an unprivileged process may actually have.
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
