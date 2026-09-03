//go:build linux || darwin

package main

import "syscall"

// freeSpace reports the bytes available to an unprivileged writer under dir.
//
// Bavail rather than Bfree deliberately: on a filesystem with reserved blocks
// the difference is several gigabytes, and overestimating headroom is the one
// error this whole limit exists to prevent. Note also that on a thin-provisioned
// pool even this is an upper bound — the filesystem reports the volume's size,
// not the pool's remaining extents — which is why the floor is set high rather
// than close to zero.
func freeSpace(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
