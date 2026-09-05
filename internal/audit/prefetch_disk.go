//go:build unix

package audit

import "syscall"

// Keeping the cache from being the reason the disk fills.
//
// MaxBytes bounds what the cache itself holds, which is not the same question.
// The volume also carries the witness database, Proton's retained 13.6 GB tree,
// and whatever else shares it; a cache that stays under its own cap can still
// be the last straw. Filling the disk would stop the witness recording what it
// has attested, so the floor matters more than the cache does.
//
// Checked before each download rather than periodically: the gap between a
// check and a 250 MB write is exactly where a surprise fits.

// defaultMinFreeBytes is the headroom the prefetcher refuses to eat into.
//
// Comfortably more than one proof, so the check cannot be passed and then
// falsified by the download it just authorised.
const defaultMinFreeBytes = 5 << 30

// freeBytes reports space available on the volume holding dir.
func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
