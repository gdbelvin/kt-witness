//go:build !linux && !darwin

package main

import "fmt"

// freeSpace has no portable implementation, and guessing is not an option: the
// free-space floor is a safety limit, so a platform where it cannot be measured
// must refuse to fetch rather than proceed unbounded.
func freeSpace(dir string) (int64, error) {
	return 0, fmt.Errorf("corpus: free-space checking is not implemented on this platform; refusing to fetch")
}
