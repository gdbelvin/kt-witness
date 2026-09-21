//go:build !unix

package netmeter

import "syscall"

// Marking is a socket option this platform does not offer. The dialer stays
// usable and the traffic goes out unclassified, which is what it did before.
func mark(_, _ string, _ syscall.RawConn) error { return nil }
