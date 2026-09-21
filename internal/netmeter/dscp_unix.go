//go:build unix

package netmeter

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// mark sets the DSCP class on a socket before it connects.
//
// Both options are attempted on a dual-stack socket rather than inspecting the
// address, because Go resolves and may fall back between families: a name that
// came back AAAA-first gets an IPv6 socket, and the same code has to mark it.
// Setting the wrong family's option returns an error that is correctly ignored.
//
// Errors are swallowed. A kernel or container that refuses the option leaves
// the traffic unmarked, which is exactly what it was before — failing the dial
// over a QoS hint would trade a working witness for a classification nobody has
// promised to honour anyway.
func mark(network, _ string, c syscall.RawConn) error {
	class := int(dscp.Load())
	if class == 0 {
		return nil
	}
	tos := class << 2 // the codepoint occupies the top 6 bits of the TOS byte
	return c.Control(func(fd uintptr) {
		f := int(fd)
		if !strings.HasSuffix(network, "6") {
			_ = unix.SetsockoptInt(f, unix.IPPROTO_IP, unix.IP_TOS, tos)
		}
		if !strings.HasSuffix(network, "4") {
			_ = unix.SetsockoptInt(f, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
		}
	})
}
