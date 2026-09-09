// Package workrpc serves the worker channel over gRPC.
//
// # Why this listener is not the public one
//
// The witness publishes on a Cloudflare tunnel, and this does not go anywhere
// near it. The work channel dispatches verification to machines on the
// operator's own network; nothing outside needs to reach it, and a channel that
// accepts results is a channel that can inflate the coverage figure this
// witness publishes.
//
// So the bind address is CHECKED rather than documented. A witness configured
// to serve work on a public address refuses to start, because the failure mode
// of getting it wrong is silent — an exposed port looks exactly like a working
// one until somebody finds it.
package workrpc

import (
	"fmt"
	"net"
)

// CheckListenAddr refuses an address that is not plainly local.
//
// Loopback, RFC1918, link-local and the CGNAT range Tailscale uses are allowed.
// A bare port, "0.0.0.0" and any globally routable address are refused, because
// each of those quietly serves the world.
func CheckListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("workrpc: %q is not host:port: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("workrpc: %q has no port", addr)
	}
	if host == "" {
		return fmt.Errorf("workrpc: %q binds every interface; name a LAN address, "+
			"because the work channel must not be reachable from outside this network", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname could resolve anywhere, and to different places later.
		return fmt.Errorf("workrpc: %q is a hostname; give an IP address so what "+
			"this binds cannot change under it", addr)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("workrpc: %q binds every interface; name a LAN address", addr)
	}
	if !isLocal(ip) {
		return fmt.Errorf("workrpc: %s is a public address; the work channel is "+
			"for machines on this network only", ip)
	}
	return nil
}

// cgnat is 100.64.0.0/10 — shared address space, and where Tailscale puts
// tailnet addresses. Treated as local because a tailnet is the operator's own
// network by any useful definition, and refusing it would push people onto
// 0.0.0.0 instead, which is worse.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}
