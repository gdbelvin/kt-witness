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
	"os"
	"strings"
)

// CheckListenAddr refuses an address that is not plainly local. It returns a
// note the caller must log when confinement rests on something this process
// cannot see.
//
// Loopback, RFC1918, link-local and the CGNAT range Tailscale uses are allowed.
// A hostname and any globally routable address are refused, because each of
// those quietly serves the world.
//
// # The container exception
//
// An unspecified address is refused on a host and allowed inside a container,
// and the difference is not a compromise — it is where the confinement actually
// lives.
//
// A container has its own network namespace. It cannot bind the host's LAN
// address at all: 192.168.0.10 does not exist in there, so a witness
// configured that way does not serve the LAN, it fails to start with "cannot
// assign requested address". What reaches the container is exactly what the
// port publish allows, and compose pins that to one LAN address:
//
//	ports: [ "192.168.0.10:18090:8090" ]
//
// So the check that matters moves from this process to that line. Refusing an
// unspecified bind here would not make the deployment safer; it would make it
// impossible, and the pressure would go somewhere worse — host networking, or
// this check deleted outright.
//
// The trade is real and worth stating plainly: inside a container this process
// can no longer prove its own confinement, so it says so at startup instead. If
// that publish rule ever loses its host_ip, nothing here will catch it.
func CheckListenAddr(addr string) (note string, err error) {
	return checkListenAddr(addr, inContainer())
}

// checkListenAddr is the decision, with the environment passed in so both
// answers can be tested on whichever kind of machine the tests run on.
func checkListenAddr(addr string, contained bool) (note string, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("workrpc: %q is not host:port: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("workrpc: %q has no port", addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		if !contained {
			return "", fmt.Errorf("workrpc: %q binds every interface; name a LAN address, "+
				"because the work channel must not be reachable from outside this network", addr)
		}
		return "binding every interface inside this container; what can reach it is " +
			"whatever the port publish allows, and that must name a LAN address " +
			"(host_ip) — nothing in this process can check it", nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname could resolve anywhere, and to different places later.
		return "", fmt.Errorf("workrpc: %q is a hostname; give an IP address so what "+
			"this binds cannot change under it", addr)
	}
	if !isLocal(ip) {
		return "", fmt.Errorf("workrpc: %s is a public address; the work channel is "+
			"for machines on this network only", ip)
	}
	return "", nil
}

// inContainer reports whether this process has its own network namespace, by
// the markers the runtimes leave behind. Conservative: anything it cannot
// recognise is treated as a host, where the strict rule applies.
func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil { // podman
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		return strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "kubepods")
	}
	return false
}

// cgnat is 100.64.0.0/10 — shared address space, and where Tailscale puts
// tailnet addresses. Treated as local because a tailnet is the operator's own
// network by any useful definition, and refusing it would push people onto
// 0.0.0.0 instead, which is worse.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}
