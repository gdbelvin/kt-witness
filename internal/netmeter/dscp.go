package netmeter

import (
	"net"
	"sync/atomic"
	"time"
)

// Marking this witness's traffic as bulk.
//
// # What a mark does, and what it does not
//
// It does not slow the downloads down. The bytes that saturate the link are
// sent by a CDN, and a DSCP class we set on our own outbound packets does not
// travel to it, does not survive the ISP's edge, and does not govern what comes
// back. Anyone expecting the mark alone to fix a video call will be
// disappointed, and it is worth saying so here rather than discovering it while
// the call is still bad. The thing that holds the rate down is limit.go, which
// reads slowly.
//
// What the mark does is make this traffic IDENTIFIABLE to equipment that is
// willing to act on it, which is the piece a router-side policy needs and the
// piece software on this machine cannot provide any other way:
//
//   - Egress is governed directly. Uploads, gRPC to workers, and the proof
//     server's responses are ours to classify and a marked flow is sorted into
//     the bulk queue by any shaper that reads DSCP.
//   - Ingress is governed indirectly, and only with help. A router doing ingress
//     shaping — CAKE with `diffserv4`, say — classifies by connection, and
//     conntrack carries the class it saw on the outbound side across to the
//     returning packets. So the mark on our request is how the router knows the
//     284 MB coming back is bulk, and without it the download is
//     indistinguishable from a video call in the one queue that could tell them
//     apart.
//
// So this is a prerequisite for a QoS policy rather than a QoS policy. It costs
// one setsockopt per connection and it is what a shaper keys on.
//
// # Which class
//
// CS1 by default. RFC 8622's Lower Effort (DSCP 1) is the more correct modern
// answer and is what this SHOULD mean, but CS1 is what deployed equipment
// actually recognises — CAKE's diffserv3 and diffserv4 both sort CS1 into the
// Bulk tin, and older gear that predates LE treats an unknown low class as
// best-effort, which silently loses the distinction. Configurable, because the
// right answer is a fact about somebody's router.

// DSCP classes worth naming. The value is the 6-bit codepoint, not the byte:
// see mark, which shifts.
const (
	DSCPDefault = 0 // best effort, i.e. do not mark
	DSCPLE      = 1 // RFC 8622 Lower Effort — correct, less widely honoured
	DSCPCS1     = 8 // the de-facto scavenger class
)

var dscp atomic.Int32

// SetDSCP sets the class applied to every connection Dialer makes from now on.
// Zero stops marking. Existing connections keep whatever they were opened with.
func SetDSCP(class int) { dscp.Store(int32(class)) }

// DSCP reports the configured class.
func DSCP() int { return int(dscp.Load()) }

// Dialer is the dialer every outbound connection in this process should use, so
// that one setting covers the prefetcher, the verifier and every source
// adapter. A transport that builds its own dialer is a flow nothing can
// classify, which is the same failure limit.go had when two of three download
// paths bypassed the meter.
func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   mark,
	}
}
