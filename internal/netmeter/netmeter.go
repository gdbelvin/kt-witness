// Package netmeter counts bytes moved per log.
//
// Bandwidth is the resource this witness actually consumes at scale — the
// measured model in docs/cost.md puts it at roughly 40 GB/day, almost all of it
// construction-audit proofs — and it is the one an operator running this at home
// has a hard limit on. Estimating it from documentation was how the model was
// built; measuring it is how the model gets checked.
//
// Counting happens in the transport rather than at call sites because the call
// sites are spread across five adapters, the audit verifier and a tile fetcher,
// and any of them could grow a new request that nobody remembered to
// instrument. A RoundTripper sees all of it by construction.
package netmeter

import (
	"io"
	"net/http"
	"sync"
)

// Stats is what one origin has moved.
type Stats struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
}

var (
	mu    sync.Mutex
	byLog = map[string]*Stats{}
)

// Wrap returns a RoundTripper that attributes everything it carries to origin.
//
// A nil base means http.DefaultTransport, so callers that never set one keep
// working.
func Wrap(base http.RoundTripper, origin string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base, origin: origin}
}

type transport struct {
	base   http.RoundTripper
	origin string
}

// Unwrap returns the wrapped RoundTripper.
//
// This exists so that safety properties of the underlying transport stay
// checkable. Apple's endpoint is served by Apple's own private CA and the
// client is pinned to it; a test asserts that pinning, and wrapping the
// transport for metrics must not make that assertion impossible to write.
// Metrics are never worth blinding a security test.
func (t *transport) Unwrap() http.RoundTripper { return t.base }

// Unwrap returns the transport rt wraps, or rt itself if it is not one of ours.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*transport); ok {
		return t.base
	}
	return rt
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Request bytes are counted from ContentLength rather than by wrapping the
	// body: a witness sends almost nothing — a few hundred bytes of protobuf at
	// most — and wrapping request bodies risks disturbing retry semantics for a
	// number that will never matter.
	var out int64
	if r.ContentLength > 0 {
		out = r.ContentLength
	}

	resp, err := t.base.RoundTrip(r)
	if err != nil {
		record(t.origin, 0, out, 1)
		return resp, err
	}

	// Response bytes are counted as they are actually read, not from
	// Content-Length. A 284 MB proof that fails halfway through cost us the
	// bytes we received, not the bytes we were promised, and the whole point of
	// this is to know what the link really carried.
	record(t.origin, 0, out, 1)
	resp.Body = &countingBody{ReadCloser: resp.Body, origin: t.origin}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	origin string
	n      int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.n += int64(n)
		// Flush per read rather than on Close: a body that is never closed, or
		// a process that exits mid-download, would otherwise lose the count
		// entirely — and a long download is exactly when someone is watching.
		record(c.origin, int64(n), 0, 0)
	}
	return n, err
}

func record(origin string, in, out, reqs int64) {
	mu.Lock()
	defer mu.Unlock()
	s := byLog[origin]
	if s == nil {
		s = &Stats{}
		byLog[origin] = s
	}
	s.BytesIn += in
	s.BytesOut += out
	s.Requests += reqs
}

// Snapshot returns a copy of the counters, keyed by origin.
func Snapshot() map[string]Stats {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]Stats, len(byLog))
	for k, v := range byLog {
		out[k] = *v
	}
	return out
}

// Add records bytes moved outside any HTTP transport we control — notably the
// audit verifier, which downloads its own proofs and reports the size back.
// Without this the largest single consumer of bandwidth in the whole system
// would be invisible in its own bandwidth metric.
func Add(origin string, bytesIn int64) { record(origin, bytesIn, 0, 0) }
