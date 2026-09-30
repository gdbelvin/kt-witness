package server

// Per-endpoint request metrics.
//
// The question these answer is "is anyone relying on this witness?", which the
// performance metrics cannot: a witness can cosign every log on time and still
// be of no use to anybody, because nobody fetches what it signs. The answer is
// in who calls the read endpoints and the push endpoint, how often, and how
// long they wait.
//
// Two things keep the answer honest:
//
//   - Traffic is split by how it arrived. Telegraf scrapes /metrics over the
//     LAN every 15s and Docker probes /healthz; both would otherwise dominate
//     every graph and make an unused witness look busy. Requests that came
//     through the Cloudflare Tunnel carry Cf-Ray, and only those are outside
//     parties: via="tunnel". Everything else is via="direct".
//
//   - Routes are a fixed set. The raw path is attacker-chosen — scanners send
//     thousands of distinct ones — and a label per path would grow the series
//     count without bound. Anything not listed is "other".

import (
	"crypto/sha256"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

const (
	MHTTPRequests      = "kt_witness_http_requests_total"
	MHTTPDurationBkt   = "kt_witness_http_request_duration_seconds_bucket"
	MHTTPDurationSum   = "kt_witness_http_request_duration_seconds_sum"
	MHTTPDurationCount = "kt_witness_http_request_duration_seconds_count"
	MHTTPClients       = "kt_witness_http_distinct_clients"
	MCheckpointFetches = "kt_witness_checkpoint_fetches_total"
)

// latencyBuckets are the histogram upper bounds, in seconds. The registry
// has no histogram type, so the buckets are cumulative counters labelled le,
// which is exactly what the Prometheus histogram exposition is underneath and
// what Flux's histogramQuantile reads.
var latencyBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// clientWindow is how far back "distinct clients" looks.
const clientWindow = 24 * time.Hour

func describeHTTP() {
	d := metrics.Describe
	d(MHTTPRequests, metrics.Counter, "HTTP requests served, by route, method, status code, and via (tunnel = arrived through the Cloudflare Tunnel, i.e. an outside party; direct = LAN, including the Telegraf scrape and the Docker healthcheck).")
	d(MHTTPDurationBkt, metrics.Counter, "Cumulative count of HTTP requests that completed within le seconds, by route and via. Histogram buckets, for latency quantiles.")
	d(MHTTPDurationSum, metrics.Counter, "Total seconds spent serving HTTP requests, by route and via.")
	d(MHTTPDurationCount, metrics.Counter, "HTTP requests timed, by route and via.")
	d(MHTTPClients, metrics.Gauge, "Distinct clients seen through the tunnel in the trailing 24 hours, by route. Clients are told apart by Cf-Connecting-Ip, held only as a hash in memory.")
	d(MCheckpointFetches, metrics.Counter, "Cosigned checkpoints served, by origin and via: which logs' cosignatures somebody actually reads.")
}

// route maps a request path onto the fixed route set.
func route(path string) string {
	switch path {
	case "/", "/status.json", "/add-checkpoint", "/about", "/metrics", "/healthz",
		"/.well-known/tlog-witness-key", "/funding.json", "/.well-known/funding-manifest-urls",
		"/forks", "/audits", "/history", "/applications", "/log", "/gossip", "/graph", "/events":
		return path
	}
	if strings.HasSuffix(path, "/checkpoint") && strings.Count(path, "/") == 2 {
		return "/{origin}/checkpoint"
	}
	return "other"
}

// method bounds the method label the same way route bounds the path: Go's
// server accepts any token as a method, so a scanner could otherwise mint a
// series per word it sends.
func method(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions:
		return m
	}
	return "other"
}

// via reports whether a request came through the Cloudflare Tunnel.
func via(r *http.Request) string {
	if r.Header.Get("Cf-Ray") != "" {
		return "tunnel"
	}
	return "direct"
}

// statusRecorder captures the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps streaming handlers (/events) working through the wrapper.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// clientTracker counts distinct outside clients per route over a trailing
// window. Only a truncated hash of the address is kept, and only in memory:
// the count is the point, not who.
type clientTracker struct {
	mu   sync.Mutex
	seen map[string]map[[8]byte]time.Time // route → client → last seen
}

func (c *clientTracker) observe(rt, addr string, now time.Time) {
	sum := sha256.Sum256([]byte(addr))
	var k [8]byte
	copy(k[:], sum[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]map[[8]byte]time.Time{}
	}
	m := c.seen[rt]
	if m == nil {
		m = map[[8]byte]time.Time{}
		c.seen[rt] = m
	}
	m[k] = now
}

// publish prunes expired clients and sets the gauge. Called at scrape time,
// so the figure is current whenever it is read and costs nothing otherwise.
func (c *clientTracker) publish(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	all := map[[8]byte]bool{}
	for rt, m := range c.seen {
		for k, t := range m {
			if now.Sub(t) > clientWindow {
				delete(m, k)
				continue
			}
			all[k] = true
		}
		metrics.Set(MHTTPClients, map[string]string{"route": rt}, float64(len(m)))
	}
	metrics.Set(MHTTPClients, map[string]string{"route": "all"}, float64(len(all)))
}

var clients clientTracker

// clientAddr is the outside party's address: Cloudflare's view of it for
// tunnelled requests, since the connection itself comes from cloudflared.
func clientAddr(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// instrument wraps h with the per-route request metrics.
func instrument(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		elapsed := time.Since(start).Seconds()

		code := rec.code
		if code == 0 {
			code = http.StatusOK
		}
		rt, v := route(r.URL.Path), via(r)
		metrics.Inc(MHTTPRequests, map[string]string{
			"route": rt, "method": method(r.Method), "code": strconv.Itoa(code), "via": v,
		})
		lbl := map[string]string{"route": rt, "via": v}
		metrics.Add(MHTTPDurationSum, lbl, elapsed)
		metrics.Inc(MHTTPDurationCount, lbl)
		for _, le := range latencyBuckets {
			if elapsed <= le {
				metrics.Inc(MHTTPDurationBkt, map[string]string{
					"route": rt, "via": v, "le": strconv.FormatFloat(le, 'g', -1, 64),
				})
			}
		}
		metrics.Inc(MHTTPDurationBkt, map[string]string{"route": rt, "via": v, "le": "+Inf"})

		if v == "tunnel" {
			clients.observe(rt, clientAddr(r), start)
		}
	})
}
