package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

func scrape(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if err := metrics.Default.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// value returns the sample for an exact name+labels line, or "".
func value(out, series string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, series+" ") {
			return strings.TrimPrefix(line, series+" ")
		}
	}
	return ""
}

func TestRouteIsBounded(t *testing.T) {
	for path, want := range map[string]string{
		"/":                     "/",
		"/add-checkpoint":       "/add-checkpoint",
		"/about":                "/about",
		"/abc123/checkpoint":    "/{origin}/checkpoint",
		"/a/b/checkpoint":       "other",
		"/wp-login.php":         "other",
		"/.env":                 "other",
		"/metrics":              "/metrics",
		"/.well-known/whatever": "other",
	} {
		if got := route(path); got != want {
			t.Errorf("route(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestMethodIsBounded(t *testing.T) {
	for m, want := range map[string]string{
		"GET": "GET", "POST": "POST", "HEAD": "HEAD", "OPTIONS": "OPTIONS",
		"FOO": "other", "PROPFIND": "other", "get": "other",
	} {
		if got := method(m); got != want {
			t.Errorf("method(%q) = %q, want %q", m, got, want)
		}
	}
}

// Tunnel traffic and LAN traffic must be told apart, or the Telegraf scrape
// alone makes an unused witness look relied on.
func TestInstrumentSplitsTunnelFromDirect(t *testing.T) {
	h := instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))

	req := httptest.NewRequest("GET", "/about", nil)
	req.Header.Set("Cf-Ray", "8c1-EWR")
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
	h.ServeHTTP(httptest.NewRecorder(), req)
	// Same client again, and a second one: two distinct.
	h.ServeHTTP(httptest.NewRecorder(), req)
	req2 := httptest.NewRequest("GET", "/about", nil)
	req2.Header.Set("Cf-Ray", "8c2-EWR")
	req2.Header.Set("Cf-Connecting-Ip", "198.51.100.9")
	h.ServeHTTP(httptest.NewRecorder(), req2)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/wp-login.php", nil))

	clients.publish(time.Now())
	out := scrape(t)

	if got := value(out, `kt_witness_http_requests_total{code="200",method="GET",route="/about",via="tunnel"}`); got != "3" {
		t.Errorf("tunnel /about requests = %q, want 3", got)
	}
	if got := value(out, `kt_witness_http_requests_total{code="404",method="GET",route="other",via="direct"}`); got != "1" {
		t.Errorf("direct other 404 = %q, want 1", got)
	}
	if got := value(out, `kt_witness_http_distinct_clients{route="/about"}`); got != "2" {
		t.Errorf("distinct /about clients = %q, want 2", got)
	}
	// Buckets are cumulative: a fast request lands in every bucket, and +Inf
	// always equals the count.
	inf := value(out, `kt_witness_http_request_duration_seconds_bucket{le="+Inf",route="/about",via="tunnel"}`)
	top := value(out, `kt_witness_http_request_duration_seconds_bucket{le="10",route="/about",via="tunnel"}`)
	cnt := value(out, `kt_witness_http_request_duration_seconds_count{route="/about",via="tunnel"}`)
	if inf != "3" || top != "3" || cnt != "3" {
		t.Errorf("buckets +Inf=%q le=10=%q count=%q, want all 3", inf, top, cnt)
	}
}

func TestDistinctClientsExpire(t *testing.T) {
	var c clientTracker
	now := time.Now()
	c.observe("/x-expire", "192.0.2.1", now.Add(-25*time.Hour))
	c.observe("/x-expire", "192.0.2.2", now)
	c.publish(now)
	if got := value(scrape(t), `kt_witness_http_distinct_clients{route="/x-expire"}`); got != "1" {
		t.Errorf("distinct after expiry = %q, want 1", got)
	}
}

func TestCheckpointFetchCountedByOrigin(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	origin := "example.org/log"
	req := httptest.NewRequest("GET", "/"+originHashes(origin)[0]+"/checkpoint", nil)
	req.Header.Set("Cf-Ray", "1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("checkpoint GET = %d", rr.Code)
	}
	series := `kt_witness_checkpoint_fetches_total{origin="` + origin + `",via="tunnel"}`
	if value(scrape(t), series) == "" {
		t.Errorf("no %s", series)
	}
}
