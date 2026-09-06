package server

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	var h tlog.Hash
	h[0] = 0xab
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: "example.org/log", Size: 4321, Hash: h,
		Cosigned: []byte("example.org/log\n4321\n"), WitnessedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{
		Store:   db,
		VKey:    "witness.example.com+deadbeef+AAAA",
		Version: "test",
		Tiers:   map[string]string{"example.org/log": "A+ (root-chain continuity)"},
	}
}

// The plain-text index is the machine contract. Monitors and the C2SP tooling
// read it, so adding a browser UI must not change what a non-browser sees.
func TestIndexStaysPlainTextForTooling(t *testing.T) {
	s := testServer(t)
	for _, accept := range []string{"", "*/*", "application/json", "text/plain"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		s.index(w, req)

		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Accept=%q gave Content-Type %q, want text/plain", accept, ct)
		}
		if body := w.Body.String(); !strings.Contains(body, "example.org/log") {
			t.Errorf("Accept=%q: plain-text index lost its content", accept)
		}
	}
}

// A browser gets the status page from the same URL.
func TestIndexServesHTMLToBrowsers(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	w := httptest.NewRecorder()
	s.index(w, req)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type %q, want text/html", ct)
	}
	// html/template escapes "+" as &#43;, which is correct — compare against the
	// unescaped text so the assertions test content, not escaping.
	body := html.UnescapeString(w.Body.String())
	for _, want := range []string{
		"witness.example.com",               // identity
		"witness.example.com+deadbeef+AAAA", // the key others pin
		"example.org/log",                   // the witnessed log
		"4,321",                             // size, humanised
		"A+ (root-chain continuity)",        // the tier — the thing not to misread
		"What the tiers mean",               // and its explanation
		"/graph",                            // the map of the whole fleet, linked where it is looked for
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status page is missing %q", want)
		}
	}
}

// The page's data must be scrapable, or publishing it as HTML just moves the
// problem of evidence being hard to consume.
func TestStatusJSON(t *testing.T) {
	s := testServer(t)
	w := httptest.NewRecorder()
	s.statusJSON(w, httptest.NewRequest(http.MethodGet, "/status.json", nil))

	var v struct {
		TotalLogs    int   `json:"TotalLogs"`
		TotalEntries int64 `json:"TotalEntries"`
		Logs         []struct {
			Origin string `json:"Origin"`
			Tier   string `json:"Tier"`
		} `json:"Logs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("status.json is not valid JSON: %v", err)
	}
	if v.TotalLogs != 1 || v.TotalEntries != 4321 {
		t.Errorf("aggregates wrong: %+v", v)
	}
	if len(v.Logs) != 1 || v.Logs[0].Tier == "" {
		t.Errorf("per-log tier missing: %+v", v.Logs)
	}
}

// html/template escapes by default; confirm an origin cannot inject markup.
func TestStatusPageEscapesOrigins(t *testing.T) {
	s := testServer(t)
	var h tlog.Hash
	if err := s.Store.CompareAndSet(nil, &store.Record{
		Origin: `evil"><script>alert(1)</script>`, Size: 1, Hash: h,
		Cosigned: []byte("x"), WitnessedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.index(w, req)
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("an origin injected raw markup into the status page")
	}
}

// The metrics endpoint must expose the series alerts are written against, and
// must stay parseable when an origin contains exposition-reserved characters.
func TestMetricsEndpoint(t *testing.T) {
	s := testServer(t)
	Init("test", "testcommit", "testdate")
	w := httptest.NewRecorder()
	s.metricsHandler(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type %q, want the Prometheus text format", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE kt_witness_log_size gauge",
		"# TYPE kt_witness_withheld_total counter",
		`kt_witness_build_info{built="testdate",commit="testcommit",version="test"} 1`,
		`origin="example.org/log"`,
		`tier="A+ (root-chain continuity)"`,
		"kt_witness_logs_total 1",
		"kt_witness_entries_attested 4321",
		"kt_witness_forks_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// Every line is either a comment or "name{labels} value".
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, " ") {
			t.Errorf("malformed exposition line: %q", line)
		}
	}
}

// A log removed from the configuration keeps its stored history — that is our
// own audit trail — but must not be reported as live. Otherwise it ages
// forever and trips the staleness alarm that is supposed to mean the witness
// itself is stuck.
func TestUnconfiguredOriginsAreNotReportedAsLive(t *testing.T) {
	s := testServer(t)
	var h tlog.Hash
	if err := s.Store.CompareAndSet(nil, &store.Record{
		Origin: "retired.example/log", Size: 7, Hash: h,
		Cosigned: []byte("x"), WitnessedAt: time.Now().Add(-72 * time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	v, err := s.buildStatus()
	if err != nil {
		t.Fatal(err)
	}
	for _, lg := range v.Logs {
		if lg.Origin == "retired.example/log" {
			t.Fatal("an unconfigured origin was reported as a live log")
		}
	}
	if len(v.Retired) != 1 || v.Retired[0] != "retired.example/log" {
		t.Errorf("retired origins should still be listed, got %v", v.Retired)
	}
	if v.TotalLogs != 1 {
		t.Errorf("TotalLogs counted a retired origin: %d", v.TotalLogs)
	}
}

// The tier a source reports is what its own checks prove; whether a log is also
// construction audited lives in the audit record. Computing the effective tier
// from the source alone meant B+ could never be reached by the logs that are
// actually audited — the AKD adapter reports A+ while its tier-B evidence comes
// from the sidecar.
func TestEffectiveTierComesFromTheAuditRecord(t *testing.T) {
	s := testServer(t)
	const origin = "example.org/log"

	if err := s.Store.RecordHistory(&store.History{
		Origin: origin, From: 10, To: 12, Epochs: 3, VerifiedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	// Two of three epochs audited: construction audited, but not across the
	// whole published range.
	for _, e := range []int64{10, 11} {
		if err := s.Store.RecordAudit(&store.Audit{
			Origin: origin, Epoch: e, Sampled: true, Verified: true, DecidedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Coverage is cached, and the tier is derived from it. This test asserts the
	// tier the instant an audit lands, so it asks for the exact figure rather
	// than a cached one — which is the case the knob exists for.
	s.CoverageTTL = -1

	v, err := s.buildStatus()
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Logs[0].Tier; !strings.HasPrefix(got, "B (") {
		t.Errorf("partial coverage should read as tier B, got %q", got)
	}

	// The third epoch closes the range.
	if err := s.Store.RecordAudit(&store.Audit{
		Origin: origin, Epoch: 12, Sampled: true, Verified: true, DecidedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	v, err = s.buildStatus()
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Logs[0].Tier; !strings.HasPrefix(got, "B+") {
		t.Errorf("full coverage should earn tier B+, got %q", got)
	}
	if v.Logs[0].HistoryAudited != 3 || v.Logs[0].HistoryTotal != 3 {
		t.Errorf("coverage misreported: %d/%d", v.Logs[0].HistoryAudited, v.Logs[0].HistoryTotal)
	}
}
