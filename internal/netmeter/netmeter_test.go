package netmeter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Bytes must be counted as actually read, not as promised by Content-Length. A
// 284 MB proof that fails halfway through cost us what arrived, and the whole
// point of this metric is to know what the link really carried.
func TestCountsBytesActuallyRead(t *testing.T) {
	body := strings.Repeat("x", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	c := &http.Client{Transport: Wrap(nil, "test.example/log")}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Read only part of it, then abandon the rest.
	buf := make([]byte, 1000)
	n, _ := io.ReadFull(resp.Body, buf)
	resp.Body.Close()

	got := Snapshot()["test.example/log"]
	if got.BytesIn != int64(n) {
		t.Errorf("counted %d bytes, read %d — the metric must reflect what arrived", got.BytesIn, n)
	}
	if got.Requests != 1 {
		t.Errorf("counted %d requests, want 1", got.Requests)
	}
}

// Unwrap must expose the wrapped transport, so that a security property of the
// underlying transport — Apple's private-CA pinning, in practice — stays
// testable. Metrics are never worth blinding a security test.
func TestUnwrapExposesTheWrappedTransport(t *testing.T) {
	base := &http.Transport{}
	if Unwrap(Wrap(base, "o")) != base {
		t.Fatal("Unwrap did not return the wrapped transport")
	}
	// An unwrapped transport passes through unchanged.
	if Unwrap(base) != base {
		t.Fatal("Unwrap altered a transport it did not wrap")
	}
}

// Not every download goes through a transport we wrap — the audit prefetcher
// streams proof blobs on a plain client of its own — so those bytes are
// reported explicitly instead.
func TestAddRecordsOutOfBandBytes(t *testing.T) {
	Add("akd.example/log", 1234)
	Add("akd.example/log", 766)
	if got := Snapshot()["akd.example/log"].BytesIn; got != 2000 {
		t.Errorf("out-of-band bytes = %d, want 2000", got)
	}
}
