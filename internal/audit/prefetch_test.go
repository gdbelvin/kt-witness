package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func testPrefetcher(t *testing.T, maxBytes int64) *Prefetcher {
	t.Helper()
	return &Prefetcher{Dir: t.TempDir(), MaxBytes: maxBytes, Workers: 2}
}

// TestPrefetchRoundTrip covers the lifecycle the sweep depends on: a proof is
// fetched, found, and released once verified.
func TestPrefetchRoundTrip(t *testing.T) {
	body := make([]byte, 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	p := testPrefetcher(t, 1<<20)
	const origin = "example.com/log"

	if got := p.Path(origin, 7); got != "" {
		t.Fatalf("reported a proof it does not hold: %q", got)
	}
	if err := p.Fetch(context.Background(), origin, srv.URL, 7, "aa", "bb"); err != nil {
		t.Fatal(err)
	}
	path := p.Path(origin, 7)
	if path == "" {
		t.Fatal("fetched proof is not findable")
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() != int64(len(body)) {
		t.Fatalf("cached file wrong: %v size=%v", err, fi)
	}

	p.Release(origin, 7)
	if p.Path(origin, 7) != "" {
		t.Fatal("released proof is still reported as held")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("released proof was left on disk; the cache would fill")
	}
}

// TestPrefetchStopsAtTheCap is the property that keeps this from filling the
// disk. Downloading is faster than verifying, so an unbounded queue grows
// without limit.
func TestPrefetchStopsAtTheCap(t *testing.T) {
	body := make([]byte, 8192)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	// Room for two.
	p := testPrefetcher(t, 3*4096)
	const origin = "example.com/log"
	for e := int64(1); e <= 10; e++ {
		if err := p.Fetch(context.Background(), origin, srv.URL, e, "aa", "bb"); err != nil {
			t.Fatalf("epoch %d: %v", e, err)
		}
	}
	files, bytes := p.Stats()
	if bytes > 3*8192 {
		t.Fatalf("cache holds %d bytes, past its cap: an unbounded queue fills the disk", bytes)
	}
	if files == 0 {
		t.Fatal("cache holds nothing; the cap is not a reason to fetch none")
	}
	// A full cache must not be an error — it is the system working.
	if err := p.Fetch(context.Background(), origin, srv.URL, 99, "aa", "bb"); err != nil {
		t.Fatalf("a full cache reported an error: %v", err)
	}
}

// TestPrefetchLeavesNoPartialFiles: a truncated proof looks exactly like a
// complete one to the verifier, which would report a decode failure against a
// log that published perfectly good data.
func TestPrefetchLeavesNoPartialFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := testPrefetcher(t, 1<<20)
	if err := p.Fetch(context.Background(), "example.com/log", srv.URL, 1, "aa", "bb"); err == nil {
		t.Fatal("a 500 should be reported")
	}
	ents, _ := os.ReadDir(p.Dir)
	for _, e := range ents {
		t.Fatalf("left behind %q; a partial file would be verified as if whole",
			filepath.Base(e.Name()))
	}
	if files, bytes := p.Stats(); files != 0 || bytes != 0 {
		t.Fatalf("failed fetch counted as cached: %d files %d bytes", files, bytes)
	}
}
