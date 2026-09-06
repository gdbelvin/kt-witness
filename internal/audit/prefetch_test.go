package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// The cap has to be enforced, not merely consulted.
//
// Prune existed and was called from nowhere, so the limit was advisory: Fetch
// declined to add past it, but nothing removed what was already over. Proofs for
// epochs the sweep had moved past were never released and never evicted, and the
// cache ran 5.9 GB above its limit on a volume it shares with the witness
// database and two 13 GB Proton trees.
func TestPruneEnforcesTheCap(t *testing.T) {
	dir := t.TempDir()
	p := &Prefetcher{Dir: dir, MaxBytes: 3000}

	// Ten files of 1000 bytes, written oldest-first so eviction order is
	// well-defined.
	for i := 0; i < 10; i++ {
		name := cacheKey("meta.test/v1", int64(i))
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 1000), 0o644); err != nil {
			t.Fatal(err)
		}
		// Distinct mtimes: Prune drops oldest first and same-second timestamps
		// would make the assertion depend on map order.
		mt := time.Now().Add(time.Duration(i-20) * time.Minute)
		if err := os.Chtimes(filepath.Join(dir, name), mt, mt); err != nil {
			t.Fatal(err)
		}
	}

	// Adopt what is on disk, as a restart would.
	if _, held := p.Stats(); held != 10000 {
		t.Fatalf("adopted %d bytes, want 10000 — a restart must see the files "+
			"already there or it re-downloads them", held)
	}

	p.Prune()

	files, held := p.Stats()
	if held > p.maxBytes() {
		t.Errorf("held %d bytes after Prune, above the %d cap", held, p.maxBytes())
	}
	if files > 3 {
		t.Errorf("kept %d files for a cap of 3x1000 bytes", files)
	}
	// The newest survive: the sweep is walking downward and will want those next.
	if p.Path("meta.test/v1", 9) == "" {
		t.Error("evicted the newest proof; oldest-first is the whole point")
	}
	if p.Path("meta.test/v1", 0) != "" {
		t.Error("kept the oldest proof while over cap")
	}
}
