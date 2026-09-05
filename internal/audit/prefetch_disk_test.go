//go:build unix

package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPrefetchBacksOffOnLowDisk is the property that keeps the cache from being
// the reason the witness stops recording what it attested.
//
// MaxBytes bounds what this cache holds, which is a different question from
// what the volume can spare — the same disk carries the store and Proton's
// retained tree. A floor set above all free space must stop fetching, and must
// do so without erroring, because verification keeps draining the cache and the
// condition clears itself.
func TestPrefetchBacksOffOnLowDisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	dir := t.TempDir()
	free, err := freeBytes(dir)
	if err != nil {
		t.Skipf("cannot read free space here: %v", err)
	}

	// A floor above everything available: fetching must stop.
	p := &Prefetcher{Dir: dir, MaxBytes: 1 << 30, MinFreeBytes: free + (1 << 30)}
	if err := p.Fetch(context.Background(), "example.com/log", srv.URL, 1, "aa", "bb"); err != nil {
		t.Fatalf("running low on disk is not an error, it is a reason to wait: %v", err)
	}
	if files, _ := p.Stats(); files != 0 {
		t.Fatalf("cached %d files with the disk below its floor", files)
	}

	// With a floor the volume clears, the same fetch proceeds.
	p2 := &Prefetcher{Dir: dir, MaxBytes: 1 << 30, MinFreeBytes: 1}
	if err := p2.Fetch(context.Background(), "example.com/log", srv.URL, 1, "aa", "bb"); err != nil {
		t.Fatal(err)
	}
	if files, _ := p2.Stats(); files != 1 {
		t.Fatalf("expected the fetch to proceed with room available, got %d files", files)
	}
}
