package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func readyCache(t *testing.T, origins ...string) *Prefetcher {
	t.Helper()
	return &Prefetcher{Dir: t.TempDir(), Origins: origins, MaxBytes: 1 << 30}
}

// put writes a proof into the cache the way a completed download would.
func put(t *testing.T, p *Prefetcher, origin string, epoch int64) {
	t.Helper()
	p.init()
	k := cacheKey(origin, epoch)
	if err := os.WriteFile(filepath.Join(p.Dir, k), []byte("proof"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.cached[k] = 5
	p.bytes += 5
	p.markReady(origin, epoch)
	p.mu.Unlock()
}

// TestReadyHandsOutOnlyWhatIsOnDisk is the property the whole three-stage
// arrangement rests on: the queue offers epochs whose bytes are already here,
// so a lease is answered by a local read rather than by a worker waiting
// through a WAN download that starts when it asks.
func TestReadyHandsOutOnlyWhatIsOnDisk(t *testing.T) {
	const o = "whatsapp.kt/v2"
	p := readyCache(t, o)

	if _, _, ok := p.Ready(o, 0, 8); ok {
		t.Error("an empty cache offered work")
	}

	for _, e := range []int64{10, 11, 12, 20} {
		put(t, p, o, e)
	}

	// A contiguous run, stopping at the gap. The gap is not a failure — the
	// generator simply has not fetched 13 yet — and handing out 10..20 would
	// name seven epochs that are not here.
	from, to, ok := p.Ready(o, 0, 8)
	if !ok || from != 10 || to != 12 {
		t.Fatalf("got %d..%d ok=%v, want 10..12", from, to, ok)
	}
	// Past the run, the far epoch is still offered on its own.
	if from, to, ok := p.Ready(o, 13, 8); !ok || from != 20 || to != 20 {
		t.Errorf("after the gap: %d..%d ok=%v, want 20..20", from, to, ok)
	}
	// `n` bounds it.
	if _, to, _ := p.Ready(o, 0, 2); to != 11 {
		t.Errorf("asked for 2 epochs, run ended at %d, want 11", to)
	}
	// Another origin's proofs are not this one's work.
	if _, _, ok := p.Ready("meta.messenger.kt/v1", 0, 8); ok {
		t.Error("an origin with nothing cached was offered work")
	}
}

// TestReleasedProofsStopBeingOffered. Release is the third stage: a verified
// epoch's bytes go back so the generator can fetch the next one. If Ready kept
// offering it, the queue would hand out work whose file had been deleted and
// the worker would get a 404 for something the witness believed it held.
func TestReleasedProofsStopBeingOffered(t *testing.T) {
	const o = "whatsapp.kt/v2"
	p := readyCache(t, o)
	put(t, p, o, 5)
	if _, _, ok := p.Ready(o, 0, 4); !ok {
		t.Fatal("a cached epoch was not offered")
	}
	p.Release(o, 5)
	if _, _, ok := p.Ready(o, 0, 4); ok {
		t.Error("a released epoch was still offered")
	}
	if p.Held(o) != 0 {
		t.Errorf("Held reports %d after releasing the only proof", p.Held(o))
	}
}

// TestAdoptedProofsAreOfferedAfterARestart. The cache survives a restart and
// the queue must see what is in it — otherwise every restart re-downloads
// everything, which is the bandwidth this exists to conserve.
func TestAdoptedProofsAreOfferedAfterARestart(t *testing.T) {
	const o = "whatsapp.kt/v2"
	dir := t.TempDir()
	first := &Prefetcher{Dir: dir, Origins: []string{o}, MaxBytes: 1 << 30}
	put(t, first, o, 42)

	// A fresh Prefetcher over the same directory, as on restart.
	second := &Prefetcher{Dir: dir, Origins: []string{o}, MaxBytes: 1 << 30}
	from, to, ok := second.Ready(o, 0, 4)
	if !ok || from != 42 || to != 42 {
		t.Errorf("after restart: %d..%d ok=%v, want 42..42 — the cache on disk "+
			"was not recognised and would be downloaded again", from, to, ok)
	}
}

// TestPruningForgetsWhatItDeletes. Prune drops the oldest files when the cache
// is over its cap; if `ready` kept them, the queue would offer epochs whose
// bytes are gone.
func TestPruningForgetsWhatItDeletes(t *testing.T) {
	const o = "whatsapp.kt/v2"
	p := &Prefetcher{Dir: t.TempDir(), Origins: []string{o}, MaxBytes: 6}
	for _, e := range []int64{1, 2, 3} {
		put(t, p, o, e)
	}
	p.Prune()
	from, _, ok := p.Ready(o, 0, 8)
	if ok {
		if _, err := os.Stat(p.Path(o, from)); err != nil {
			t.Errorf("epoch %d is still offered but its file is gone: %v", from, err)
		}
	}
	if p.Held(o) > 2 {
		t.Errorf("Held reports %d after pruning to a 6-byte cap of 5-byte files", p.Held(o))
	}
}
