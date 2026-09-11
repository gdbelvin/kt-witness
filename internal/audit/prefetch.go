package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
)

// Downloading proofs ahead of verifying them.
//
// # Why
//
// Verification used to fetch its own proof, which serialised two resources that
// do not compete. A Meta proof is ~250 MB and takes roughly five seconds to
// arrive on this link; verifying it takes about twenty-five. So for a fifth of
// every cycle the CPU sat idle waiting for bytes, and for the other four fifths
// the link sat idle. Neither was saturated and the backlog drained at the speed
// of their sum rather than the slower of the two.
//
// Fetching ahead fixes that: the link runs flat out filling a disk cache while
// the pool verifies from it. Throughput becomes bounded by whichever resource is
// genuinely scarce — here the CPU — instead of by the two taking turns.
//
// # Why it is bounded, and by disk rather than count
//
// Download is faster than verification, so an unbounded queue grows without
// limit until the disk is full. The cache is capped in bytes because that is
// what actually runs out: proof sizes vary from 200 to 280 MB, so a count would
// be a proxy for the wrong thing.
//
// When the cache is full the prefetcher simply waits. That is the one place in
// this system where waiting is right: the constraint is disk, it is ours, and
// the alternative to waiting is filling it.

// Prefetcher keeps a bounded on-disk cache of proofs waiting to be verified.
type Prefetcher struct {
	// Dir holds cached proofs. One file per epoch, named by content-independent
	// key so a partially written file can never be mistaken for a complete one.
	Dir string

	// MaxBytes caps the cache. Zero means the default.
	MaxBytes int64

	// Workers is how many downloads run at once. The link, not the CPU, is what
	// this saturates.
	Workers int

	// MinFreeBytes is the free space the cache refuses to consume. Zero means
	// the default. Distinct from MaxBytes: that bounds what this cache holds,
	// this bounds what the volume can spare — and the volume carries the
	// witness database and Proton's retained tree as well.
	MinFreeBytes uint64

	Client *http.Client
	Log    *slog.Logger

	// Origins this cache holds proofs for. Needed because a cache key hashes
	// the origin — which is what lets the cache survive a log changing where it
	// publishes — so the origin cannot be read back out of a filename without
	// knowing the candidates.
	Origins []string

	mu     sync.Mutex
	cached map[string]int64 // key -> size
	// ready is which epochs are on disk, per origin. The queue hands out work
	// from THIS rather than from the store, so that a lease is always answered
	// by bytes that are already here and a worker never waits on a WAN fetch.
	ready  map[string]map[int64]bool
	bytes  int64
	inWork map[string]bool

	once sync.Once
	sem  chan struct{}
}

const (
	// defaultPrefetchBytes is about forty Meta proofs: enough that verification
	// never waits on the network, small beside the hundreds of gigabytes free on
	// this host, and self-limiting if the disk shrinks.
	defaultPrefetchBytes = 10 << 30

	// defaultPrefetchWorkers saturates a home link without becoming a
	// thundering herd against somebody else's CDN.
	defaultPrefetchWorkers = 4
)

func (p *Prefetcher) init() {
	p.once.Do(func() {
		p.cached = map[string]int64{}
		p.inWork = map[string]bool{}
		p.ready = map[string]map[int64]bool{}
		byHash := map[string]string{}
		for _, o := range p.Origins {
			sum := sha256.Sum256([]byte(o))
			byHash[hex.EncodeToString(sum[:6])] = o
		}
		n := p.Workers
		if n < 1 {
			n = defaultPrefetchWorkers
		}
		p.sem = make(chan struct{}, n)
		if p.Client == nil {
			p.Client = &http.Client{Timeout: 10 * time.Minute}
		}
		// Adopt anything already on disk from a previous run. Re-downloading
		// proofs we already hold would waste exactly the bandwidth this exists
		// to use well.
		_ = filepath.Walk(p.Dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() || filepath.Ext(path) == ".part" {
				return nil
			}
			base := filepath.Base(path)
			p.cached[base] = fi.Size()
			p.bytes += fi.Size()
			if o, e, ok := splitKey(base, byHash); ok {
				p.markReady(o, e)
			}
			return nil
		})
	})
}

func (p *Prefetcher) minFree() uint64 {
	if p.MinFreeBytes > 0 {
		return p.MinFreeBytes
	}
	return defaultMinFreeBytes
}

func (p *Prefetcher) maxBytes() int64 {
	if p.MaxBytes > 0 {
		return p.MaxBytes
	}
	return defaultPrefetchBytes
}

// cacheKey names a proof without embedding a URL, so the cache survives a log
// changing where it publishes.
func cacheKey(origin string, epoch int64) string {
	sum := sha256.Sum256([]byte(origin))
	return fmt.Sprintf("%s-%d.proof", hex.EncodeToString(sum[:6]), epoch)
}

// splitKey recovers the origin and epoch from a cache filename, given the
// origins this cache was told about.
func splitKey(base string, byHash map[string]string) (string, int64, bool) {
	name := strings.TrimSuffix(base, ".proof")
	i := strings.LastIndex(name, "-")
	if i <= 0 || name == base {
		return "", 0, false
	}
	o, ok := byHash[name[:i]]
	if !ok {
		return "", 0, false
	}
	e, err := strconv.ParseInt(name[i+1:], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return o, e, true
}

// markReady records that an epoch's proof is on disk. Caller holds no lock
// during init; every other caller holds p.mu.
func (p *Prefetcher) markReady(origin string, epoch int64) {
	m := p.ready[origin]
	if m == nil {
		m = map[int64]bool{}
		p.ready[origin] = m
	}
	m[epoch] = true
}

// Ready returns the next contiguous run of epochs whose proofs are on disk,
// at or after `after`, at most n long.
//
// This is what the work queue hands out. It used to hand out whatever the store
// said was unverified, which meant a lease could name epochs nobody had
// downloaded — and the worker then waited on a cold WAN fetch that began only
// when it asked. Both machines sat idle behind that: a laptop running eight
// concurrent verifications at under one core of eight, and a thirty-two core
// server at two, against a CDN giving about 20 Mbit/s per connection.
//
// Handing out only what is cached inverts it. The generator runs ahead and
// fills this; the queue drains it; a worker's first byte is a local read.
func (p *Prefetcher) Ready(origin string, after int64, n int) (from, to int64, ok bool) {
	if p == nil || n < 1 {
		return 0, 0, false
	}
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.ready[origin]
	if len(m) == 0 {
		return 0, 0, false
	}
	// The lowest cached epoch at or after `after`; then as far as it runs
	// without a gap. Sparse and small — the cache holds tens to hundreds of
	// epochs, not the history — so a scan of the keys is cheaper than keeping
	// them sorted through every add and release.
	first := int64(-1)
	for e := range m {
		if e >= after && (first < 0 || e < first) {
			first = e
		}
	}
	if first < 0 {
		return 0, 0, false
	}
	last := first
	for m[last+1] && last-first+1 < int64(n) {
		last++
	}
	return first, last, true
}

// Held reports how many proofs are cached for an origin, so the generator knows
// whether to fetch more.
func (p *Prefetcher) Held(origin string) int {
	if p == nil {
		return 0
	}
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready[origin])
}

// Path returns the cached proof for an epoch, or "" if it is not held.
func (p *Prefetcher) Path(origin string, epoch int64) string {
	if p == nil {
		return ""
	}
	p.init()
	k := cacheKey(origin, epoch)
	p.mu.Lock()
	_, ok := p.cached[k]
	p.mu.Unlock()
	if !ok {
		return ""
	}
	return filepath.Join(p.Dir, k)
}

// Release drops a proof once it has been verified.
//
// Called by the consumer rather than on a timer: the cache exists to hand work
// to the verifier, and the moment that has happened the bytes are dead weight
// occupying room the next download needs.
func (p *Prefetcher) Release(origin string, epoch int64) {
	if p == nil {
		return
	}
	p.init()
	k := cacheKey(origin, epoch)
	p.mu.Lock()
	size, ok := p.cached[k]
	if ok {
		delete(p.cached, k)
		p.bytes -= size
		if m := p.ready[origin]; m != nil {
			delete(m, epoch)
		}
	}
	p.mu.Unlock()
	if ok {
		_ = os.Remove(filepath.Join(p.Dir, k))
	}
}

// Fetch downloads one proof into the cache if there is room and it is not
// already held or in flight.
//
// Returns without error when the cache is full: a full cache is the system
// working, not a fault, and the caller simply tries again later.
func (p *Prefetcher) Fetch(ctx context.Context, origin, logDirectory string, epoch int64, prevRoot, currRoot string) error {
	if p == nil || p.Dir == "" {
		return nil
	}
	p.init()
	k := cacheKey(origin, epoch)

	p.mu.Lock()
	if _, held := p.cached[k]; held || p.inWork[k] || p.bytes >= p.maxBytes() {
		p.mu.Unlock()
		return nil
	}
	p.inWork[k] = true
	p.mu.Unlock()

	// Checked here, immediately before writing, because the interesting failure
	// is the disk filling from somewhere else between passes. Backing off is not
	// an error: verification keeps draining the cache, which frees space, so the
	// system recovers on its own rather than needing a human.
	if free, err := freeBytes(p.Dir); err == nil && free < p.minFree() {
		p.mu.Lock()
		delete(p.inWork, k)
		p.mu.Unlock()
		if p.Log != nil {
			p.Log.Warn("prefetch paused: not enough free disk",
				"free_gb", free>>30, "floor_gb", p.minFree()>>30,
				"note", "verification will drain the cache and free space")
		}
		return nil
	}

	defer func() {
		p.mu.Lock()
		delete(p.inWork, k)
		p.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.sem <- struct{}{}:
	}
	defer func() { <-p.sem }()

	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/%d/%s/%s", logDirectory, epoch, prevRoot, currRoot)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("prefetch: GET %s: HTTP %d", url, resp.StatusCode)
	}

	// Written to .part and renamed. A crash mid-download would otherwise leave
	// a truncated file that looks exactly like a complete one, and the verifier
	// would report a decode failure against a log that published fine.
	tmp := filepath.Join(p.Dir, k+".part")
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	// Through netmeter rather than straight off the body: that is where the
	// bytes are counted AND where the download is held below the line rate.
	// This is the path that pulls ~90% of everything, so a cap that missed it
	// would not be a cap.
	n, err := io.Copy(f, netmeter.Reader(ctx, origin, resp.Body))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmp)
		if err == nil {
			err = closeErr
		}
		return err
	}
	if err := os.Rename(tmp, filepath.Join(p.Dir, k)); err != nil {
		os.Remove(tmp)
		return err
	}

	p.mu.Lock()
	p.cached[k] = n
	p.markReady(origin, epoch)
	p.bytes += n
	held, total := len(p.cached), p.bytes
	p.mu.Unlock()

	if p.Log != nil {
		p.Log.Debug("proof prefetched", "origin", origin, "epoch", epoch,
			"mb", n>>20, "cached", held, "cache_gb", total>>30)
	}
	return nil
}

// Stats reports what the cache is holding.
func (p *Prefetcher) Stats() (files int, bytes int64) {
	if p == nil {
		return 0, 0
	}
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.cached), p.bytes
}

// Prune drops the oldest cached proofs until the cache is under its cap.
//
// Only needed when epochs are abandoned — a log that stops publishing, a sweep
// that is redirected — since the normal path releases each proof as it is
// verified.
func (p *Prefetcher) Prune() {
	if p == nil {
		return
	}
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bytes <= p.maxBytes() {
		return
	}
	type ent struct {
		key  string
		mod  time.Time
		size int64
	}
	// byKey lets a pruned file be forgotten from `ready` as well. Without it the
	// queue would go on offering an epoch whose bytes have been deleted, and the
	// worker would get a 404 for work the witness believed it held.
	byKey := map[string]struct {
		origin string
		epoch  int64
	}{}
	hashes := map[string]string{}
	for _, o := range p.Origins {
		sum := sha256.Sum256([]byte(o))
		hashes[hex.EncodeToString(sum[:6])] = o
	}
	for k := range p.cached {
		if o, e, ok := splitKey(k, hashes); ok {
			byKey[k] = struct {
				origin string
				epoch  int64
			}{o, e}
		}
	}
	var ents []ent
	for k, size := range p.cached {
		fi, err := os.Stat(filepath.Join(p.Dir, k))
		if err != nil {
			continue
		}
		ents = append(ents, ent{k, fi.ModTime(), size})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].mod.Before(ents[j].mod) })
	for _, e := range ents {
		if p.bytes <= p.maxBytes() {
			return
		}
		delete(p.cached, e.key)
		p.bytes -= e.size
		if id, ok := byKey[e.key]; ok {
			if m := p.ready[id.origin]; m != nil {
				delete(m, id.epoch)
			}
		}
		_ = os.Remove(filepath.Join(p.Dir, e.key))
	}
}

// ReportMetrics publishes the cache's occupancy.
//
// This is the panel that tells a CPU-bound pipeline from a bandwidth-bound one,
// and nothing else can. The cache sits between downloading and verifying: full
// means downloads are outrunning verification, so the link has headroom and the
// CPU is the constraint; empty while the CPU idles means the opposite. Without
// it, "are we saturating both?" can only be answered by inference — which is
// how this project spent an afternoon reasoning about the wrong resource.
func (p *Prefetcher) ReportMetrics() {
	if p == nil || p.Dir == "" {
		return
	}
	files, bytes := p.Stats()
	metrics.Set("kt_witness_prefetch_cache_bytes", nil, float64(bytes))
	metrics.Set("kt_witness_prefetch_cache_files", nil, float64(files))
	metrics.Set("kt_witness_prefetch_cache_max_bytes", nil, float64(p.maxBytes()))
	if free, err := freeBytes(p.Dir); err == nil {
		metrics.Set("kt_witness_prefetch_disk_free_bytes", nil, float64(free))
	}
}
