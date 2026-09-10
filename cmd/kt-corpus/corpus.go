package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The corpus is a bounded, on-disk set of real proofs kept so that verification
// code can be re-run against them offline and deterministically.
//
// This is deliberately NOT evidence retention. docs/cost.md is still correct
// that audit proofs are verified and discarded in production: keeping Meta's
// and WhatsApp's proofs at full rate would be ~136 TB/year and would buy
// nothing. What a regression corpus buys is different and much cheaper — a
// fixed set of inputs that (a) exercises the real verifiers on every change,
// without re-downloading or hammering a provider, and (b) survives a provider
// rewriting or withdrawing data we already checked.
//
// # Why the layout is shaped like a URL
//
// The AKD verifier fetches its proof over HTTP from
// `{log_directory}/{epoch}/{prev_root}/{curr_root}`, and Signal's verifier is a
// method on an internal Source that only reaches its response through an HTTP
// endpoint. Neither can be handed bytes directly without changing code we do
// not want to fork — and a corpus that replays through a reimplemented verifier
// tests the reimplementation, not the witness.
//
// So the corpus stores each blob at exactly the path its provider serves it
// from, and replay starts a loopback HTTP server over that directory and points
// the real, unmodified code at it. The verification path exercised by a replay
// is byte-for-byte the one that runs in production; only the socket differs.

// Kind names an ecosystem whose artifacts the corpus can hold. The two kinds
// are the ones worth keeping: AKD because its proofs are enormous and slow to
// re-fetch, Signal because its responses are tiny and cover the newest and most
// intricate code in the project (VRF, prefix tree, search proof).
type Kind string

const (
	KindAKD    Kind = "akd"
	KindSignal Kind = "signal"
)

// Manifest records what one artifact is and what it must verify to.
//
// The expectation is the point. A replay that only asks "did this parse?" would
// pass on a blob that verifies to a completely different root, which is the one
// outcome we most need to catch. So every field a verifier produces is written
// down at capture time, when the artifact was known good, and replay compares
// against the record rather than against whatever the code now happens to say.
type Manifest struct {
	Kind   Kind   `json:"kind"`
	Origin string `json:"origin"`

	// Seq orders artifacts within an origin: the epoch for AKD, the verified
	// tree size for Signal. It is what -gc uses to keep a spread rather than a
	// contiguous run.
	Seq int64 `json:"seq"`

	// Blob is the artifact's path relative to the corpus root, slash-separated
	// so a manifest copied between hosts still resolves.
	Blob   string `json:"blob"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`

	// PrevRoot and CurrRoot are the AKD epoch's published roots, taken from the
	// object key itself — so a replay checks the proof against the roots the log
	// published, never against anything we derived.
	PrevRoot string `json:"prev_root,omitempty"`
	CurrRoot string `json:"curr_root,omitempty"`

	// Root is the tree root a Signal replay must derive, hex encoded.
	Root string `json:"root,omitempty"`

	CapturedAt time.Time `json:"captured_at"`

	// path is where this manifest was loaded from. Not serialised.
	path string
}

// Corpus is one corpus directory plus the two limits that make it safe to run
// on a live host.
type Corpus struct {
	Dir string

	// MaxBytes is the hard total cap across every ecosystem, not per ecosystem.
	// A per-ecosystem cap is the wrong shape here: the host's thin pool does not
	// care which log filled it.
	MaxBytes int64

	// MinFreeBytes is the floor of free space that must remain after a
	// download. The witness host runs on an over-provisioned thin LVM pool, and
	// filling a thin pool does not merely fail a write — it can freeze every
	// guest on the pool. So this is checked before each download and again after
	// it, and a violation stops the run rather than logging a warning.
	MinFreeBytes int64

	// free reports bytes available to an unprivileged writer under dir. It is a
	// field so tests can simulate a nearly full host without one.
	free func(dir string) (int64, error)
}

func NewCorpus(dir string, maxBytes, minFree int64) *Corpus {
	return &Corpus{Dir: dir, MaxBytes: maxBytes, MinFreeBytes: minFree, free: freeSpace}
}

// slug makes an origin safe as a single path element while keeping it readable,
// because someone reading `ls` output should be able to tell which log a
// directory holds.
func slug(origin string) string {
	r := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	return r.Replace(origin)
}

func (c *Corpus) blobDir(kind Kind, origin string) string {
	return filepath.Join(c.Dir, string(kind), slug(origin), "blobs")
}

func (c *Corpus) manifestDir(kind Kind, origin string) string {
	return filepath.Join(c.Dir, string(kind), slug(origin), "manifests")
}

// Manifests loads every manifest in the corpus, ordered by kind, origin and
// sequence so that -status, -verify and -gc all see the same stable order.
func (c *Corpus) Manifests() ([]*Manifest, error) {
	var out []*Manifest
	err := filepath.WalkDir(c.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// A directory we cannot read is a reason to stop, not to silently
			// report a smaller corpus than exists — an undercount would let the
			// cap be exceeded.
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) != "manifests" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("corpus: manifest %s: %w", path, err)
		}
		m.path = path
		out = append(out, &m)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}

// TotalBytes is the corpus's accounted size, which is what the cap is enforced
// against.
func (c *Corpus) TotalBytes() (int64, error) {
	ms, err := c.Manifests()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, m := range ms {
		n += m.Bytes
	}
	return n, nil
}

// Has reports whether an artifact with this identity is already stored, so a
// re-run of -fetch neither re-downloads nor double-counts it.
func (c *Corpus) Has(kind Kind, origin string, seq int64) bool {
	_, err := os.Stat(c.manifestPath(kind, origin, seq))
	return err == nil
}

func (c *Corpus) manifestPath(kind Kind, origin string, seq int64) string {
	return filepath.Join(c.manifestDir(kind, origin), fmt.Sprintf("%d.json", seq))
}

// ErrCapReached and ErrFloorReached stop a fetch run cleanly. They are distinct
// because they mean different things to an operator: the cap is a policy we
// chose and can raise, the floor is the host telling us to stop.
var (
	ErrCapReached   = fmt.Errorf("corpus: size cap reached")
	ErrFloorReached = fmt.Errorf("corpus: free-space floor reached")
)

// CheckBudget decides whether an artifact of about `want` bytes may be
// downloaded at all.
//
// Both limits are checked before anything is written, and the caller checks
// again as bytes arrive, because a provider's Content-Length is a claim rather
// than a fact.
func (c *Corpus) CheckBudget(want int64) error {
	total, err := c.TotalBytes()
	if err != nil {
		return err
	}
	if total+want > c.MaxBytes {
		return fmt.Errorf("%w: %s stored + %s wanted exceeds cap %s",
			ErrCapReached, human(total), human(want), human(c.MaxBytes))
	}
	free, err := c.free(c.Dir)
	if err != nil {
		return err
	}
	if free-want < c.MinFreeBytes {
		return fmt.Errorf("%w: %s free, %s wanted, floor %s",
			ErrFloorReached, human(free), human(want), human(c.MinFreeBytes))
	}
	return nil
}

// Remaining is how many more bytes may be stored before either limit binds. It
// is what bounds a streaming download whose true length is not known in
// advance.
func (c *Corpus) Remaining() (int64, error) {
	total, err := c.TotalBytes()
	if err != nil {
		return 0, err
	}
	free, err := c.free(c.Dir)
	if err != nil {
		return 0, err
	}
	byCap := c.MaxBytes - total
	byFloor := free - c.MinFreeBytes
	if byFloor < byCap {
		return byFloor, nil
	}
	return byCap, nil
}

// writeBlob streams r into the corpus, refusing to write past the remaining
// budget.
//
// The limit is enforced here rather than by checking the file afterwards
// because "write it and see" is exactly the behaviour that fills a thin pool:
// the failure we are guarding against happens during the write, not after it.
func (c *Corpus) writeBlob(dst string, r io.Reader, budget int64) (int64, string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, "", err
	}
	// Written to a temporary name and renamed, so an interrupted download never
	// looks like a complete artifact to a later replay.
	tmp := dst + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	// One byte past the budget is enough to detect an overrun, and stops us
	// storing it.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, budget+1))
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err == nil && n > budget {
		err = fmt.Errorf("%w: artifact exceeded remaining budget of %s", ErrCapReached, human(budget))
	}
	if err != nil {
		os.Remove(tmp)
		return 0, "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// save writes a manifest once its artifact has been verified.
//
// Nothing is admitted to the corpus unverified. An artifact whose expectation
// was never established would turn every future replay into a tautology: it
// would "pass" against a recorded value that no verifier ever produced.
func (c *Corpus) save(m *Manifest) error {
	dir := c.manifestDir(m.Kind, m.Origin)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p := c.manifestPath(m.Kind, m.Origin, m.Seq)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// checkBlob confirms an artifact is byte-identical to what was captured.
//
// This runs before verification, and its failure is reported differently,
// because the two say different things: a hash mismatch means our disk or our
// copy is wrong, whereas a verification failure on intact bytes means the
// verifier changed behaviour — which is the regression the corpus exists to
// catch.
func (c *Corpus) checkBlob(m *Manifest) error {
	p := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != m.Bytes {
		return fmt.Errorf("blob is %d bytes, manifest records %d", n, m.Bytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		return fmt.Errorf("blob sha256 %s does not match manifest %s", got[:16], m.SHA256[:16])
	}
	return nil
}

// remove deletes an artifact and its manifest together. The manifest goes first
// so a crash mid-delete leaves an unreferenced blob — wasted space, which is
// recoverable — rather than a manifest pointing at nothing, which would look
// like corruption on the next replay.
func (c *Corpus) remove(m *Manifest) error {
	if m.path != "" {
		if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	p := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GC prunes the corpus back under the cap.
//
// The policy is diversity-preserving rather than simply oldest-first. A corpus
// of 100 consecutive epochs from one week is a much weaker regression suite
// than 20 epochs spread across a year, because consecutive epochs of the same
// log exercise the same code with nearly the same shapes. So each round drops
// the artifact from the largest-consuming ecosystem whose sequence number is
// closest to a surviving neighbour — the most redundant one — and the extremes
// of each origin's range are kept, so the span the corpus covers never shrinks
// from the ends.
func (c *Corpus) GC() ([]*Manifest, error) {
	ms, err := c.Manifests()
	if err != nil {
		return nil, err
	}
	var dropped []*Manifest
	for {
		var total int64
		byKind := map[Kind]int64{}
		for _, m := range ms {
			total += m.Bytes
			byKind[m.Kind] += m.Bytes
		}
		if total <= c.MaxBytes {
			return dropped, nil
		}

		var worstKind Kind
		var worstBytes int64
		for k, b := range byKind {
			if b > worstBytes {
				worstKind, worstBytes = k, b
			}
		}

		victim := mostRedundant(ms, worstKind)
		if victim == nil {
			// Every remaining artifact in the largest kind is an endpoint of its
			// origin's range. Rather than refuse to converge, fall back to the
			// largest artifact overall.
			victim = largest(ms)
		}
		if victim == nil {
			return dropped, fmt.Errorf("corpus: %s stored still exceeds cap %s but nothing can be dropped",
				human(total), human(c.MaxBytes))
		}
		if err := c.remove(victim); err != nil {
			return dropped, err
		}
		dropped = append(dropped, victim)
		ms = without(ms, victim)
	}
}

// mostRedundant picks the artifact of the given kind that contributes least to
// the corpus's spread: the one whose nearest surviving neighbour in the same
// origin is closest. Endpoints of a range are never chosen, so pruning erodes
// density and not coverage.
func mostRedundant(ms []*Manifest, kind Kind) *Manifest {
	byOrigin := map[string][]*Manifest{}
	for _, m := range ms {
		if m.Kind == kind {
			byOrigin[m.Origin] = append(byOrigin[m.Origin], m)
		}
	}
	var best *Manifest
	var bestGap int64 = -1
	for _, list := range byOrigin {
		if len(list) < 3 {
			continue // only endpoints; dropping one would shrink the span
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Seq < list[j].Seq })
		for i := 1; i < len(list)-1; i++ {
			gap := list[i+1].Seq - list[i-1].Seq
			// A larger artifact breaks ties, since it buys back more space for
			// the same loss of density.
			if bestGap < 0 || gap < bestGap || (gap == bestGap && best != nil && list[i].Bytes > best.Bytes) {
				best, bestGap = list[i], gap
			}
		}
	}
	return best
}

func largest(ms []*Manifest) *Manifest {
	var best *Manifest
	for _, m := range ms {
		if best == nil || m.Bytes > best.Bytes {
			best = m
		}
	}
	return best
}

func without(ms []*Manifest, drop *Manifest) []*Manifest {
	out := ms[:0]
	for _, m := range ms {
		if m != drop {
			out = append(out, m)
		}
	}
	return out
}

// human formats a byte count for operator-facing output. Sizes here span
// kilobytes to hundreds of gigabytes, and a raw integer at that range is
// genuinely hard to read correctly at a glance.
func human(n int64) string {
	const unit = 1 << 10
	if n < 0 {
		return "-" + human(-n)
	}
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
