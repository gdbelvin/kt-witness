package loglist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

const (
	// DefaultInterval is how often lists are re-fetched when unset.
	DefaultInterval = 24 * time.Hour
	// MaxInterval is the network's requirement: lists are applied at least
	// weekly. A longer configured interval is clamped to it.
	MaxInterval = 7 * 24 * time.Hour

	// DefaultMaxBytes bounds a list download. The largest published profile
	// is sized for 40,000 logs; at roughly 250 bytes per Ed25519 entry that is
	// about 10 MiB, so a tighter bound would eventually reject the real list.
	DefaultMaxBytes = 16 << 20

	// fetchTimeout bounds one list download, end to end.
	fetchTimeout = 60 * time.Second
)

// ListStatus is what the status page shows about one list.
type ListStatus struct {
	URL string
	// LastFetch is the last time the list was fetched AND parsed; zero if
	// never. LastAttempt is the last try, successful or not.
	LastFetch   time.Time
	LastAttempt time.Time
	// LastErr is the error from LastAttempt, empty if it succeeded.
	LastErr string
	// Logs is how many entries the last good copy of the list had.
	Logs int
	// Added is how many logs this list has introduced during this process.
	Added int
}

// Fetcher periodically downloads log lists and adds newly listed logs to the
// store and registry. It never removes or changes a log: see the package doc.
type Fetcher struct {
	URLs     []string
	Interval time.Duration
	// Client defaults to a client with a timeout.
	Client *http.Client
	// MaxBytes defaults to DefaultMaxBytes.
	MaxBytes int64
	Store    *store.Store
	Registry *Registry
	Log      *slog.Logger

	mu     sync.Mutex
	status map[string]*ListStatus
}

// Run loads previously discovered logs, fetches every list immediately, then
// again every Interval until ctx is done.
func (f *Fetcher) Run(ctx context.Context) {
	// Load is idempotent, and doing it here means a forgotten Load at startup
	// cannot leave stored logs out of the registry: FetchOnce would see them
	// as already known and never add them.
	if err := f.Registry.Load(f.Store); err != nil {
		f.log().Error("loglist: loading discovered logs", "err", err)
	}
	iv := f.interval()
	t := time.NewTicker(iv)
	defer t.Stop()
	for ctx.Err() == nil {
		// Errors are logged and recorded in Status by FetchOnce; the
		// previous state stays in force until the next tick.
		_ = f.FetchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (f *Fetcher) interval() time.Duration {
	switch {
	case f.Interval <= 0:
		return DefaultInterval
	case f.Interval > MaxInterval:
		f.log().Warn("loglist: interval exceeds the network's weekly minimum; clamping",
			"configured", f.Interval, "used", MaxInterval)
		return MaxInterval
	}
	return f.Interval
}

// FetchOnce fetches and applies every list once. Lists are independent: one
// failing does not stop the others. The returned error joins every failure.
func (f *Fetcher) FetchOnce(ctx context.Context) error {
	var errs []error
	for _, u := range f.URLs {
		if err := f.fetchList(ctx, u); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f *Fetcher) fetchList(ctx context.Context, url string) error {
	now := time.Now()
	entries, err := f.download(ctx, url)
	if err != nil {
		// The whole list is rejected; nothing from it is applied. What we
		// already have stays exactly as it was.
		f.log().Error("loglist: list rejected, keeping previous state", "list", url, "err", err)
		f.record(url, func(s *ListStatus) { s.LastAttempt, s.LastErr = now, err.Error() })
		return err
	}

	added := 0
	var errs []error
	for _, e := range entries {
		ok, err := f.apply(url, e, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ok {
			added++
		}
	}
	err = errors.Join(errs...)
	f.record(url, func(s *ListStatus) {
		s.LastAttempt = now
		s.Logs = len(entries)
		s.Added += added
		if err != nil {
			// The list parsed but could not be fully persisted: the
			// store is the problem, not the list, so don't call it fetched.
			s.LastErr = err.Error()
			return
		}
		s.LastFetch, s.LastErr = now, ""
	})
	return err
}

// apply adds one entry if it is new, and reports whether it did.
func (f *Fetcher) apply(url string, e Entry, now time.Time) (bool, error) {
	if f.Registry.IsStatic(e.Origin) {
		// The operator's configuration wins; the list's opinion of this
		// log is not recorded at all.
		return false, nil
	}
	if _, known := f.Registry.Lookup(e.Origin); known {
		// Already discovered, possibly from another list (the real lists
		// overlap). Whatever this list now says about it is ignored.
		return false, nil
	}
	v, err := note.NewVerifier(e.VKey)
	if err != nil {
		// Most likely a key type golang.org/x/mod/sumdb/note can't verify,
		// such as ML-DSA-44. We couldn't check its checkpoints, so we don't
		// record it — leaving the slot open for when we can.
		f.log().Warn("loglist: skipping log whose key we cannot verify",
			"list", url, "origin", e.Origin, "key_type", fmt.Sprintf("0x%02x", e.KeyType()), "err", err)
		return false, nil
	}
	pl := &store.PushLog{
		Origin: e.Origin, VKey: e.VKey, QPD: e.QPD, Contact: e.Contact,
		List: url, AddedAt: now.UTC(),
	}
	stored, err := f.Store.AddPushLog(pl)
	if err != nil {
		return false, err
	}
	if !stored {
		// In the store but not the registry: Load was skipped or failed for
		// it. The stored key is authoritative; this list's is not.
		return false, nil
	}
	l := &push.Log{
		Origin: pl.Origin, VKey: pl.VKey, Verifier: v,
		QPD: pl.QPD, Contact: pl.Contact, From: url,
	}
	if !f.Registry.add(l) {
		return false, nil
	}
	f.log().Info("loglist: discovered log", "origin", e.Origin, "list", url, "qpd", e.QPD)
	return true, nil
}

func (f *Fetcher) download(ctx context.Context, url string) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loglist: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loglist: fetch %s: HTTP %s", url, resp.Status)
	}
	max := f.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	// Read one byte past the bound so an oversized list is an error rather
	// than silently truncated — a truncated list could parse cleanly with
	// its tail missing.
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("loglist: fetch %s: %w", url, err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("loglist: fetch %s: list exceeds %d bytes", url, max)
	}
	entries, err := Parse(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w (from %s)", err, url)
	}
	return entries, nil
}

func (f *Fetcher) record(url string, update func(*ListStatus)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status == nil {
		f.status = make(map[string]*ListStatus)
	}
	s := f.status[url]
	if s == nil {
		s = &ListStatus{URL: url}
		f.status[url] = s
	}
	update(s)
}

// Status reports on each configured list, in URLs order. A list not yet
// attempted has zero times.
func (f *Fetcher) Status() []ListStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ListStatus, 0, len(f.URLs))
	for _, u := range f.URLs {
		if s := f.status[u]; s != nil {
			out = append(out, *s)
		} else {
			out = append(out, ListStatus{URL: u})
		}
	}
	return out
}

func (f *Fetcher) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}
