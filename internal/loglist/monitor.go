package loglist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/source/c2sp"
)

// DefaultProbeInterval is how often a discovered log that is not yet polled is
// tried again. A log that starts publishing tiles after we discovered it is
// picked up within this long.
const DefaultProbeInterval = time.Hour

// probeTimeout bounds one probe: a checkpoint and the tiles behind its root.
// probeConcurrency is how many run at once.
const (
	probeTimeout     = time.Minute
	probeConcurrency = 4
)

// Monitor turns list-discovered logs into polled ones where it can.
//
// A list names an origin and a key, never a monitoring URL, so a discovered log
// is witnessed by push alone: we see only what its operator chooses to send.
// Many C2SP logs, though, are served at the URL their origin spells — origin
// "example.com/log" publishes https://example.com/log/checkpoint and tiles
// beside it. For each discovered log the Monitor tries exactly that URL, and a
// log that answers with a checkpoint signed under the key we already hold, and
// tiles that back its root, is polled from then on like a configured one.
//
// The URL is a convention, not a claim the list makes, so nothing about trust
// changes: the source pins the origin line and the key the log was discovered
// with, and a server at that URL that is not the log cannot produce a
// checkpoint we accept. What the URL does change is where this witness
// connects, and the origin is an input a third party wrote. Hence the
// restrictions in probeURL and PublicClient: a public DNS name, the default
// port, and a dialer that refuses private, loopback and link-local addresses
// on every connection, not just the first.
//
// Like the rest of this package it only adds. A polled log that later stops
// answering is not demoted: it is a log we were watching that went dark, and
// the round loop reports that the way it reports any other.
type Monitor struct {
	Registry *Registry
	// Configured is every origin the operator configured, of any type. The
	// registry only knows the C2SP ones, which are the only ones that can be
	// pushed; a sigsum or static CT log can also be on a list, and promoting
	// it here would witness one origin from two sources in the same round.
	Configured map[string]bool
	// Interval defaults to DefaultProbeInterval.
	Interval time.Duration
	// Client defaults to PublicClient(). Every request a promoted source
	// makes goes through it.
	Client *http.Client
	Log    *slog.Logger

	// baseURL maps an origin to the URL the log is probed at, or "" if the
	// origin cannot name one. Nil means probeURL; tests substitute their own.
	baseURL func(origin string) string

	clientOnce sync.Once

	mu      sync.RWMutex
	sources map[string]source.Source
	urls    map[string]string
}

// Run probes immediately, then every Interval until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	iv := m.Interval
	if iv <= 0 {
		iv = DefaultProbeInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for ctx.Err() == nil {
		m.ProbeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ProbeOnce tries every discovered log not already polled, and returns how many
// it promoted. Configured logs are skipped: they have a URL the operator chose.
//
// Probes run a few at a time. Against the real staging list most hosts answer
// at once, but a dead one holds its probe for the full timeout, and one at a
// time a handful of those made a pass take minutes.
func (m *Monitor) ProbeOnce(ctx context.Context) int {
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, probeConcurrency)
		n   atomic.Int64
	)
	for _, l := range m.Registry.Logs() {
		if m.Registry.IsStatic(l.Origin) || m.Configured[l.Origin] || m.Polled(l.Origin) {
			continue
		}
		u := m.urlFor(l.Origin)
		if u == "" {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(l *push.Log) {
			defer wg.Done()
			defer func() { <-sem }()
			src, err := m.probe(ctx, l, u)
			if err != nil {
				// Most discovered logs will not be at their origin's URL;
				// that is the expected answer and it stays push-only, so not
				// a warning.
				m.log().Debug("loglist: discovered log is not pollable", "origin", l.Origin, "url", u, "err", err)
				return
			}
			m.mu.Lock()
			if m.sources == nil {
				m.sources = make(map[string]source.Source)
				m.urls = make(map[string]string)
			}
			m.sources[l.Origin] = src
			m.urls[l.Origin] = u
			m.mu.Unlock()
			n.Add(1)
			m.log().Info("loglist: polling discovered log", "origin", l.Origin, "url", u)
		}(l)
	}
	wg.Wait()
	return int(n.Load())
}

// probe builds a source for l at u and checks that it can actually be
// witnessed: the checkpoint verifies under l's key and origin, and the log
// serves tiles that hash to its root. A log with a checkpoint but no tiles
// would otherwise be promoted into an error every round.
func (m *Monitor) probe(ctx context.Context, l *push.Log, u string) (source.Source, error) {
	src, err := c2sp.New(c2sp.Config{
		Origin:     l.Origin,
		BaseURL:    u,
		Verifier:   l.Verifier,
		HTTPClient: m.client(),
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	head, err := src.Fetch(ctx, nil)
	if err != nil {
		return nil, err
	}
	// An empty tree has no tiles, so it cannot show it serves any; the next
	// pass after it grows can.
	if head.Size == 0 {
		return nil, errors.New("checkpoint is for the empty tree")
	}
	// From the empty tree: no consistency claim, only that the tiles behind
	// this root exist and hash to it.
	if err := src.VerifyConsistency(ctx, nil, head); err != nil {
		return nil, err
	}
	return src, nil
}

// Sources returns the promoted sources, ordered by origin. Safe on a nil
// Monitor, which has none.
func (m *Monitor) Sources() []source.Source {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]source.Source, 0, len(m.sources))
	for _, s := range m.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin() < out[j].Origin() })
	return out
}

// Polled reports whether origin has been promoted. Safe on a nil Monitor.
func (m *Monitor) Polled(origin string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.sources[origin]
	return ok
}

// URL returns the URL a promoted origin is polled at, or "".
func (m *Monitor) URL(origin string) string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.urls[origin]
}

func (m *Monitor) urlFor(origin string) string {
	if m.baseURL != nil {
		return m.baseURL(origin)
	}
	return probeURL(origin)
}

// client is shared by every probe and promoted source, so they share one
// connection pool rather than each minting a transport.
func (m *Monitor) client() *http.Client {
	m.clientOnce.Do(func() {
		if m.Client == nil {
			m.Client = PublicClient()
		}
	})
	return m.Client
}

func (m *Monitor) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// probeURL returns "https://<origin>/" when origin reads as a public DNS name
// followed by an optional path, and "" otherwise. "go.sum database tree" names
// no URL; neither does an origin whose host is an IP literal, carries a port,
// or is a single label like "localhost" or "proxmox". The checks are on the
// text; PublicClient is what checks the addresses a name resolves to.
func probeURL(origin string) string {
	if origin == "" || strings.ContainsAny(origin, " \t\r\n?#%@\\") || strings.Contains(origin, "://") {
		return ""
	}
	host, path, _ := strings.Cut(origin, "/")
	if !publicHostname(host) {
		return ""
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return ""
		}
	}
	return "https://" + strings.TrimSuffix(origin, "/") + "/"
}

func publicHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 || strings.HasSuffix(h, ".") {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// A numeric final label is how an IPv4 address in an unusual spelling
	// ("0x7f.1") gets past ParseAddr. No public suffix is all digits.
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// PublicClient returns an HTTP client for URLs derived from third-party input.
// It connects only to public unicast addresses, checked on every dial — so a
// redirect, or a name that later resolves somewhere else, cannot turn it on
// this witness's own network — and it never uses a proxy, which would make the
// dialed address the proxy's rather than the destination's.
func PublicClient() *http.Client {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkPublic(address)
		},
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("loglist: refusing redirect to %s", req.URL.Scheme)
			}
			if len(via) >= 3 {
				return errors.New("loglist: too many redirects")
			}
			return nil
		},
	}
}

// errNotPublic is returned for a dial to an address PublicClient refuses.
var errNotPublic = errors.New("loglist: refusing to connect to a non-public address")

// cgnat is 100.64.0.0/10, shared address space — and the range Tailscale
// hands out, so a homelab's tailnet lives there.
// notPublic is every range a log's address has no business being in, beyond
// what the netip predicates already cover: special-purpose IPv4 space, and the
// IPv6 prefixes that carry an IPv4 address inside them. A NAT64 or 6to4 address
// is a way to name an IPv4 host — on a network that translates, possibly one on
// our own LAN — so those are refused outright rather than unwrapped.
var notPublic = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"; Linux routes a dial here to the local host
		"100.64.0.0/10",   // shared address space — and the range Tailscale hands out
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved
		"::/96",           // IPv4-compatible (deprecated)
		"64:ff9b::/96",    // NAT64
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard-only
		"2001::/23",       // IETF protocol assignments, Teredo among them
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

func checkPublic(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: %s", errNotPublic, ip)
	}
	for _, p := range notPublic {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s", errNotPublic, ip)
		}
	}
	return nil
}
