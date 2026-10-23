package loglist

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/push"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// tileLog is a tlog-tiles log in memory, served at /<origin>/ the way a log
// whose URL is its origin would be.
type tileLog struct {
	origin string
	signer note.Signer
	vkey   string
	hashes []tlog.Hash
	n      int64

	noTiles bool // serve the checkpoint but 404 every tile
	hits    atomic.Int64
}

func newTileLog(t *testing.T, origin string, n int) *tileLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	l := &tileLog{origin: origin, signer: s, vkey: vkey}
	for i := 0; i < n; i++ {
		stored, err := tlog.StoredHashes(int64(i), fmt.Appendf(nil, "entry %d", i), l)
		if err != nil {
			t.Fatal(err)
		}
		l.hashes = append(l.hashes, stored...)
	}
	l.n = int64(n)
	return l
}

func (l *tileLog) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, ix := range indexes {
		if ix < 0 || ix >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("hash %d not stored", ix)
		}
		out[i] = l.hashes[ix]
	}
	return out, nil
}

func (l *tileLog) checkpoint(t *testing.T, signer note.Signer) []byte {
	t.Helper()
	root, err := tlog.TreeHash(l.n, l)
	if err != nil {
		t.Fatal(err)
	}
	text := torchwood.Checkpoint{Origin: l.origin, Tree: tlog.Tree{N: l.n, Hash: root}}.String()
	msg, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// pushLog is how the registry would hold l had a list named it.
func (l *tileLog) pushLog(t *testing.T) *push.Log {
	t.Helper()
	v, err := note.NewVerifier(l.vkey)
	if err != nil {
		t.Fatal(err)
	}
	return &push.Log{Origin: l.origin, VKey: l.vkey, Verifier: v, From: "https://list.invalid/l"}
}

// logHost serves several tileLogs, each under /<origin>/.
func logHost(t *testing.T, cp map[string][]byte, logs ...*tileLog) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, l := range logs {
			rest, ok := strings.CutPrefix(r.URL.Path, "/"+l.origin+"/")
			if !ok {
				continue
			}
			l.hits.Add(1)
			if rest == "checkpoint" {
				w.Write(cp[l.origin])
				return
			}
			if l.noTiles {
				break
			}
			tile, err := torchwood.ParseTilePath(rest)
			if err != nil || tile.L < 0 {
				break
			}
			data, err := tlog.ReadTileData(tile, l)
			if err != nil {
				break
			}
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMonitorPromotesOnlyWitnessableLogs(t *testing.T) {
	good := newTileLog(t, "good.example/log", 300)
	wrongKey := newTileLog(t, "wrongkey.example/log", 10)
	noTiles := newTileLog(t, "notiles.example/log", 10)
	noTiles.noTiles = true
	absent := newTileLog(t, "absent.example/log", 10)
	configured := newTileLog(t, "configured.example/log", 10)
	empty := newTileLog(t, "empty.example/log", 0)

	// Same origin, same tree, a key the list never named.
	impostor := newTileLog(t, wrongKey.origin, 0)
	cp := map[string][]byte{
		good.origin:       good.checkpoint(t, good.signer),
		wrongKey.origin:   wrongKey.checkpoint(t, impostor.signer),
		noTiles.origin:    noTiles.checkpoint(t, noTiles.signer),
		configured.origin: configured.checkpoint(t, configured.signer),
		empty.origin:      empty.checkpoint(t, empty.signer),
	}
	srv := logHost(t, cp, good, wrongKey, noTiles, configured, empty)

	reg := NewRegistry([]*push.Log{configured.pushLog(t)})
	for _, l := range []*tileLog{good, wrongKey, noTiles, absent, empty} {
		reg.add(l.pushLog(t))
	}
	m := &Monitor{
		Registry: reg,
		Client:   srv.Client(),
		baseURL:  func(o string) string { return srv.URL + "/" + o + "/" },
	}

	if n := m.ProbeOnce(context.Background()); n != 1 {
		t.Fatalf("ProbeOnce promoted %d logs, want 1", n)
	}
	for _, c := range []struct {
		l    *tileLog
		want bool
	}{{good, true}, {wrongKey, false}, {noTiles, false}, {absent, false}, {configured, false}, {empty, false}} {
		if got := m.Polled(c.l.origin); got != c.want {
			t.Errorf("Polled(%s) = %v, want %v", c.l.origin, got, c.want)
		}
	}
	if configured.hits.Load() != 0 {
		t.Errorf("configured log was probed %d times; it has an operator-chosen URL", configured.hits.Load())
	}
	if m.URL(good.origin) == "" {
		t.Error("URL of a polled log is empty")
	}

	srcs := m.Sources()
	if len(srcs) != 1 || srcs[0].Origin() != good.origin {
		t.Fatalf("Sources() = %v, want just %s", srcs, good.origin)
	}
	head, err := srcs[0].Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("promoted source cannot fetch: %v", err)
	}
	if head.Size != good.n {
		t.Errorf("fetched size %d, want %d", head.Size, good.n)
	}

	// A second pass leaves the polled log alone and promotes nothing new.
	before := good.hits.Load()
	if n := m.ProbeOnce(context.Background()); n != 0 {
		t.Errorf("second ProbeOnce promoted %d, want 0", n)
	}
	if good.hits.Load() != before {
		t.Error("an already polled log was probed again")
	}
}

// A log the list names but that only starts publishing later is picked up on a
// later pass.
func TestMonitorRetriesUnpollableLogs(t *testing.T) {
	late := newTileLog(t, "late.example/log", 5)
	cp := map[string][]byte{}
	srv := logHost(t, cp, late)
	reg := NewRegistry(nil)
	reg.add(late.pushLog(t))
	m := &Monitor{Registry: reg, Client: srv.Client(),
		baseURL: func(o string) string { return srv.URL + "/" + o + "/" }}

	if n := m.ProbeOnce(context.Background()); n != 0 {
		t.Fatalf("promoted a log with no checkpoint")
	}
	cp[late.origin] = late.checkpoint(t, late.signer)
	if n := m.ProbeOnce(context.Background()); n != 1 {
		t.Fatalf("did not promote the log once it published")
	}
}

func TestNilMonitorHasNoSources(t *testing.T) {
	var m *Monitor
	if m.Sources() != nil || m.Polled("x") || m.URL("x") != "" {
		t.Fatal("nil Monitor reported something")
	}
}

func TestProbeURL(t *testing.T) {
	for origin, want := range map[string]string{
		"api.riskrouter.eu/tlog/evidence-v2":        "https://api.riskrouter.eu/tlog/evidence-v2/",
		"transparency.syngraphe.org/countersign/v1": "https://transparency.syngraphe.org/countersign/v1/",
		"example.com":      "https://example.com/",
		"example.com/log/": "https://example.com/log/",
		"sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1": "https://sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1/",

		// No URL in these.
		"go.sum database tree": "",
		"":                     "",
		"localhost/log":        "",
		"proxmox/log":          "",
		"192.168.0.42/redfish": "",
		"127.0.0.1/log":        "",
		"[::1]/log":            "",
		"0x7f.1/log":           "",
		"10.0.0.1":             "",
		"example.com:8080/log": "",
		"user@example.com/log": "",
		"https://example.com":  "",
		"example.com/../x":     "",
		"example.com/a?b":      "",
		"example.com/a#b":      "",
		"example.com./log":     "",
		"-bad.example.com/log": "",
		"exa_mple.com/log":     "",
	} {
		if got := probeURL(origin); got != want {
			t.Errorf("probeURL(%q) = %q, want %q", origin, got, want)
		}
	}
}

func TestCheckPublic(t *testing.T) {
	for addr, ok := range map[string]bool{
		"1.1.1.1:443":              true,
		"[2606:4700::1111]:443":    true,
		"127.0.0.1:443":            false,
		"10.1.2.3:443":             false,
		"172.16.0.1:443":           false,
		"192.168.0.42:443":         false,
		"100.92.87.118:443":        false, // tailnet
		"169.254.169.254:80":       false, // cloud metadata
		"0.0.0.0:443":              false,
		"0.1.2.3:443":              false,
		"[::1]:443":                false,
		"[fd00::1]:443":            false,
		"[fe80::1]:443":            false,
		"[::ffff:192.168.0.1]:443": false,
		"224.0.0.1:443":            false,
	} {
		err := checkPublic(addr)
		if (err == nil) != ok {
			t.Errorf("checkPublic(%s) = %v, want ok=%v", addr, err, ok)
		}
	}
}

// The guard is on the dial, so it holds whatever the URL said.
func TestPublicClientRefusesLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("PublicClient reached a loopback server")
	}))
	defer srv.Close()
	_, err := PublicClient().Get(srv.URL)
	if !errors.Is(err, errNotPublic) {
		t.Fatalf("Get(%s) err = %v, want errNotPublic", srv.URL, err)
	}
}
