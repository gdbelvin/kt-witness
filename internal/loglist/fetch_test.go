package loglist

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

// listServer serves whatever body is currently set.
type listServer struct {
	mu     sync.Mutex
	body   string
	status int
}

func (s *listServer) set(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *listServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.WriteHeader(s.status)
	io.WriteString(w, s.body)
}

func entry(vkey string, qpd int64, contact string) string {
	return fmt.Sprintf("vkey %s\nqpd %d\ncontact %s\n", vkey, qpd, contact)
}

type fixture struct {
	srv   *httptest.Server
	ls    *listServer
	db    *store.Store
	reg   *Registry
	f     *Fetcher
	path  string
	stat  *push.Log
	stat2 string // a different key for the static origin, as a list might offer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{ls: &listServer{status: http.StatusOK}}
	fx.srv = httptest.NewServer(fx.ls)
	t.Cleanup(fx.srv.Close)

	fx.path = filepath.Join(t.TempDir(), "t.db")
	db, err := store.Open(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fx.db.Close() })
	fx.db = db

	staticKey := testVKey(t, "static.example/log")
	v, err := note.NewVerifier(staticKey)
	if err != nil {
		t.Fatal(err)
	}
	fx.stat = &push.Log{Origin: "static.example/log", VKey: staticKey, Verifier: v}
	fx.stat2 = testVKey(t, "static.example/log")
	fx.reg = NewRegistry([]*push.Log{fx.stat})
	fx.f = &Fetcher{
		URLs: []string{fx.srv.URL}, Store: db, Registry: fx.reg,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return fx
}

// The network's central rule: a changed list must not remove or update a log
// we already have. Revision 2 re-keys A, drops B, re-offers a static origin
// with a different key, and adds C. Only C may change anything.
func TestFetchIsAddOnly(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()

	a1 := testVKey(t, "a.example/log")
	a2 := testVKey(t, "a.example/log")
	b := testVKey(t, "b.example/log")
	c := testVKey(t, "c.example/log")

	fx.ls.set(http.StatusOK, "logs/v0\n"+
		entry(a1, 24, "a-ops")+
		entry(b, 48, "b-ops")+
		entry(fx.stat2, 1, "list-says-static"))
	if err := fx.f.FetchOnce(ctx); err != nil {
		t.Fatal(err)
	}

	st := fx.f.Status()
	if len(st) != 1 || st[0].LastFetch.IsZero() || st[0].LastErr != "" || st[0].Logs != 3 || st[0].Added != 2 {
		t.Fatalf("status after rev 1: %+v", st)
	}

	fx.ls.set(http.StatusOK, "logs/v0\n"+
		entry(a2, 86400, "new-a-ops")+
		entry(c, 96, "c-ops")+
		entry(fx.stat2, 1, "list-says-static"))
	if err := fx.f.FetchOnce(ctx); err != nil {
		t.Fatal(err)
	}

	check := func(reg *Registry, db *store.Store) {
		t.Helper()
		for _, want := range []struct {
			origin, vkey, contact, from string
			qpd                         int64
		}{
			{"a.example/log", a1, "a-ops", fx.srv.URL, 24},
			{"b.example/log", b, "b-ops", fx.srv.URL, 48},
			{"c.example/log", c, "c-ops", fx.srv.URL, 96},
			{"static.example/log", fx.stat.VKey, "", FromConfig, 0},
		} {
			l, ok := reg.Lookup(want.origin)
			if !ok {
				t.Errorf("%s: missing from registry", want.origin)
				continue
			}
			if l.VKey != want.vkey || l.Contact != want.contact || l.QPD != want.qpd || l.From != want.from {
				t.Errorf("%s: registry has %+v, want %+v", want.origin, l, want)
			}
			if l.Verifier == nil || l.Verifier.Name() != strings.SplitN(want.vkey, "+", 2)[0] {
				t.Errorf("%s: bad verifier", want.origin)
			}
		}
		stored, err := db.PushLogs()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]*store.PushLog{}
		for _, pl := range stored {
			got[pl.Origin] = pl
		}
		if len(got) != 3 {
			t.Errorf("store has %d logs, want 3 (static must not be stored)", len(got))
		}
		if got["a.example/log"] == nil || got["a.example/log"].VKey != a1 || got["a.example/log"].QPD != 24 {
			t.Errorf("stored a: %+v", got["a.example/log"])
		}
		if got["b.example/log"] == nil || got["b.example/log"].VKey != b {
			t.Errorf("stored b: %+v", got["b.example/log"])
		}
		if got["c.example/log"] == nil || got["c.example/log"].VKey != c {
			t.Errorf("stored c: %+v", got["c.example/log"])
		}
		if len(reg.Logs()) != 4 || strings.Join(reg.Origins(), ",") != "a.example/log,b.example/log,c.example/log,static.example/log" {
			t.Errorf("origins: %v", reg.Origins())
		}
	}
	check(fx.reg, fx.db)
	if st := fx.f.Status(); st[0].Added != 3 {
		t.Errorf("added = %d, want 3", st[0].Added)
	}

	// After a restart, the first-seen keys come back from the store, and a
	// list still offering a2 does not displace a1.
	fx.db.Close()
	db, err := store.Open(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	fx.db = db
	reg := NewRegistry([]*push.Log{fx.stat})
	if err := reg.Load(db); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{URLs: []string{fx.srv.URL}, Store: db, Registry: reg, Log: fx.f.Log}
	if err := f.FetchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	check(reg, db)
}

// A malformed list, a non-200, or an oversized body is rejected whole and
// changes nothing; the status page shows the failure without losing the time
// of the last good fetch.
func TestFetchRejectsBadListsKeepingState(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	a := testVKey(t, "a.example/log")
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(a, 24, "a"))
	if err := fx.f.FetchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	good := fx.f.Status()[0].LastFetch

	d := testVKey(t, "d.example/log")
	for name, set := range map[string]func(){
		"bad entry after good one": func() {
			fx.ls.set(http.StatusOK, "logs/v0\n"+entry(d, 24, "d")+"vkey "+testVKey(t, "e.example")+"\nqpd 0\ncontact e\n")
		},
		"http 404":  func() { fx.ls.set(http.StatusNotFound, "logs/v0\n"+entry(d, 24, "d")) },
		"http 500":  func() { fx.ls.set(http.StatusInternalServerError, "") },
		"no header": func() { fx.ls.set(http.StatusOK, entry(d, 24, "d")) },
		"oversized": func() {
			fx.ls.set(http.StatusOK, "logs/v0\n"+entry(d, 24, "d")+strings.Repeat("#\n", 1024))
			fx.f.MaxBytes = 512
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx.f.MaxBytes = 0
			set()
			if err := fx.f.FetchOnce(ctx); err == nil {
				t.Fatal("accepted")
			}
			if _, ok := fx.reg.Lookup("d.example/log"); ok {
				t.Fatal("rejected list still added a log")
			}
			st := fx.f.Status()[0]
			if st.LastErr == "" || !st.LastFetch.Equal(good) || st.LastAttempt.Before(good) {
				t.Fatalf("status: %+v", st)
			}
			if logs, _ := fx.db.PushLogs(); len(logs) != 1 {
				t.Fatalf("store has %d logs", len(logs))
			}
		})
	}

	// And recovery clears the error.
	fx.f.MaxBytes = 0
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(a, 24, "a")+entry(d, 24, "d"))
	if err := fx.f.FetchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st := fx.f.Status()[0]; st.LastErr != "" || st.LastFetch.Before(good) {
		t.Fatalf("status after recovery: %+v", st)
	}
	if _, ok := fx.reg.Lookup("d.example/log"); !ok {
		t.Fatal("d not added after recovery")
	}
}

// A key we cannot build a verifier for (ML-DSA-44, today) is skipped, and
// recorded nowhere, without costing the rest of the list.
func TestFetchSkipsUnverifiableKeys(t *testing.T) {
	fx := newFixture(t)
	a := testVKey(t, "a.example/log")
	pq := mldsaVKey(t, "pq.example/log")
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(pq, 24, "pq")+entry(a, 24, "a"))
	if err := fx.f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := fx.reg.Lookup("pq.example/log"); ok {
		t.Fatal("unverifiable log was registered")
	}
	if _, ok := fx.reg.Lookup("a.example/log"); !ok {
		t.Fatal("verifiable log was not registered")
	}
	logs, _ := fx.db.PushLogs()
	if len(logs) != 1 || logs[0].Origin != "a.example/log" {
		t.Fatalf("store: %+v", logs)
	}
	if st := fx.f.Status()[0]; st.LastErr != "" || st.Logs != 2 || st.Added != 1 {
		t.Fatalf("status: %+v", st)
	}
}

// Two lists offering the same origin with different keys: whichever is fetched
// first introduces it, and the other is a no-op, as the real lists overlap.
func TestFetchOverlappingLists(t *testing.T) {
	fx := newFixture(t)
	second := &listServer{status: http.StatusOK}
	srv2 := httptest.NewServer(second)
	defer srv2.Close()
	fx.f.URLs = append(fx.f.URLs, srv2.URL)

	k1 := testVKey(t, "shared.example/log")
	k2 := testVKey(t, "shared.example/log")
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(k1, 24, "one"))
	second.set(http.StatusOK, "logs/v0\n"+entry(k2, 48, "two"))
	if err := fx.f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	l, ok := fx.reg.Lookup("shared.example/log")
	if !ok || l.VKey != k1 || l.From != fx.srv.URL {
		t.Fatalf("got %+v", l)
	}
	st := fx.f.Status()
	if len(st) != 2 || st[0].Added != 1 || st[1].Added != 0 || st[1].LastFetch.IsZero() {
		t.Fatalf("status: %+v", st)
	}
}

// Which lists name an origin is recorded for every entry — including a
// statically configured origin and one already introduced by another list —
// but only as an index: the key in force does not move.
func TestListsForRecordsEveryMentionWithoutRekeying(t *testing.T) {
	fx := newFixture(t)
	second := &listServer{status: http.StatusOK}
	srv2 := httptest.NewServer(second)
	defer srv2.Close()
	fx.f.URLs = append(fx.f.URLs, srv2.URL)

	k1 := testVKey(t, "shared.example/log")
	k2 := testVKey(t, "shared.example/log")
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(k1, 24, "one")+entry(fx.stat2, 1, "static"))
	second.set(http.StatusOK, "logs/v0\n"+entry(k2, 48, "two"))
	for i := 0; i < 2; i++ { // twice: mentions must not duplicate
		if err := fx.f.FetchOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := fx.reg.ListsFor("shared.example/log"); len(got) != 2 || got[0] != fx.srv.URL || got[1] != srv2.URL {
		t.Errorf("shared: ListsFor = %v", got)
	}
	if got := fx.reg.ListsFor("static.example/log"); len(got) != 1 || got[0] != fx.srv.URL {
		t.Errorf("static: ListsFor = %v", got)
	}
	if l, _ := fx.reg.Lookup("shared.example/log"); l.VKey != k1 {
		t.Error("a second mention re-keyed the log")
	}
	if l, _ := fx.reg.Lookup("static.example/log"); l.VKey != fx.stat.VKey {
		t.Error("a mention re-keyed the static log")
	}
	if got := fx.reg.ListsFor("nobody.example/log"); got != nil {
		t.Errorf("unlisted origin: %v", got)
	}

	// After a restart the discovering list is known from the store alone.
	reg := NewRegistry(nil)
	if err := reg.Load(fx.db); err != nil {
		t.Fatal(err)
	}
	if got := reg.ListsFor("shared.example/log"); len(got) != 1 || got[0] != fx.srv.URL {
		t.Errorf("after Load: ListsFor = %v", got)
	}
}

// Real published lists end to end, including the overlap between them.
func TestFetchRealLists(t *testing.T) {
	fx := newFixture(t)
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("testdata")))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	fx.f.URLs = []string{
		srv.URL + "/testing-log-list.1",
		srv.URL + "/staging-log-list-10qps-4klogs.1",
		srv.URL + "/staging-log-list-100qps-40klogs.1",
	}
	if err := fx.f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	logs, _ := fx.db.PushLogs()
	// 9 + 12 + 13, less the one sigsum log listed in both testing and 10qps.
	if len(logs) != 33 {
		t.Fatalf("stored %d logs, want 33", len(logs))
	}
	if len(fx.reg.Logs()) != 34 { // plus the static one
		t.Fatalf("registry has %d logs", len(fx.reg.Logs()))
	}
}

func TestIntervalClamp(t *testing.T) {
	f := &Fetcher{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for in, want := range map[time.Duration]time.Duration{
		0:                   DefaultInterval,
		-time.Hour:          DefaultInterval,
		time.Hour:           time.Hour,
		MaxInterval:         MaxInterval,
		MaxInterval + 1:     MaxInterval,
		30 * 24 * time.Hour: MaxInterval,
	} {
		f.Interval = in
		if got := f.interval(); got != want {
			t.Errorf("interval(%v) = %v, want %v", in, got, want)
		}
	}
}

// Run loads stored logs before its first fetch, fetches immediately, and stops
// with its context.
func TestRunLoadsThenFetches(t *testing.T) {
	fx := newFixture(t)
	old := testVKey(t, "old.example/log")
	if _, err := fx.db.AddPushLog(&store.PushLog{Origin: "old.example/log", VKey: old, QPD: 1, List: "earlier"}); err != nil {
		t.Fatal(err)
	}
	a := testVKey(t, "a.example/log")
	fx.ls.set(http.StatusOK, "logs/v0\n"+entry(a, 24, "a")+entry(testVKey(t, "old.example/log"), 5, "x"))
	fx.f.Interval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fx.f.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for fx.f.Status()[0].LastFetch.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no fetch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if l, ok := fx.reg.Lookup("old.example/log"); !ok || l.VKey != old || l.From != "earlier" {
		t.Fatalf("stored log: %+v", l)
	}
	if _, ok := fx.reg.Lookup("a.example/log"); !ok {
		t.Fatal("new log missing")
	}
}
