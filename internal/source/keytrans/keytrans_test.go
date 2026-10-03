package keytrans

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// Fixtures are real exchanges recorded from the keytrans reference log by its
// cmd/keytrans-fixtures, so this package is tested against the implementation
// it witnesses without depending on it.
type fixture struct {
	Configuration string `json:"configuration"`
	Exchanges     []struct {
		Log      string  `json:"log"`
		Note     string  `json:"note"`
		Last     *uint64 `json:"last"`
		Size     uint64  `json:"size"`
		Request  string  `json:"request"`
		Response string  `json:"response"`
	} `json:"exchanges"`
}

func loadFixture(t *testing.T, mode string) *fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/keytrans-" + mode + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// fakeLog answers recorded requests for whichever log is selected. A request
// that was never recorded is a 404, so the adapter's request encoding is
// checked against the reference implementation's byte for byte.
type fakeLog struct {
	mu     sync.Mutex
	f      *fixture
	log    string
	mutate func([]byte) []byte
	served int
	// latest serves the last recording of a request rather than the first.
	// Two first-observation requests are byte-identical, so this picks
	// between the one at the log's start and the one at its end.
	latest bool
}

func (l *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.URL.Path != "/v1/distinguished" {
		http.NotFound(w, r)
		return
	}
	var match string
	for _, e := range l.f.Exchanges {
		if e.Log == l.log && e.Request == hex.EncodeToString(body) && (match == "" || l.latest) {
			match = e.Response
		}
	}
	if match != "" {
		resp, _ := hex.DecodeString(match)
		if l.mutate != nil {
			resp = l.mutate(resp)
		}
		l.served = len(resp)
		w.Write(resp)
		return
	}
	http.Error(w, "no recorded exchange for "+hex.EncodeToString(body), http.StatusNotFound)
}

type memState struct{ m map[string][]byte }

func (s *memState) SourceState(o string) ([]byte, error)    { return s.m[o], nil }
func (s *memState) PutSourceState(o string, b []byte) error { s.m[o] = b; return nil }

func newSource(t *testing.T, f *fixture, url string, st source.StateStore) *Source {
	t.Helper()
	s, err := New(Config{Endpoint: url, Configuration: f.Configuration, State: st})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// round does what the witness core does: fetch against prev, then check
// consistency, which retains the new view.
func round(t *testing.T, s *Source, prev *source.Head) (*source.Head, error) {
	t.Helper()
	ctx := context.Background()
	next, err := s.Fetch(ctx, prev)
	if err != nil {
		return nil, err
	}
	if err := s.VerifyConsistency(ctx, prev, next); err != nil {
		return nil, err
	}
	return next, nil
}

func TestWitnessesRecordedLog(t *testing.T) {
	for _, mode := range []string{"auditing", "contact"} {
		t.Run(mode, func(t *testing.T) {
			f := loadFixture(t, mode)
			fake := &fakeLog{f: f, log: "main"}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			st := &memState{m: map[string][]byte{}}
			s := newSource(t, f, srv.URL, st)

			var prev *source.Head
			for _, want := range []int64{1, 5, 15} {
				next, err := round(t, s, prev)
				if err != nil {
					t.Fatalf("size %d: %v", want, err)
				}
				if next.Size != want {
					t.Fatalf("got size %d, want %d", next.Size, want)
				}
				if !strings.HasPrefix(next.Origin, OriginPrefix) || !strings.HasPrefix(string(next.Signed), next.Origin+"\n") {
					t.Fatalf("checkpoint %q", next.Signed)
				}
				if mode == "auditing" && len(next.Cosigners) != 1 {
					t.Fatalf("auditor not recorded as cosigner: %v", next.Cosigners)
				}
				prev = next
			}

			// Unchanged log: the same head again.
			same, err := round(t, s, prev)
			if err != nil {
				t.Fatalf("unchanged head: %v", err)
			}
			if same.Size != prev.Size || same.Hash != prev.Hash {
				t.Fatal("unchanged head differs")
			}

			// A restart keeps the retained view, so the witness continues.
			s2 := newSource(t, f, srv.URL, st)
			if _, err := round(t, s2, prev); err != nil {
				t.Fatalf("after restart: %v", err)
			}
			// Without it, the witness withholds rather than guessing.
			s3 := newSource(t, f, srv.URL, &memState{m: map[string][]byte{}})
			if _, err := s3.Fetch(context.Background(), prev); err == nil {
				t.Fatal("proved consistency with no retained view")
			}
			// A fresh observation verifies on its own.
			fake.latest = true
			fresh, err := round(t, s3, nil)
			if err != nil || fresh.Hash != prev.Hash {
				t.Fatalf("fresh observation: %v", err)
			}
		})
	}
}

// A log that keeps its keys but rewrites history after genesis cannot extend
// what the witness saw.
func TestForkRejected(t *testing.T) {
	for _, mode := range []string{"auditing", "contact"} {
		t.Run(mode, func(t *testing.T) {
			f := loadFixture(t, mode)
			fake := &fakeLog{f: f, log: "main"}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			s := newSource(t, f, srv.URL, &memState{m: map[string][]byte{}})
			h1, err := round(t, s, nil)
			if err != nil {
				t.Fatal(err)
			}
			h5, err := round(t, s, h1)
			if err != nil {
				t.Fatal(err)
			}
			fake.mu.Lock()
			fake.log = "fork"
			fake.mu.Unlock()
			if next, err := s.Fetch(context.Background(), h5); err == nil {
				t.Fatalf("forked head at size %d accepted", next.Size)
			}
		})
	}
}

// Every byte of a response is bound by a signature, a hash, or the strict
// shape check: corrupting any one must fail verification.
func TestEveryByteIsBound(t *testing.T) {
	for _, mode := range []string{"auditing", "contact"} {
		t.Run(mode, func(t *testing.T) {
			f := loadFixture(t, mode)
			fake := &fakeLog{f: f, log: "main"}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			setup := func() (*Source, *source.Head) {
				fake.mutate = nil
				s := newSource(t, f, srv.URL, &memState{m: map[string][]byte{}})
				h1, err := round(t, s, nil)
				if err != nil {
					t.Fatal(err)
				}
				h5, err := round(t, s, h1)
				if err != nil {
					t.Fatal(err)
				}
				return s, h5
			}
			checked := 0
			for off := 0; ; off++ {
				s, prev := setup()
				o := off
				hit := false
				fake.mutate = func(b []byte) []byte {
					if o >= len(b) {
						return b
					}
					hit = true
					b = append([]byte(nil), b...)
					b[o] ^= 1
					return b
				}
				_, err := s.Fetch(context.Background(), prev)
				if !hit {
					break
				}
				if err == nil {
					t.Fatalf("flipping byte %d of %d went undetected", off, fake.served)
				}
				checked++
			}
			if checked < 100 {
				t.Fatalf("only %d bytes exercised", checked)
			}
			t.Logf("%d corrupted responses rejected", checked)
		})
	}
}

func TestConfigurationPinsOrigin(t *testing.T) {
	f := loadFixture(t, "auditing")
	if _, err := New(Config{Endpoint: "http://x", Configuration: f.Configuration, Origin: "signal.org/kt"}); err == nil {
		t.Fatal("origin not derived from configuration accepted")
	}
	raw, _ := hex.DecodeString(f.Configuration)
	s, err := New(Config{Endpoint: "http://x", Configuration: f.Configuration, Origin: OriginFor(raw)})
	if err != nil || s.Origin() != OriginFor(raw) {
		t.Fatalf("derived origin: %v", err)
	}
}

// The implicit-tree arithmetic matches the draft's examples.
func TestImplicitTree(t *testing.T) {
	if ibstRoot(50) != 31 {
		t.Fatal(ibstRoot(50))
	}
	got := frontier(50)
	if len(got) != 3 || got[0] != 31 || got[1] != 47 || got[2] != 49 {
		t.Fatal(got)
	}
	if v := updateView(5, 14); len(v) != 4 || v[0] != 5 || v[1] != 7 || v[2] != 11 || v[3] != 13 {
		t.Fatal(v)
	}
}
