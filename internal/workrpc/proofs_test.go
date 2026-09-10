package workrpc

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// A canary a worker can recognise is not a test.
//
// The first version of this served only corrupted proofs, and pointed workers
// at them with a field ordinary assignments left empty. A worker wanting to
// cheat had merely to refuse anything arriving from the witness: perfect score
// on every test, verifying nothing, and a record that read as evidence of
// diligence. These tests pin the property that fixes it — that nothing about a
// canary distinguishes it from ordinary work except the bytes themselves.

func testServer(t *testing.T, body []byte, every int) *ProofServer {
	t.Helper()
	fetch := func(origin string, epoch int64) (io.ReadCloser, int64, error) {
		return io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
	}
	p, _, err := NewProofServer("127.0.0.1:0", nil, fetch, every)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The response for a canary and for ordinary work must be identical in
// everything a worker can see except the bytes: same status, same length, same
// headers, same path shape.
func TestACanaryLooksExactlyLikeOrdinaryWork(t *testing.T) {
	body := bytes.Repeat([]byte("proof"), 1000)
	// Every request is a canary, so the two runs differ only in that.
	always := testServer(t, body, 1)
	never := testServer(t, body, 1_000_000)

	var canaryResp, plainResp struct {
		status int
		length string
		ctype  string
		body   []byte
	}
	for _, c := range []struct {
		p    *ProofServer
		into *struct {
			status int
			length string
			ctype  string
			body   []byte
		}
	}{{always, &canaryResp}, {never, &plainResp}} {
		rec := &recorder{header: http.Header{}}
		req, _ := http.NewRequest(http.MethodGet, "/proof/whatsapp.kt/v2/1000", nil)
		c.p.serve(rec, req)
		c.into.status = rec.code
		c.into.length = rec.header.Get("Content-Length")
		c.into.ctype = rec.header.Get("Content-Type")
		c.into.body = rec.buf.Bytes()
	}

	if canaryResp.status != plainResp.status {
		t.Errorf("status differs: canary %d, ordinary %d", canaryResp.status, plainResp.status)
	}
	if canaryResp.length != plainResp.length {
		t.Errorf("Content-Length differs: canary %q, ordinary %q — a worker could filter on it",
			canaryResp.length, plainResp.length)
	}
	if canaryResp.ctype != plainResp.ctype {
		t.Errorf("Content-Type differs: canary %q, ordinary %q", canaryResp.ctype, plainResp.ctype)
	}
	if len(canaryResp.body) != len(plainResp.body) {
		t.Errorf("body length differs: canary %d, ordinary %d", len(canaryResp.body), len(plainResp.body))
	}
	if bytes.Equal(canaryResp.body, plainResp.body) {
		t.Error("the canary was not corrupted at all")
	}
}

// Exactly one bit, so the corruption is the kind a verifier that skips a hash
// would miss — not a mangled file that any structural check catches.
func TestExactlyOneBitIsFlipped(t *testing.T) {
	body := bytes.Repeat([]byte{0x5a}, 4096)
	p := testServer(t, body, 1)
	rec := &recorder{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodGet, "/proof/m/kt/7", nil)
	p.serve(rec, req)

	got := rec.buf.Bytes()
	if len(got) != len(body) {
		t.Fatalf("served %d bytes, want %d", len(got), len(body))
	}
	diff := 0
	for i := range got {
		d := got[i] ^ body[i]
		for ; d != 0; d &= d - 1 {
			diff++
		}
	}
	if diff != 1 {
		t.Errorf("%d bits differ, want exactly 1", diff)
	}
}

// The witness has to remember which epochs it corrupted, and only once: a
// second answer for the same epoch is not a canary verdict, and treating it as
// one would let a worker be accused twice for a single test.
func TestACanaryIsRememberedExactlyOnce(t *testing.T) {
	body := []byte("proof")
	p := testServer(t, body, 1)
	rec := &recorder{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodGet, "/proof/m/kt/42", nil)
	p.serve(rec, req)

	if !p.WasCanary("m/kt", 42) {
		t.Fatal("the corrupted epoch was not recorded")
	}
	if p.WasCanary("m/kt", 42) {
		t.Error("the same canary was reported twice")
	}
	if p.WasCanary("m/kt", 43) {
		t.Error("an epoch that was never corrupted was reported as a canary")
	}
}

// A path that does not name an origin and an epoch gets the same answer as a
// proof that is not there — a worker learns that it cannot have the proof, not
// why.
func TestMalformedPathsAreNotFound(t *testing.T) {
	p := testServer(t, []byte("x"), 1_000_000)
	for _, path := range []string{"/proof/", "/proof/noepoch", "/proof/m/kt/notanumber"} {
		rec := &recorder{header: http.Header{}}
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		p.serve(rec, req)
		if rec.code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, rec.code)
		}
	}
}

// copyFlipping streams, so it must land the flip in the right place regardless
// of where the read boundaries fall.
func TestFlipLandsAtTheRightOffsetAcrossReads(t *testing.T) {
	for _, offset := range []int64{0, 1, 1 << 20, (1 << 20) + 5, 3 << 20} {
		src := bytes.Repeat([]byte{0}, 4<<20)
		var out bytes.Buffer
		if err := copyFlipping(&out, oneByteAtATime(src), offset, 0x80); err != nil {
			t.Fatal(err)
		}
		got := out.Bytes()
		if len(got) != len(src) {
			t.Fatalf("offset %d: %d bytes out, want %d", offset, len(got), len(src))
		}
		for i, b := range got {
			want := byte(0)
			if int64(i) == offset {
				want = 0x80
			}
			if b != want {
				t.Fatalf("offset %d: byte %d is %#x, want %#x", offset, i, b, want)
			}
		}
	}
}

// oneByteAtATime forces the copy to cross buffer boundaries in awkward places.
func oneByteAtATime(b []byte) io.Reader { return &dribble{b: b} }

type dribble struct {
	b []byte
	i int
}

func (d *dribble) Read(p []byte) (int, error) {
	if d.i >= len(d.b) {
		return 0, io.EOF
	}
	n := 7
	if d.i+n > len(d.b) {
		n = len(d.b) - d.i
	}
	copy(p, d.b[d.i:d.i+n])
	d.i += n
	return n, nil
}

// recorder is a minimal ResponseWriter; httptest would pull in a dependency
// this package does not otherwise need.
type recorder struct {
	code   int
	header http.Header
	buf    bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.buf.Write(b)
}
func (r *recorder) WriteHeader(c int) { r.code = c }
