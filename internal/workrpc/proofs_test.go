package workrpc

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
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
	// Open by default, so the tests that are about corruption are not also
	// about authorisation. The tests below that ARE about authorisation set
	// MayRead themselves.
	p.MayRead = func(string, string, int64) bool { return true }
	return p
}

// get issues a request as one session and returns the recorder.
func get(t *testing.T, p *ProofServer, session, origin string, epoch int64) *recorder {
	t.Helper()
	rec := &recorder{header: http.Header{}}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/proof/%s/%s/%d", session, origin, epoch), nil)
	p.serve(rec, req)
	return rec
}

// THE bypass, and the check that closes it.
//
// The published roots chain — curr_E equals prev_{E+1}, which this witness
// enforces as a fork condition — and prev is by definition Root(unchanged). So
// a worker able to read epoch E+1 can answer for epoch E without applying the
// commitment or building the merged tree: report Root(unchanged_E) and
// Root(unchanged_{E+1}), both matching the published values, having never
// checked the append-only property at all.
//
// Both numbers are public and derivable two ways, so no different question
// closes it. Denying the second proof does.
func TestAWorkerCannotReadTheNeighbouringEpoch(t *testing.T) {
	p := testServer(t, []byte("proof"), 1_000_000)

	// This session holds epoch 100 and nothing else.
	p.MayRead = func(worker, origin string, epoch int64) bool {
		return worker == "laptop" && origin == "m/kt" && epoch == 100
	}
	session, err := p.Session("laptop")
	if err != nil {
		t.Fatal(err)
	}

	if rec := get(t, p, session, "m/kt", 100); rec.code != http.StatusOK {
		t.Fatalf("the assigned epoch was refused: %d", rec.code)
	}
	for _, epoch := range []int64{101, 99} {
		if rec := get(t, p, session, "m/kt", epoch); rec.code != http.StatusNotFound {
			t.Errorf("epoch %d was served to a worker that does not hold it (%d) — "+
				"the append-only check can be skipped", epoch, rec.code)
		}
	}
}

// A caller without a valid session gets nothing, and learns nothing.
func TestAnUnknownSessionIsRefused(t *testing.T) {
	p := testServer(t, []byte("proof"), 1_000_000)
	p.MayRead = func(string, string, int64) bool { return true }

	if rec := get(t, p, "not-a-real-token", "m/kt", 100); rec.code != http.StatusNotFound {
		t.Errorf("an unknown session was served: %d", rec.code)
	}
	// And the refusal is the same answer as a proof that is not there, so a
	// caller cannot use the status to probe which epochs exist.
	session, _ := p.Session("laptop")
	p.MayRead = func(string, string, int64) bool { return false }
	if rec := get(t, p, session, "m/kt", 100); rec.code != http.StatusNotFound {
		t.Errorf("a refused read answered %d, not 404 — the two must be indistinguishable", rec.code)
	}
}

// A session dies with its stream; a disconnected worker stops being able to
// read, rather than holding a key to the proof store indefinitely.
func TestASessionStopsWorkingWhenItEnds(t *testing.T) {
	p := testServer(t, []byte("proof"), 1_000_000)
	session, _ := p.Session("laptop")
	if rec := get(t, p, session, "m/kt", 1); rec.code != http.StatusOK {
		t.Fatalf("a live session was refused: %d", rec.code)
	}
	p.EndSession(session)
	if rec := get(t, p, session, "m/kt", 1); rec.code != http.StatusNotFound {
		t.Errorf("an ended session still reads proofs: %d", rec.code)
	}
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
		sess, _ := c.p.Session("laptop")
		rec := &recorder{header: http.Header{}}
		req, _ := http.NewRequest(http.MethodGet, "/proof/"+sess+"/whatsapp.kt/v2/1000", nil)
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
	sess, _ := p.Session("laptop")
	rec := get(t, p, sess, "m/kt", 7)

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
	sess, _ := p.Session("laptop")
	get(t, p, sess, "m/kt", 42)

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
	sess, _ := p.Session("laptop")
	for _, path := range []string{"/proof/", "/proof/" + sess, "/proof/" + sess + "/noepoch", "/proof/" + sess + "/m/kt/notanumber"} {
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
	// Bounded by the caller's buffer as well as by what is left.
	//
	// Returning a fixed 7 regardless of len(p) violates io.Reader, and the
	// caller that notices is io.ReadAll: it reads into b[len(b):cap(b)], which
	// is short when its buffer is nearly full, then does b = b[:len(b)+n] with
	// the n it was handed and panics on the slice bounds. Whether that happens
	// depends on the growth sequence for a particular length, so this passed on
	// Go 1.27 and panicked on the 1.25 in go.mod — a reader whose contract is
	// wrong only sometimes, which is the kind CI is for.
	n := min(7, len(p), len(d.b)-d.i)
	copy(p, d.b[d.i:d.i+n])
	d.i += n
	return n, nil
}

// The dribble reader is itself worth one assertion, because the way it was
// wrong was invisible on the developer's Go version and only appeared on the
// one go.mod pins. A helper that lies about how much it read makes every test
// using it meaningless in a way that looks like a bug in the code under test.
func TestDribbleHonoursTheBufferItIsGiven(t *testing.T) {
	d := &dribble{b: make([]byte, 100)}
	small := make([]byte, 3)
	n, err := d.Read(small)
	if err != nil {
		t.Fatal(err)
	}
	if n > len(small) {
		t.Fatalf("Read returned %d for a %d-byte buffer; io.Reader forbids n > len(p)", n, len(small))
	}
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

// A canary is only a test of the append-only check if it corrupts the bytes
// that check reads.
//
// The bypass the tests above close by denying the second proof has a second
// door. curr_E equals prev_{E+1}, and prev is Root(unchanged), so a worker that
// does get hold of proof E+1 can answer for epoch E out of the two unchanged
// sets and never read inserted_E. Both roots correct, the append-only property
// never checked — and a canary bit chosen uniformly over the file lands in
// `unchanged`, which that worker does read, roughly nine times in ten. It
// would notice the corruption, report a mismatch, and be recorded as diligent.
//
// So the flip is aimed. These tests pin the aim rather than the intention.
func TestACanaryAimsAtTheInsertedSet(t *testing.T) {
	wire, err := os.ReadFile("../audit/testdata/proof.bin")
	if err != nil {
		t.Fatal(err)
	}
	ins, err := akdtree.FieldRanges(wire, insertedField)
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != 1 {
		t.Fatalf("the fixture has %d `inserted` ranges, want 1", len(ins))
	}
	uniform := float64(ins[0].End-ins[0].Start) / float64(len(wire))

	// Which bytes of `inserted` a verifier actually hashes. The aimed
	// three-quarters must land only in these; the uniform quarter may land
	// anywhere, framing included.
	payload := map[int]bool{}
	_, total, _, err := akdtree.PayloadOffset(wire, insertedField, -1)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < total; n++ {
		off, _, found, err := akdtree.PayloadOffset(wire, insertedField, n)
		if err != nil || !found {
			t.Fatalf("locating payload byte %d: found=%v err=%v", n, found, err)
		}
		payload[off] = true
	}

	p := testServer(t, wire, 1) // every proof is a canary
	var logs bytes.Buffer
	p.Log = slog.New(slog.NewTextHandler(&logs, nil))
	sess, _ := p.Session("laptop")

	const draws = 240
	inside, framing := 0, 0
	for i := 0; i < draws; i++ {
		logs.Reset()
		got := get(t, p, sess, "m/kt", int64(i)).buf.Bytes()
		if len(got) != len(wire) {
			t.Fatalf("draw %d: served %d bytes, want %d", i, len(got), len(wire))
		}
		at, bits := -1, 0
		for j := range got {
			d := got[j] ^ wire[j]
			if d == 0 {
				continue
			}
			at = j
			for ; d != 0; d &= d - 1 {
				bits++
			}
		}
		if at < 0 || bits != 1 {
			t.Fatalf("draw %d: %d bits flipped at byte %d, want exactly 1", i, bits, at)
		}

		hit := at >= ins[0].Start && at < ins[0].End
		// The log line has to name the region correctly, because it is the only
		// thing that tells an operator which of the two failures a worker just
		// walked into: a canary in `inserted` that comes back verified means the
		// append-only check was skipped, one in `unchanged` means the proof was
		// not read at all.
		want := "region=unchanged"
		if hit {
			want = "region=inserted"
		}
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("draw %d: byte %d is in %s but the log says otherwise: %s",
				i, at, map[bool]string{true: "`inserted`", false: "`unchanged`"}[hit], logs.String())
		}
		if !strings.Contains(logs.String(), "inserted=") {
			t.Errorf("draw %d: the canary log does not report the size of the inserted "+
				"span, which is the only place this is ever measured: %s", i, logs.String())
		}
		if !hit {
			continue
		}
		inside++
		if !payload[at] {
			// Framing rather than payload, which only the uniform quarter can
			// reach. It is a weaker canary — a corrupted length desynchronises
			// every element after it, so the proof stops decoding, and "this
			// does not parse" is the verdict an honest verifier gives too. Not
			// an error, but counted, because if the aim ever regressed to
			// uniform this is the count that would move first.
			framing++
			continue
		}
		// A payload flip changes no length, so the proof still decodes in full
		// and only the roots move. That is the answer a worker which skipped the
		// append-only check cannot produce.
		if _, _, err := akdtree.Decode(got); err != nil {
			t.Fatalf("draw %d: a payload flip at byte %d broke the framing: %v", i, at, err)
		}
	}

	// Three in four by construction, plus whatever the uniform quarter happens
	// to contribute. The bounds are wide because this is a real coin: at 240
	// draws the standard deviation is about 6.4, so 140 and 230 are far enough
	// out to be a broken aim rather than a bad afternoon.
	if inside < 140 || inside > 230 {
		t.Errorf("%d of %d canaries landed in `inserted`; want roughly 187 (three quarters "+
			"aimed, plus %.1f%% of the uniform quarter)", inside, draws, 100*uniform)
	}
	if outside := draws - inside; outside < 10 {
		t.Errorf("only %d of %d canaries landed outside `inserted`; some must, or a worker "+
			"can verify the first few megabytes and echo the published roots for the rest",
			outside, draws)
	}
	// Of the flips inside `inserted`, the aimed ones are always on payload;
	// only the uniform quarter can hit framing, and only 14.7% of `inserted` is
	// framing, so the expected count here is about one in 240 draws. A dozen
	// would mean the aim had quietly stopped aiming.
	if framing > 12 {
		t.Errorf("%d of %d canaries hit framing inside `inserted`; the aimed share is "+
			"supposed to choose payload bytes only", framing, draws)
	}
	t.Logf("%d of %d canaries in `inserted` (%.1f%%), %d of those on framing; uniform "+
		"choice would have managed %.1f%%",
		inside, draws, 100*float64(inside)/draws, framing, 100*uniform)
}

// A body that is not a proof at all must still be served, whole and with one
// bit flipped. The framing scan reads it before anything goes out, so a scan
// that gave up mid-stream and dropped what it had read would silently truncate
// every proof the operator's encoder ever changes.
func TestABodyThatIsNotAProofIsStillServedWhole(t *testing.T) {
	for _, body := range [][]byte{
		[]byte("proof"),                     // gives up on the first tag
		bytes.Repeat([]byte{0x5a}, 4096),    // frames, but as some other message
		bytes.Repeat([]byte{0x0a, 0x00}, 8), // field 1, empty elements, no payload
		nil,
	} {
		p := testServer(t, body, 1)
		sess, _ := p.Session("laptop")
		got := get(t, p, sess, "m/kt", 1).buf.Bytes()
		if len(got) != len(body) {
			t.Errorf("%d-byte body came back as %d bytes", len(body), len(got))
			continue
		}
		bits := 0
		for i := range got {
			for d := got[i] ^ body[i]; d != 0; d &= d - 1 {
				bits++
			}
		}
		if len(body) > 0 && bits != 1 {
			t.Errorf("%d-byte body: %d bits flipped, want 1", len(body), bits)
		}
	}
}

// readInserted must hand back every byte it consumed, whatever the reads look
// like, or the proof it was scanning arrives at the worker short.
func TestTheFramingScanLosesNothing(t *testing.T) {
	wire, err := os.ReadFile("../audit/testdata/proof.bin")
	if err != nil {
		t.Fatal(err)
	}
	ins, err := akdtree.FieldRanges(wire, insertedField)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{insertedScanLimit, 1, 1000} {
		src := oneByteAtATime(wire)
		head, sp := readInserted(src, limit)
		rest, err := io.ReadAll(io.MultiReader(bytes.NewReader(head), src))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rest, wire) {
			t.Fatalf("limit %d: the proof came back as %d bytes, want %d", limit, len(rest), len(wire))
		}
		if !sp.known {
			t.Fatalf("limit %d: the fixture's framing did not parse", limit)
		}
		// Whatever the limit, everything the scan claims is `inserted` is.
		if sp.end > ins[0].End {
			t.Fatalf("limit %d: claimed %d bytes of `inserted`, which ends at %d",
				limit, sp.end, ins[0].End)
		}
		if limit >= ins[0].End && sp.end != ins[0].End {
			t.Fatalf("limit %d: found %d bytes of `inserted`, want %d", limit, sp.end, ins[0].End)
		}
		if limit < ins[0].End && !sp.capped {
			t.Fatalf("limit %d: the scan stopped short of %d without saying it was capped",
				limit, ins[0].End)
		}
	}
}
