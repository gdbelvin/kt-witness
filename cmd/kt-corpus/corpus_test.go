package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// httpGet returns just the status code, which is all these tests need from the
// replay server.
func httpGet(url string) (int, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// fixedFree makes a test corpus behave as if the host had exactly this much
// free space, so the floor can be exercised without a nearly full disk.
func fixedFree(c *Corpus, n int64) {
	c.free = func(string) (int64, error) { return n, nil }
}

// store writes an artifact and its manifest directly, standing in for a capture
// that already verified.
func store(t *testing.T, c *Corpus, kind Kind, origin string, seq int64, body []byte) *Manifest {
	t.Helper()
	name := "blob"
	switch kind {
	case KindSignal:
		name = "0.json"
	case KindAKD:
		name = "p/c"
	}
	rel := path.Join(string(kind), slug(origin), "blobs", name+"-"+hex.EncodeToString([]byte{byte(seq)}))
	full := filepath.Join(c.Dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	m := &Manifest{
		Kind: kind, Origin: origin, Seq: seq,
		Blob: rel, Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:]),
		Root:       strings.Repeat("00", 32),
		CapturedAt: time.Now().UTC(),
	}
	if err := c.save(m); err != nil {
		t.Fatal(err)
	}
	return m
}

func newTestCorpus(t *testing.T, maxBytes, floor int64) *Corpus {
	t.Helper()
	c := NewCorpus(t.TempDir(), maxBytes, floor)
	fixedFree(c, 1<<40)
	return c
}

// The cap is the limit that keeps the corpus from growing without bound, and it
// is a total across ecosystems rather than per ecosystem: the host's thin pool
// does not care which log filled it.
func TestSizeCapRefusesBeforeDownload(t *testing.T) {
	c := newTestCorpus(t, 1000, 0)
	store(t, c, KindSignal, "signal.org/kt", 1, bytes.Repeat([]byte("x"), 800))

	if err := c.CheckBudget(100); err != nil {
		t.Fatalf("100 bytes should fit under the cap: %v", err)
	}
	err := c.CheckBudget(300)
	if !errors.Is(err, ErrCapReached) {
		t.Fatalf("want ErrCapReached, got %v", err)
	}
}

// Content-Length is a claim, so the cap has to hold even when a provider
// understates a response's size. This is the check that actually protects the
// disk.
func TestSizeCapStopsMidStream(t *testing.T) {
	c := newTestCorpus(t, 1000, 0)
	remaining, err := c.Remaining()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(c.Dir, "over")
	_, _, err = c.writeBlob(dst, bytes.NewReader(bytes.Repeat([]byte("y"), 5000)), remaining)
	if !errors.Is(err, ErrCapReached) {
		t.Fatalf("want ErrCapReached, got %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("an over-budget artifact must not be left on disk")
	}
	if _, err := os.Stat(dst + ".partial"); !os.IsNotExist(err) {
		t.Fatal("the partial file must be cleaned up")
	}
}

// The floor exists because the witness host's volumes sit on an over-provisioned
// thin pool, where running out of space can freeze every guest. It must refuse
// even when the corpus is nowhere near its own cap.
func TestFreeSpaceFloorRefuses(t *testing.T) {
	c := NewCorpus(t.TempDir(), 1<<40, 100<<30)
	fixedFree(c, 101<<30)

	if err := c.CheckBudget(1 << 20); err != nil {
		t.Fatalf("1 MB should fit above the floor: %v", err)
	}
	err := c.CheckBudget(2 << 30)
	if !errors.Is(err, ErrFloorReached) {
		t.Fatalf("want ErrFloorReached, got %v", err)
	}
	if errors.Is(err, ErrCapReached) {
		t.Fatal("the corpus is far below its cap; this must be reported as the floor")
	}
}

// Remaining is what bounds a streaming download, so it must track whichever
// limit binds first.
func TestRemainingTakesTheTighterLimit(t *testing.T) {
	c := NewCorpus(t.TempDir(), 10<<30, 100<<30)
	fixedFree(c, 101<<30)
	got, err := c.Remaining()
	if err != nil {
		t.Fatal(err)
	}
	if got != 1<<30 {
		t.Fatalf("floor should bind at 1 GB, got %s", human(got))
	}
	fixedFree(c, 1<<40)
	if got, _ = c.Remaining(); got != 10<<30 {
		t.Fatalf("cap should bind at 10 GB, got %s", human(got))
	}
}

// A replay that passes on mutated input tests nothing, so the first thing a
// replay does is confirm the artifact is the one that was captured.
func TestReplayFailsOnCorruptedArtifact(t *testing.T) {
	c := newTestCorpus(t, 1<<30, 0)
	m := store(t, c, KindSignal, "signal.org/kt", 7, []byte(`{"serializedResponse":"AAAA"}`))

	if err := c.checkBlob(m); err != nil {
		t.Fatalf("intact artifact should pass its integrity check: %v", err)
	}

	full := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	body, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	body[3] ^= 0x01 // one bit, the smallest mutation there is
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := c.checkBlob(m); err == nil {
		t.Fatal("a flipped bit must fail the integrity check")
	}

	r, err := NewReplayer(c, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.Replay(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "blob integrity") {
		t.Fatalf("replay must reject a corrupted artifact as an integrity failure, got %v", err)
	}
}

// Truncation is the other way an artifact goes wrong, and it must not be
// mistaken for a shorter but valid proof.
func TestReplayFailsOnTruncatedArtifact(t *testing.T) {
	c := newTestCorpus(t, 1<<30, 0)
	m := store(t, c, KindSignal, "signal.org/kt", 9, []byte("0123456789"))
	full := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	if err := os.WriteFile(full, []byte("01234"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.checkBlob(m); err == nil {
		t.Fatal("a truncated artifact must fail the integrity check")
	}
}

// Integrity is necessary but not sufficient: a blob whose hash matches its
// manifest can still be nonsense, and the point of replay is that the real
// verifier runs. This artifact is intact and complete — and must still fail,
// because it is not a valid Signal response.
func TestReplayRunsTheRealVerifier(t *testing.T) {
	c := newTestCorpus(t, 1<<30, 0)
	m := store(t, c, KindSignal, "signal.org/kt", 11, []byte(`{"serializedResponse":"AAAA"}`))
	if err := c.checkBlob(m); err != nil {
		t.Fatalf("artifact should be intact: %v", err)
	}
	r, err := NewReplayer(c, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.Replay(context.Background(), m)
	if err == nil {
		t.Fatal("garbage must not verify")
	}
	if strings.Contains(err.Error(), "blob integrity") {
		t.Fatalf("failure came from the hash check, not the verifier: %v", err)
	}
}

// A stored blob that is not a valid proof must fail replay, and must fail with
// a verification error rather than being quietly counted as a pass.
//
// This test used to assert that replay failed when the Rust subprocess was absent,
// which was a statement about a missing binary rather than about the artifact.
// The verifier is always present now, so the thing worth asserting is the one
// that was always the point: garbage does not replay.
func TestAKDReplayRejectsAnArtifactThatIsNotAProof(t *testing.T) {
	c := newTestCorpus(t, 1<<30, 0)
	m := store(t, c, KindAKD, "meta.messenger.kt/v1", 5, []byte("proof"))
	r, err := NewReplayer(c, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Replay(context.Background(), m); err == nil {
		t.Fatal("five bytes that are not a proof replayed successfully")
	}
}

// GC keeps the corpus under the cap while preserving the spread of epochs,
// because a run of consecutive epochs is a much weaker regression suite than the
// same number spread across history.
func TestGCPrunesToCapAndKeepsTheSpan(t *testing.T) {
	c := newTestCorpus(t, 300, 0)
	body := bytes.Repeat([]byte("z"), 100)
	for _, seq := range []int64{10, 11, 12, 13, 100} {
		store(t, c, KindAKD, "meta.messenger.kt/v1", seq, body)
	}

	dropped, err := c.GC()
	if err != nil {
		t.Fatal(err)
	}
	total, err := c.TotalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if total > c.MaxBytes {
		t.Fatalf("gc left %s, over the %s cap", human(total), human(c.MaxBytes))
	}
	if len(dropped) != 2 {
		t.Fatalf("want 2 artifacts dropped, got %d", len(dropped))
	}

	ms, err := c.Manifests()
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := ms[0].Seq, ms[len(ms)-1].Seq
	if lo != 10 || hi != 100 {
		t.Fatalf("gc must erode density, not coverage: span is now %d..%d", lo, hi)
	}
	for _, m := range ms {
		if _, err := os.Stat(filepath.Join(c.Dir, filepath.FromSlash(m.Blob))); err != nil {
			t.Fatalf("surviving manifest %d has no blob: %v", m.Seq, err)
		}
	}
	for _, m := range dropped {
		if _, err := os.Stat(filepath.Join(c.Dir, filepath.FromSlash(m.Blob))); !os.IsNotExist(err) {
			t.Fatalf("dropped artifact %d still on disk", m.Seq)
		}
	}
}

// Epoch selection walks back from the tip in doubling steps, so a small budget
// still buys a wide span rather than one afternoon's worth of nearly identical
// trees.
func TestDiverseEpochsSpread(t *testing.T) {
	got := diverseEpochs(1000, 5, 0)
	want := []int64{1000, 999, 998, 996, 992}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if e := diverseEpochs(3, 10, 0); len(e) == 0 || e[len(e)-1] <= 0 {
		t.Fatalf("selection must stay above the floor: %v", e)
	}
}

// The replay server exists only to feed the corpus to verifiers that fetch over
// HTTP. It must not become a way to read the rest of the host's filesystem.
func TestReplayServerStaysInsideTheCorpus(t *testing.T) {
	c := newTestCorpus(t, 1<<30, 0)
	rs, err := newReplayServer(c)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()

	resp, err := httpGet(rs.URL() + "/../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if resp == 200 {
		t.Fatal("path traversal must not be served")
	}
	if resp, err = httpGet(rs.URL() + signalPath); err != nil {
		t.Fatal(err)
	} else if resp == 200 {
		t.Fatal("no signal artifact is selected; the endpoint must 404")
	}
}
