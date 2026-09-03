package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source/akd"
)

// The live tests are the ones that matter, because the offline tests can only
// prove that a corrupted artifact is rejected — they cannot prove that a good
// one is accepted by the real verifier, and a corpus tool that fails everything
// would pass all of them.
func liveOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("live test; set KT_WITNESS_LIVE=1")
	}
}

// TestLiveSignalCaptureAndReplay is the full loop for the highest-value artifact
// in the corpus: capture a real response from Signal, replay it through the
// production verifier, then mutate it and require the replay to fail.
//
// The negative control is deliberately done twice over, because the two failures
// mean different things and only one of them tests the cryptography. Corrupting
// a byte and leaving the manifest alone only proves the hash check works.
// Corrupting a byte and *repairing the recorded hash* is the real control: the
// artifact is then internally consistent, so the only thing that can reject it
// is the verifier itself.
func TestLiveSignalCaptureAndReplay(t *testing.T) {
	liveOrSkip(t)

	c := NewCorpus(t.TempDir(), 64<<20, 0)
	fixedFree(c, 1<<40)
	r, err := NewReplayer(c, "", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f := NewFetcher(c, r, testWriter{t})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const origin = "signal.org/kt"
	if err := f.FetchSignal(ctx, origin, "https://chat.signal.org", 1, 0); err != nil {
		t.Fatalf("capture: %v", err)
	}
	ms, err := c.Manifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("want 1 artifact captured, got %d", len(ms))
	}
	m := ms[0]
	t.Logf("captured tree size %d root %s (%s)", m.Seq, m.Root[:16], human(m.Bytes))

	if err := r.Replay(ctx, m); err != nil {
		t.Fatalf("a freshly captured artifact must replay: %v", err)
	}

	// Control 1: mutate the blob, leave the manifest.
	full := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	body, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), body...)
	// A byte well inside the base64 payload, so the mutation lands in the proof
	// rather than in the JSON envelope.
	mutated[len(mutated)/2] ^= 0x01
	if err := os.WriteFile(full, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Replay(ctx, m); err == nil {
		t.Fatal("replay passed on a mutated artifact")
	}

	// Control 2: repair the hash so the artifact is self-consistent. Only the
	// verifier can reject it now.
	sum := sha256.Sum256(mutated)
	m.SHA256 = hex.EncodeToString(sum[:])
	m.Bytes = int64(len(mutated))
	if err := r.Replay(ctx, m); err == nil {
		t.Fatal("replay passed on a mutated artifact whose hash had been repaired: the verifier is not being exercised")
	} else {
		t.Logf("mutated artifact rejected by the verifier: %v", err)
	}

	// Control 3: intact bytes, wrong recorded expectation. This is the case a
	// replay that only asked "did it parse?" would miss.
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	good := sha256.Sum256(body)
	m.SHA256 = hex.EncodeToString(good[:])
	m.Bytes = int64(len(body))
	m.Root = "00" + m.Root[2:]
	if err := r.Replay(ctx, m); err == nil {
		t.Fatal("replay passed against a root the artifact does not verify to")
	}
}

// TestLiveAKDCaptureAndReplay does the same for an AKD log. WhatsApp rather than
// Meta by default: its proofs are ~58.5 MB against Meta's ~284 MB, so the test
// exercises the identical code path for a fifth of the bandwidth.
//
// It needs the Rust sidecar, which is a separate build, so it is gated on the
// binary's path as well as on KT_WITNESS_LIVE.
func TestLiveAKDCaptureAndReplay(t *testing.T) {
	liveOrSkip(t)
	sidecar := os.Getenv("KT_WITNESS_SIDECAR")
	if sidecar == "" {
		t.Skip("set KT_WITNESS_SIDECAR to the kt-akd-verify binary")
	}

	c := NewCorpus(t.TempDir(), 2<<30, 0)
	fixedFree(c, 1<<40)
	r, err := NewReplayer(c, sidecar, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f := NewFetcher(c, r, testWriter{t})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cfg := akd.Config{
		Origin:            "whatsapp.kt/v2",
		LogDirectory:      "https://d4ttn6vhp3mg0.cloudfront.net",
		PlexiNamespaceURL: "https://plexi.key-transparency.cloudflare.com/namespaces/whatsapp.key-transparency.v2",
	}
	// Three epochs, not one, and one success is enough. Meta's and WhatsApp's
	// proofs are served through a CDN that caches negative listings, so a
	// just-published object can 404 for a while — the trap described in
	// design.md, and observed while building this. Fetch skips such an epoch
	// rather than treating absence as evidence, so a test that demanded a
	// specific epoch would fail for a reason that has nothing to do with the
	// code under test.
	if err := f.FetchAKD(ctx, cfg, 3); err != nil {
		t.Fatalf("capture: %v", err)
	}
	ms, err := c.Manifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no epoch could be captured")
	}
	m := ms[0]
	t.Logf("captured epoch %d (%s)", m.Seq, human(m.Bytes))

	if err := r.Replay(ctx, m); err != nil {
		t.Fatalf("a freshly captured epoch must replay: %v", err)
	}

	// The negative control, with the hash repaired so the failure comes from the
	// append-only verification rather than from our own integrity check.
	full := filepath.Join(c.Dir, filepath.FromSlash(m.Blob))
	body, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0x01
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	m.SHA256 = hex.EncodeToString(sum[:])
	if err := r.Replay(ctx, m); err == nil {
		t.Fatal("replay passed on a mutated proof")
	} else {
		t.Logf("mutated proof rejected: %v", err)
	}
}

// testWriter routes the fetcher's progress output into the test log. A fetch
// run deliberately continues past an artifact it could not take, so without
// this a live failure would surface only as "0 artifacts captured".
type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("%s", b)
	return len(b), nil
}
