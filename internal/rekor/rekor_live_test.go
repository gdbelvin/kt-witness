package rekor

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const rekorBase = "https://rekor.sigstore.dev"

// TestLiveRekorCheckpoint is the acceptance test. Rekor's key hash and
// signature scheme were both established by probing rather than from
// documentation, so the only thing that establishes them is a real checkpoint
// verifying under a key fetched independently.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveRekorCheckpoint(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}

	pemBytes := get(t, rekorBase+"/api/v1/log/publicKey")
	body := get(t, rekorBase+"/api/v1/log")
	var log struct {
		SignedTreeHead string `json:"signedTreeHead"`
	}
	if err := json.Unmarshal(body, &log); err != nil {
		t.Fatal(err)
	}
	if log.SignedTreeHead == "" {
		t.Fatal("no signed tree head served")
	}

	v, err := NewVerifier("rekor.sigstore.dev", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open([]byte(log.SignedTreeHead), note.VerifierList(v))
	if err != nil {
		t.Fatalf("production Rekor checkpoint does not verify: %v", err)
	}
	lines := strings.SplitN(n.Text, "\n", 4)
	t.Logf("origin %q, size %s, root %s", lines[0], lines[1], lines[2])
	if !strings.HasPrefix(lines[0], "rekor.sigstore.dev") {
		t.Errorf("unexpected origin %q", lines[0])
	}

	// Negative control: a checkpoint whose size has been altered must not
	// verify. A check that passes on mutated input checks nothing.
	tampered := strings.Replace(log.SignedTreeHead, "\n"+lines[1]+"\n", "\n"+lines[1]+"0\n", 1)
	if _, err := note.Open([]byte(tampered), note.VerifierList(v)); err == nil {
		t.Fatal("a checkpoint with an altered tree size still verified")
	}
}

// The origin line and the signer name genuinely differ for Rekor — the origin
// carries a tree id suffix. Anything assuming they match will silently fail to
// find the signature.
func TestSignerNameIsNotTheOrigin(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	body := get(t, rekorBase+"/api/v1/log")
	var log struct {
		SignedTreeHead string `json:"signedTreeHead"`
	}
	_ = json.Unmarshal(body, &log)
	origin := strings.SplitN(log.SignedTreeHead, "\n", 2)[0]
	if origin == "rekor.sigstore.dev" {
		t.Skip("origin and signer name coincide today; the distinction may have gone")
	}
	t.Logf("origin %q differs from signer name %q, as expected", origin, "rekor.sigstore.dev")
}

func TestBadKeyIsRejected(t *testing.T) {
	if _, err := NewVerifier("x", []byte("not pem")); err == nil {
		t.Error("non-PEM input was accepted")
	}
	if _, err := NewVerifier("", []byte("")); err == nil {
		t.Error("an empty signer name was accepted")
	}
}

func get(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b
}
