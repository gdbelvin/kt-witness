package main

import (
	"crypto/sha256"
	"os"
	"testing"
)

// Signal's CA is embedded here as a COPY of the one internal/source/signal
// pins, because the corpus tool may not widen that package's API. A copy can
// drift, and a drifted trust anchor is the kind of thing that fails silently
// and in the wrong direction — so make the drift loud.
//
// If this fails, the two files have diverged. Copy the pinned one over this
// one; do not "fix" it the other way round, because the adapter's copy is what
// the witness actually trusts in production.
func TestEmbeddedSignalCAMatchesThePinnedOne(t *testing.T) {
	const pinned = "../../internal/source/signal/signal-root.cer"

	want, err := os.ReadFile(pinned)
	if err != nil {
		t.Skipf("cannot read the pinned certificate at %s: %v", pinned, err)
	}
	if len(signalRootCer) == 0 {
		t.Fatal("no certificate is embedded here at all")
	}
	if sha256.Sum256(want) != sha256.Sum256(signalRootCer) {
		t.Fatalf("the embedded Signal CA has drifted from the pinned one in %s.\n"+
			"pinned  sha256 %x\nembedded sha256 %x\n"+
			"Copy the pinned file over this one — the adapter's copy is what the "+
			"witness trusts in production.",
			pinned, sha256.Sum256(want), sha256.Sum256(signalRootCer))
	}
}
