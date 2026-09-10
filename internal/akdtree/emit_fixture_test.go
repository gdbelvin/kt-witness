package akdtree

import (
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
)

// TestEmitFixture writes a valid proof and its roots for other packages to use.
// Run with -run TestEmitFixture -emit to regenerate.
func TestEmitFixture(t *testing.T) {
	if os.Getenv("KT_EMIT_FIXTURE") == "" {
		t.Skip("set KT_EMIT_FIXTURE=1 to regenerate")
	}
	p := makeSynthProof(rand.New(rand.NewSource(11)), 300, 40, 4242)
	if err := os.WriteFile("../audit/testdata/proof.bin", p.wire, 0o644); err != nil {
		t.Fatal(err)
	}
	meta := "epoch 4242\n" + hex.EncodeToString(p.prev[:]) + "\n" + hex.EncodeToString(p.curr[:]) + "\n"
	if err := os.WriteFile("../audit/testdata/proof.roots", []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes, prev=%x curr=%x", len(p.wire), p.prev, p.curr)
}
