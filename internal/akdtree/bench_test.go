package akdtree

import (
	"testing"

	"lukechampine.com/blake3"
)

// BenchmarkHash64 is the floor. Every optimisation in this package is measured
// against what the machine can hash, because below that number there is nothing
// left to win and effort should stop — the lesson of docs/gpu_notes.md, applied
// to a CPU.
func BenchmarkHash64(b *testing.B) {
	var buf [64]byte
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		d := blake3.Sum256(buf[:])
		copy(buf[:32], d[:])
	}
}

// BenchmarkParentHash is what one interior node actually costs: three hashes
// for the parent plus one for its label.
func BenchmarkNodeHashes(b *testing.B) {
	var lv, ll, rv, rl Digest
	var label [32]byte
	for i := 0; i < b.N; i++ {
		lv = parentHash(lv, ll, rv, rl)
		ll = labelValue(label, 42)
	}
	_ = lv
}
