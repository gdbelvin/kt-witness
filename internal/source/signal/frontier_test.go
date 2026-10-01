package signal

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The frontier must agree with the explicitly built tree that the consistency
// and batch-inclusion tests already trust, at every size — including the
// awkward ones just past a power of two, where the right spine is deepest.
func TestLogFrontierMatchesTree(t *testing.T) {
	rt := referenceTree{}
	var f LogFrontier
	calc := &rootCalculator{}
	for n := uint64(1); n <= 300; n++ {
		leaf := rt.leaf(n - 1)
		if err := f.Append(leaf); err != nil {
			t.Fatal(err)
		}
		calc.insert(0, leaf)

		got, err := f.Root()
		if err != nil {
			t.Fatal(err)
		}
		if want := rt.root(t, n); got != want {
			t.Fatalf("size %d: frontier root %x, explicit tree %x", n, got, want)
		}
		if want, err := calc.root(); err != nil || got != want {
			t.Fatalf("size %d: frontier root %x, rootCalculator %x (%v)", n, got, want, err)
		}

		// Round-trip through the persisted form at every size.
		g, err := NewLogFrontier(f.Size(), f.Subtrees())
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := g.Root(); r != got {
			t.Fatalf("size %d: rebuilt frontier root differs", n)
		}
	}
}

// Known answers from Trail of Bits' signal-auditor (src/log/mod.rs): leaves
// 00…, 01 00…, 02 00… give these roots. They pin the 33-byte node encoding,
// in particular that a single-leaf tree's root is the leaf itself.
func TestLogFrontierKnownAnswers(t *testing.T) {
	want := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"133f2fb2b9884f212cb981871e3a33bddd95c40fc65a43a1ab21c1011d1a48c7",
		"7fb7325069ae4e7dd39c974f8839e6ff988d679267d0a356073e2c99fb1e3a03",
	}
	var f LogFrontier
	for i, w := range want {
		var leaf [32]byte
		leaf[0] = byte(i)
		if err := f.Append(leaf); err != nil {
			t.Fatal(err)
		}
		got, err := f.Root()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got[:]) != w {
			t.Fatalf("size %d: root %x, want %s", i+1, got, w)
		}
	}
}

// treeHash builds its preimage on the stack; it must still be exactly
// SHA-256(marshal(left) ‖ marshal(right)) for every flag combination.
func TestTreeHashIsMarshalledPreimage(t *testing.T) {
	a := node{value: sha256.Sum256([]byte("a"))}
	b := node{value: sha256.Sum256([]byte("b"))}
	for _, li := range []bool{false, true} {
		for _, ri := range []bool{false, true} {
			a.interior, b.interior = li, ri
			want := sha256.Sum256(append(a.marshal(), b.marshal()...))
			if got := treeHash(a, b); !got.interior || got.value != want {
				t.Fatalf("interior %v/%v: treeHash disagrees with marshal", li, ri)
			}
		}
	}
}

// Likewise the prefix-tree hashes against their spec preimages.
func TestPrefixHashPreimages(t *testing.T) {
	idx := sha256.Sum256([]byte("index"))
	l, r := sha256.Sum256([]byte("l")), sha256.Sum256([]byte("r"))
	var seed [16]byte
	copy(seed[:], "0123456789abcdef")
	cat := func(p ...[]byte) [32]byte {
		var b []byte
		for _, x := range p {
			b = append(b, x...)
		}
		return sha256.Sum256(b)
	}
	if PrefixLeafHash(idx, 0x01020304, 0x05060708090a0b0c) !=
		cat([]byte{0}, idx[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
		t.Fatal("leaf preimage")
	}
	if PrefixParentHash(l, r) != cat([]byte{1}, l[:], r[:]) {
		t.Fatal("parent preimage")
	}
	if PrefixStandInHash(seed, 200) != cat([]byte{2}, seed[:], []byte{200}) {
		t.Fatal("stand-in preimage")
	}
	if LogLeafHash(l, r) != cat(l[:], r[:]) {
		t.Fatal("log leaf preimage")
	}
}

func TestLogFrontierRejectsInconsistentShape(t *testing.T) {
	if _, err := NewLogFrontier(5, make([][32]byte, 1)); err == nil {
		t.Fatal("size 5 with one subtree root accepted")
	}
	if _, err := NewLogFrontier(0, make([][32]byte, 1)); err == nil {
		t.Fatal("empty frontier with a subtree root accepted")
	}
	var f LogFrontier
	if _, err := f.Root(); err == nil {
		t.Fatal("empty frontier produced a root")
	}
}
