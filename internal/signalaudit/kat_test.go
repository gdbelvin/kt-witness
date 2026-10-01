package signalaudit

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustHex32(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex %q", s)
	}
	return [32]byte(b)
}

// Known answers from the unit tests of Trail of Bits' signal-auditor. These are
// data, not code: the inputs and the roots they must produce.
//
// src/lib.rs test_initialize: one NewTree update and the resulting log root.
func TestKnownAnswerInitialize(t *testing.T) {
	u := Update{
		Real:       true,
		Index:      mustHex32(t, "72304a54df58d7d2673f7f99fe1689ca939eebc55741f3d1335904cb9c8564e4"),
		Commitment: mustHex32(t, "5f799a1d6d34dffacbec4d47c4f200a6be09de9b6d444ad27e87ba0beaad3607"),
		Proof:      NewTree,
	}
	seed, _ := hex.DecodeString("c3009d216ad487428a6f904ede447bc9")
	u.Seed = [16]byte(seed)

	var s State
	if err := s.Apply(u); err != nil {
		t.Fatal(err)
	}
	got, err := s.LogRoot()
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex32(t, "1e6fdd7508a05b5ba2661f7eec7e8df0a0ee9a277ca5b345f17fbe8e6aa8e9d1"); got != want {
		t.Fatalf("log root %x, want %x", got, want)
	}
}

// aesSeed is the reference tests' seed for a position: AES-128 under the zero
// key of 0^8 ‖ position_be64 — the same shape as Signal's real derivation
// (spec, "Stand-in hashes"), with a public key.
func aesSeed(pos uint64) (out [16]byte) {
	c, _ := aes.NewCipher(make([]byte, 16))
	var in [16]byte
	binary.BigEndian.PutUint64(in[8:], pos)
	c.Encrypt(out[:], in[:])
	return out
}

// katChain is src/prefix/mod.rs's three tests run as one sequence from the
// empty state (each test's starting root is the previous test's result): a
// NewTree, a real DifferentKey, and a fake DifferentKey, with the prefix root
// after each.
func katChain(t *testing.T) ([]Update, [][32]byte) {
	var i1, i2 [32]byte
	i1[0], i2[0] = 0x80, 0xc0
	w := mustHex32(t, "33819dcecb822883dd9e134325f28ba79d114fe69bb33a09d9755c6507fe22e7")
	x := mustHex32(t, "a7d0256b66a95ad4a8f9efed2ee9f060cc50c32336223063c30483dda33f0408")
	ups := []Update{
		{Real: true, Seed: aesSeed(0), Proof: NewTree},
		{Real: true, Index: i1, Seed: aesSeed(1), Proof: DifferentKey, OldSeed: aesSeed(0), Copath: [][32]byte{w}},
		{Real: false, Index: i2, Seed: aesSeed(2), Proof: DifferentKey, OldSeed: aesSeed(1), Copath: [][32]byte{w, x}},
	}
	roots := [][32]byte{
		mustHex32(t, "6eefbfcdf7b929b73963cb21eb882a2a3e49e8958fe25795df82d099e551915c"),
		mustHex32(t, "55a94bcb3a3958a83fab0053bdb553b4774b19a6516ac7fe0811a498396c2d36"),
		mustHex32(t, "82c7616b35828d31468590ecec7e3b62a31c7ec7a6874229da90a9cebf28a1df"),
	}
	return ups, roots
}

func TestKnownAnswerPrefixChain(t *testing.T) {
	ups, roots := katChain(t)
	var s State
	for i, u := range ups {
		// Through the wire, so the decoder is pinned to the same answers.
		d, err := DecodeUpdate(EncodeUpdate(u))
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		if err := s.Apply(d); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		got, ok := s.PrefixRoot()
		if !ok || got != roots[i] {
			t.Fatalf("update %d: prefix root %x, want %x", i, got, roots[i])
		}
	}
}
