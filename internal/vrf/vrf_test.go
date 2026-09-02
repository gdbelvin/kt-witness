package vrf

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The official RFC 9381 Appendix B.1 test vectors for
// ECVRF-EDWARDS25519-SHA512-TAI. These are the standard against which any
// implementation of this suite is judged; getting all three exactly right,
// including the intermediate H, is what makes the rest of the package
// trustworthy.
var rfc9381Vectors = []struct {
	name  string
	pk    string
	alpha string
	h     string
	pi    string
	beta  string
}{
	{
		name:  "empty message",
		pk:    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		alpha: "",
		h:     "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
		pi:    "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
		beta:  "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff",
	},
	{
		name:  "single byte 0x72",
		pk:    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		alpha: "72",
		h:     "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
		pi:    "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
		beta:  "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb",
	},
	{
		name:  "two bytes 0xaf82",
		pk:    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		alpha: "af82",
		h:     "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
		pi:    "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
		beta:  "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45",
	},
}

func TestRFC9381Vectors(t *testing.T) {
	for _, v := range rfc9381Vectors {
		t.Run(v.name, func(t *testing.T) {
			pk, err := NewPublicKey(mustHex(t, v.pk))
			if err != nil {
				t.Fatal(err)
			}
			got, err := pk.ProofToHash(mustHex(t, v.alpha), mustHex(t, v.pi))
			if err != nil {
				t.Fatalf("the RFC's own proof must verify: %v", err)
			}
			if want := mustHex(t, v.beta); !bytes.Equal(got, want) {
				t.Fatalf("output mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// Checking the intermediate H separately localises a failure: if this passes and
// the full verification does not, the bug is in the challenge or the group
// arithmetic rather than in hash-to-curve.
func TestEncodeToCurveMatchesVectors(t *testing.T) {
	for _, v := range rfc9381Vectors {
		t.Run(v.name, func(t *testing.T) {
			h, err := encodeToCurveTryAndIncrement(mustHex(t, v.pk), mustHex(t, v.alpha))
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, v.h); !bytes.Equal(h.Bytes(), want) {
				t.Fatalf("H mismatch\n got %x\nwant %x", h.Bytes(), want)
			}
		})
	}
}

// A VRF that accepts a tampered proof is worse than none: it would let an
// operator claim any position in the tree for any identifier.
func TestTamperedProofRejected(t *testing.T) {
	v := rfc9381Vectors[2]
	pk, err := NewPublicKey(mustHex(t, v.pk))
	if err != nil {
		t.Fatal(err)
	}
	proof := mustHex(t, v.pi)

	for _, part := range []struct {
		name string
		idx  int
	}{
		{"gamma", 0},
		{"challenge", 32},
		{"s", 48},
	} {
		t.Run(part.name, func(t *testing.T) {
			bad := append([]byte(nil), proof...)
			bad[part.idx] ^= 0x01
			if _, err := pk.ProofToHash(mustHex(t, v.alpha), bad); err == nil {
				t.Fatalf("a proof with a flipped bit in %s must be rejected", part.name)
			}
		})
	}
}

// The proof must be bound to the message, or an operator could reuse one proof
// to justify a different identifier's position.
func TestProofDoesNotVerifyForOtherMessage(t *testing.T) {
	v := rfc9381Vectors[2]
	pk, err := NewPublicKey(mustHex(t, v.pk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.ProofToHash([]byte("different"), mustHex(t, v.pi)); err == nil {
		t.Fatal("a proof must not verify for a message it was not made for")
	}
}

// And bound to the key.
func TestProofDoesNotVerifyUnderOtherKey(t *testing.T) {
	v := rfc9381Vectors[2]
	other, err := NewPublicKey(mustHex(t, rfc9381Vectors[1].pk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ProofToHash(mustHex(t, v.alpha), mustHex(t, v.pi)); err == nil {
		t.Fatal("a proof must not verify under a different public key")
	}
}

// Small-order keys would let anyone forge a proof for any message, so they must
// be refused at construction rather than producing confident wrong answers.
func TestSmallOrderKeysRejected(t *testing.T) {
	// The canonical small-order points of edwards25519.
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000", // identity
		"0000000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
	} {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := new(edwards25519.Point).SetBytes(b); err != nil {
			continue // not a valid encoding at all; nothing to test
		}
		if _, err := NewPublicKey(b); err == nil {
			t.Errorf("small-order key %s must be rejected", h[:16])
		}
	}
}

func TestMalformedInputsRejected(t *testing.T) {
	v := rfc9381Vectors[0]
	pk, err := NewPublicKey(mustHex(t, v.pk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.ProofToHash(nil, make([]byte, 79)); err == nil {
		t.Error("a short proof must be rejected")
	}
	if _, err := pk.ProofToHash(nil, make([]byte, 81)); err == nil {
		t.Error("a long proof must be rejected")
	}
	if _, err := NewPublicKey(make([]byte, 31)); err == nil {
		t.Error("a short public key must be rejected")
	}

	// A non-canonical s (>= L) must be refused rather than silently reduced.
	bad := append([]byte(nil), mustHex(t, v.pi)...)
	for i := 48; i < 80; i++ {
		bad[i] = 0xFF
	}
	if _, err := pk.ProofToHash(mustHex(t, v.alpha), bad); err == nil {
		t.Error("a non-canonical scalar must be rejected")
	}
}

// Pins the domain separators. All three hashes in the scheme are SHA-512 over
// the same kinds of input, so a wrong separator would still produce plausible
// output while silently breaking the scheme's separation.
func TestDomainSeparatorsArePinned(t *testing.T) {
	if suiteID != 0x03 {
		t.Fatal("suite must be 0x03, ECVRF-EDWARDS25519-SHA512-TAI")
	}
	if dsEncode != 0x01 || dsChallenge != 0x02 || dsProof != 0x03 || dsBack != 0x00 {
		t.Fatal("domain separators must match RFC 9381")
	}

	// proof_to_hash is SHA-512(suite || 0x03 || cofactor*gamma || 0x00)[:32].
	v := rfc9381Vectors[0]
	gamma, err := new(edwards25519.Point).SetBytes(mustHex(t, v.pi)[:32])
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New()
	h.Write([]byte{0x03, 0x03})
	h.Write(new(edwards25519.Point).MultByCofactor(gamma).Bytes())
	h.Write([]byte{0x00})
	if want := h.Sum(nil)[:32]; !bytes.Equal(proofToHash(gamma), want) {
		t.Fatal("proof_to_hash does not match its specified construction")
	}
}

// Verifies a VRF proof taken from Signal's production key transparency service.
//
// Signal's `distinguished` endpoint is unauthenticated and its response carries
// a search proof whose first field is an 80-byte VRF proof over the literal
// search key "distinguished". Passing the RFC's own vectors shows the suite is
// implemented correctly; this shows it is the same suite Signal actually
// deployed, which is the part a vector cannot tell you.
func TestSignalProductionProof(t *testing.T) {
	const (
		// libsignal rust/net/src/env.rs, production VRF key.
		signalVRFKey = "3849cf116c7bc9aef5f13f0c61a7c246e5bade4eb7e1c7b0efcacdd8c1e6a6ff"
		// Captured from https://chat.signal.org/v1/key-transparency/distinguished
		signalProof = "c560c7a7f1e597b5b2b9d7b398040e267ba78db77664f23b857c2efccc3d30a82e5b8ae89633ab079833c2a6009b91ddf5e18d1b7e843f5e53f34478134014dd2aa7a68007e28e24aa55caabe9c93509"
	)
	pk, err := NewPublicKey(mustHex(t, signalVRFKey))
	if err != nil {
		t.Fatal(err)
	}
	out, err := pk.ProofToHash([]byte("distinguished"), mustHex(t, signalProof))
	if err != nil {
		t.Fatalf("Signal's own VRF proof must verify: %v", err)
	}
	t.Logf("Signal distinguished VRF output: %x", out)
}
