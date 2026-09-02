// Package vrf implements verification for ECVRF-EDWARDS25519-SHA512-TAI,
// suite 0x03 of RFC 9381.
//
// # Why a witness needs this
//
// A Key Transparency directory does not index bindings by identifier — that
// would let anyone enumerate every user. It indexes them by a *verifiable random
// function* of the identifier: a value only the operator can compute, that
// anyone holding the public key can check, and that reveals nothing about the
// identifier without a proof.
//
// So the VRF is what ties a name to a position in the tree. Auditing that a
// binding sits where it should — the check that catches a directory quietly
// moving or duplicating an entry — is impossible without verifying VRF proofs
// first. Head consistency and even a full tree rebuild cannot substitute: they
// prove the tree is the tree, not that a given identifier maps to a given leaf.
//
// # Scope
//
// Verification only. A witness never produces VRF proofs, so there is no
// proving path here and no secret key handling to get wrong.
package vrf

import (
	"bytes"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

// Suite 0x03 constants (RFC 9381 §5.5).
const (
	suiteID = 0x03

	// Domain separators keep the three hashes in the scheme from colliding:
	// one turns a message into a curve point, one derives the challenge, and
	// one derives the output. Reusing a hash across those roles is exactly the
	// kind of thing that silently breaks a VRF.
	dsEncode    = 0x01
	dsChallenge = 0x02
	dsProof     = 0x03
	dsBack      = 0x00

	// ProofSize is gamma(32) || c(16) || s(32).
	ProofSize = 80
	// OutputSize is the length of the VRF output ("beta").
	OutputSize = 32

	challengeSize = 16
)

// PublicKey is a VRF verification key.
type PublicKey struct {
	compressed [32]byte
	point      *edwards25519.Point
}

// NewPublicKey decodes and validates a 32-byte VRF public key.
//
// Small-order keys are rejected: with one, proofs could be forged for any
// message, so accepting one would make every downstream check meaningless.
func NewPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("vrf: public key is %d bytes, want 32", len(b))
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, fmt.Errorf("vrf: public key is not a valid curve point: %w", err)
	}
	// MultByCofactor maps the whole small-order subgroup to the identity, so
	// this catches every such key.
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, fmt.Errorf("vrf: public key has small order")
	}
	pk := &PublicKey{point: p}
	copy(pk.compressed[:], b)
	return pk, nil
}

// Bytes returns the compressed public key.
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, 32)
	copy(out, pk.compressed[:])
	return out
}

// ProofToHash verifies proof for message alpha and returns the VRF output.
//
// An error means the proof does not verify; the output is only meaningful when
// err is nil.
func (pk *PublicKey) ProofToHash(alpha, proof []byte) ([]byte, error) {
	if len(proof) != ProofSize {
		return nil, fmt.Errorf("vrf: proof is %d bytes, want %d", len(proof), ProofSize)
	}
	gammaBytes := proof[:32]
	cBytes := proof[32:48]
	sBytes := proof[48:80]

	gamma, err := new(edwards25519.Point).SetBytes(gammaBytes)
	if err != nil {
		return nil, fmt.Errorf("vrf: gamma is not a valid curve point: %w", err)
	}

	// c is 16 bytes, little-endian, zero-extended to a full scalar.
	var cWide [32]byte
	copy(cWide[:], cBytes)
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(cWide[:])
	if err != nil {
		return nil, fmt.Errorf("vrf: challenge is not a canonical scalar: %w", err)
	}
	// SetCanonicalBytes rejects s >= L, which is RFC 9381's "if s >= q, INVALID".
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sBytes)
	if err != nil {
		return nil, fmt.Errorf("vrf: s is not a canonical scalar: %w", err)
	}
	negC := new(edwards25519.Scalar).Negate(c)

	h, err := encodeToCurveTryAndIncrement(pk.compressed[:], alpha)
	if err != nil {
		return nil, err
	}

	// U = [s]B - [c]Y
	u := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, pk.point, s)
	// V = [s]H - [c]Gamma
	v := new(edwards25519.Point).VarTimeMultiScalarMult(
		[]*edwards25519.Scalar{s, negC},
		[]*edwards25519.Point{h, gamma},
	)

	cPrime := generateChallenge(
		pk.compressed[:], h.Bytes(), gammaBytes, u.Bytes(), v.Bytes(),
	)
	if !bytes.Equal(cBytes, cPrime) {
		return nil, fmt.Errorf("vrf: proof does not verify")
	}
	return proofToHash(gamma), nil
}

// encodeToCurveTryAndIncrement maps (public key, message) to a curve point by
// hashing with a counter until the digest happens to decode (RFC 9381 §5.4.1.1).
//
// The "TAI" in the suite name. It is not constant time — the number of attempts
// depends on the message — which is why RFC 9381 warns against using this suite
// on secret input. For a witness the messages are already public, so the leak
// costs nothing here.
func encodeToCurveTryAndIncrement(pkBytes, alpha []byte) (*edwards25519.Point, error) {
	identity := edwards25519.NewIdentityPoint()
	for ctr := 0; ctr <= 255; ctr++ {
		hsh := sha512.New()
		hsh.Write([]byte{suiteID, dsEncode})
		hsh.Write(pkBytes)
		hsh.Write(alpha)
		hsh.Write([]byte{byte(ctr), dsBack})
		digest := hsh.Sum(nil)

		p, err := new(edwards25519.Point).SetBytes(digest[:32])
		if err != nil {
			continue // this counter's digest is not a valid encoding; try the next
		}
		// Clearing the cofactor puts the point in the prime-order subgroup;
		// a small-order point becomes the identity and is rejected.
		p.MultByCofactor(p)
		if p.Equal(identity) == 1 {
			continue
		}
		return p, nil
	}
	// Each attempt succeeds with probability ~1/2, so this needs 256 failures.
	return nil, fmt.Errorf("vrf: encode_to_curve exhausted 256 counters")
}

// generateChallenge derives the 16-byte challenge over the five points
// (RFC 9381 §5.4.3).
func generateChallenge(y, h, gamma, u, v []byte) []byte {
	hsh := sha512.New()
	hsh.Write([]byte{suiteID, dsChallenge})
	for _, p := range [][]byte{y, h, gamma, u, v} {
		hsh.Write(p)
	}
	hsh.Write([]byte{dsBack})
	return hsh.Sum(nil)[:challengeSize]
}

// proofToHash derives the VRF output from gamma (RFC 9381 §5.2).
func proofToHash(gamma *edwards25519.Point) []byte {
	cleared := new(edwards25519.Point).MultByCofactor(gamma)
	hsh := sha512.New()
	hsh.Write([]byte{suiteID, dsProof})
	hsh.Write(cleared.Bytes())
	hsh.Write([]byte{dsBack})
	return hsh.Sum(nil)[:OutputSize]
}
