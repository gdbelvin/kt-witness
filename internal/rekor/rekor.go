// Package rekor verifies Sigstore Rekor's signed tree heads.
//
// # Why this needs its own verifier
//
// Rekor publishes a checkpoint in the C2SP signed-note shape, but signs it with
// ECDSA rather than Ed25519, and `golang.org/x/mod/sumdb/note` implements only
// Ed25519. This is the same gap that internal/staticct fills for CT — except
// Rekor's scheme is different again, so the two cannot share code.
//
// # The scheme, established by probing rather than from documentation
//
//	key hash   SHA-256(DER SubjectPublicKeyInfo)[:4]
//	signature  ASN.1 DER ECDSA over the note body, hashed with SHA-256
//
// Both differ from the note conventions. The standard key hash mixes in the
// signer's name and an algorithm byte; Rekor's is the bare hash of the key, and
// the name is not covered. The signature is over the body verbatim INCLUDING
// its trailing newline — dropping it fails, which is exactly the sort of detail
// that turns into an afternoon.
//
// # Why witness Rekor at all
//
// Rekor is the transparency log behind Sigstore, which is what npm and PyPI
// attestations chain to. Witnessing it covers those transitively: a great many
// artifacts whose provenance claims rest on one log's append-only behaviour.
package rekor

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"golang.org/x/mod/sumdb/note"
)

// Verifier verifies a Rekor signed tree head.
type Verifier struct {
	name    string
	keyHash uint32
	pub     *ecdsa.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier builds a verifier from Rekor's PEM public key, as served at
// /api/v1/log/publicKey.
//
// The name must be the checkpoint's signer name — "rekor.sigstore.dev" — which
// is NOT the origin line: Rekor's origin carries a tree id suffix, and the two
// differ. The note format permits that, and this project has met it before with
// the Go checksum database.
func NewVerifier(name string, publicKeyPEM []byte) (*Verifier, error) {
	if name == "" {
		return nil, fmt.Errorf("rekor: signer name is required")
	}
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("rekor: public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rekor: parse public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rekor: public key is %T, want ECDSA", parsed)
	}

	// Bare hash of the key: no name, no algorithm byte. Established by matching
	// against the live checkpoint; see TestLiveRekorCheckpoint.
	sum := sha256.Sum256(block.Bytes)
	return &Verifier{
		name:    name,
		keyHash: binary.BigEndian.Uint32(sum[:4]),
		pub:     pub,
	}, nil
}

func (v *Verifier) Name() string    { return v.name }
func (v *Verifier) KeyHash() uint32 { return v.keyHash }

// Verify checks a DER ECDSA signature over the note body.
//
// note.Open passes the body with its trailing newline intact, which is what
// Rekor signs. Trimming it fails.
func (v *Verifier) Verify(msg, sig []byte) bool {
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(v.pub, digest[:], sig)
}
