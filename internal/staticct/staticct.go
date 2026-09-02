// Package staticct verifies the checkpoint signatures of static CT logs.
//
// # Why this exists
//
// Static CT logs (C2SP static-ct-api, as implemented by Sunlight and Tessera)
// publish a `tlog-checkpoint` signed note over `tlog-tiles` — exactly the shape
// this project's c2sp adapter already witnesses. There are ~80 of them in
// Google's log list, against 42 remaining RFC 6962 logs, so they are by some
// distance the largest population of transparency logs a witness can serve.
//
// One thing stands in the way: the log's authoritative checkpoint signature is
// not Ed25519. It is the RFC 6962 tree head signature, note algorithm 0x05, and
// `golang.org/x/mod/sumdb/note` implements only Ed25519. This package supplies
// the missing `note.Verifier`, so the existing adapter can consume those logs
// unchanged.
//
// # Why not use the Ed25519 line instead
//
// Sunlight-family logs also carry an Ed25519 signature line, which would be
// easier to verify. It is the wrong thing to check. The RFC 6962 signature is
// made with the key the CT ecosystem already knows and publishes — the one in
// Google's log list, pinned by every browser root program — whereas the Ed25519
// key is per-deployment and distributed out of band. Witnessing the key that
// nobody has independently vouched for would weaken the assertion to nothing.
//
// # The signature
//
// The note signature blob (after the note package strips the 4-byte key hash)
// carries RFC 6962's `digitally-signed` framing, not a bare signature:
//
//	uint64 timestamp
//	uint8  hash algorithm      4 = SHA-256
//	uint8  signature algorithm 3 = ECDSA
//	uint16 signature length
//	opaque signature[]         ASN.1 DER
//
// The signed message is RFC 6962 §3.5's TreeHeadSignature:
//
//	0x00                    version v1
//	0x01                    signature type tree_hash
//	uint64 timestamp        the same timestamp carried in the blob
//	uint64 tree_size
//	opaque root_hash[32]
//
// hashed with SHA-256. Note the timestamp is *not* covered by the checkpoint
// body, only by this structure, which is why it has to be carried alongside.
package staticct

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// AlgRFC6962 is the note algorithm identifier for an RFC 6962 tree head
// signature (C2SP tlog-checkpoint).
const AlgRFC6962 = 0x05

// The only algorithm pair RFC 6962 defines for CT log signatures.
const (
	hashAlgSHA256 = 4
	sigAlgECDSA   = 3
)

// Verifier verifies a static CT log's checkpoint signature.
type Verifier struct {
	name    string
	keyHash uint32
	pub     *ecdsa.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier builds a verifier from a log's name and its DER
// SubjectPublicKeyInfo, exactly as published in the CT log list.
//
// The name is the checkpoint origin, which per static-ct-api is the log's
// *submission* prefix without scheme or trailing slash. That is not always the
// monitoring prefix — Google's logs submit to
// `<log>.prod.certificate.transparency.goog` while serving tiles from a
// storage.googleapis.com bucket — and using the wrong one produces a key hash
// that matches nothing, which looks like an unsigned checkpoint rather than an
// error. Use OriginFromSubmissionURL.
func NewVerifier(name string, spki []byte) (*Verifier, error) {
	if name == "" {
		return nil, fmt.Errorf("staticct: name is required")
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("staticct: parse public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("staticct: public key is %T, want ECDSA", parsed)
	}

	// The key hash covers the log ID — SHA-256 of the SPKI, which is the
	// identifier the CT ecosystem already uses — and not the SPKI itself.
	// Established by matching against live checkpoints from Google and Let's
	// Encrypt; see TestLiveStaticCT.
	logID := sha256.Sum256(spki)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', AlgRFC6962})
	h.Write(logID[:])
	sum := h.Sum(nil)

	return &Verifier{
		name:    name,
		keyHash: binary.BigEndian.Uint32(sum[:4]),
		pub:     pub,
	}, nil
}

func (v *Verifier) Name() string    { return v.name }
func (v *Verifier) KeyHash() uint32 { return v.keyHash }

// Verify checks sig over the checkpoint text msg.
func (v *Verifier) Verify(msg, sig []byte) bool {
	if len(sig) < 12 {
		return false
	}
	timestamp := binary.BigEndian.Uint64(sig[:8])
	if sig[8] != hashAlgSHA256 || sig[9] != sigAlgECDSA {
		return false
	}
	sigLen := int(binary.BigEndian.Uint16(sig[10:12]))
	// Exact length, not a lower bound: trailing bytes after a valid signature
	// must not be silently ignored.
	if len(sig) != 12+sigLen {
		return false
	}
	der := sig[12 : 12+sigLen]

	size, root, ok := parseCheckpoint(msg, v.name)
	if !ok {
		return false
	}

	var signed [50]byte
	signed[0] = 0 // version v1
	signed[1] = 1 // signature type tree_hash
	binary.BigEndian.PutUint64(signed[2:10], timestamp)
	binary.BigEndian.PutUint64(signed[10:18], size)
	copy(signed[18:], root[:])

	digest := sha256.Sum256(signed[:])
	return ecdsa.VerifyASN1(v.pub, digest[:], der)
}

// parseCheckpoint reads the origin, size and root hash from a checkpoint body.
//
// The origin is checked against the verifier's name: a signature is only
// meaningful for the log it names, and accepting a correctly signed checkpoint
// under the wrong origin would let one log's head be witnessed as another's.
func parseCheckpoint(msg []byte, want string) (size uint64, root [32]byte, ok bool) {
	lines := strings.SplitN(string(msg), "\n", 4)
	if len(lines) < 3 {
		return 0, root, false
	}
	if lines[0] != want {
		return 0, root, false
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, root, false
	}
	decoded, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(decoded) != 32 {
		return 0, root, false
	}
	copy(root[:], decoded)
	return size, root, true
}

// OriginFromSubmissionURL derives the checkpoint origin from a CT log list
// submission URL by stripping the scheme and any trailing slash.
func OriginFromSubmissionURL(u string) string {
	s := strings.TrimPrefix(u, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}
