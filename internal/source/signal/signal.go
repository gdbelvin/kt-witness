// Package signal witnesses Signal's Key Transparency deployment.
//
// # Why this is possible without asking Signal
//
// Signal runs two distinct planes. The auditor plane (audit.kt.signal.org,
// batched updates and SetAuditorHead) is bilateral and needs a Signal-issued
// client certificate. The client plane is wide open: the KT endpoints are
// unauthenticated *by design* — the server rejects requests that carry
// credentials — so anyone can fetch a signed tree head.
//
//	GET https://chat.signal.org/v1/key-transparency/distinguished
//
// returns a FullTreeHead containing the service's tree head and, because Signal
// deploys in third-party-auditing mode, one FullAuditorTreeHead per auditor.
// Each of those carries the auditor's own tree size, timestamp, root value and
// Ed25519 signature.
//
// # What this adapter verifies, and what it does not
//
// It verifies the auditor's Ed25519 signature over the exact preimage libsignal
// uses, and tracks that auditor's signed heads over time. Combined with the
// core's gates, that gives conclusive equivocation detection: two different
// roots signed at the same tree size is a contradiction the auditor's own key
// attests to.
//
// It does NOT prove append-only between two observations. Doing so needs a
// consistency proof between the two auditor tree sizes, and Signal's public API
// offers consistency proofs only against the *service* tree — whose root is not
// served directly and must be reconstructed via the combined-tree search proof
// machinery. That is a substantial piece of work and is not done here, so this
// source reports TierSignedHead rather than TierA. See NOTES.md.
//
// Three auditors are configured in production (Signal, Cloudflare, Trail of
// Bits). Each is witnessed as its own log, so divergence or lag between them is
// visible rather than averaged away.
package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// signalRoot is Signal's private CA. chat.signal.org does not chain to public
// roots, so it must be pinned. Taken verbatim from libsignal
// (rust/net/res/signal.cer), which is where Signal's own clients get it.
//
//go:embed signal-root.cer
var signalRoot []byte

// Production key material, pinned in libsignal rust/net/src/env.rs. These were
// cross-checked against the live wire: the auditor_public_key values in a real
// distinguished response match the hardcoded auditor keys byte for byte.
const (
	ProdSigningKey = "a3973067984382cfa89ec26d7cc176680aefe92b3d2eba85159dad0b8354b622"
	ProdVRFKey     = "3849cf116c7bc9aef5f13f0c61a7c246e5bade4eb7e1c7b0efcacdd8c1e6a6ff"
)

// ProdAuditorKeys are the three auditors Signal deploys with. Signal's blog
// names Signal, Cloudflare and Trail of Bits; which key belongs to whom is not
// published by any of them.
var ProdAuditorKeys = []string{
	"2d973608e909a09e12cbdbd21ad58775fd72fe1034a5a079f26541d5764ce17f",
	"2f217a86cd2dbc95d46a84420942a95877b3723f634bc64bb9e406796df746ef",
	"7fe5d91de235188486d8fb836a6da37e625e2b10eb6d144185b9364cc83cbbb6",
}

// deploymentModeThirdPartyAuditing is the mode byte mixed into every signature
// preimage (libsignal DeploymentMode::byte).
const deploymentModeThirdPartyAuditing = 3

type Source struct {
	cfg     Config
	client  *http.Client
	sigKey  []byte
	vrfKey  []byte
	auditor []byte
}

type Config struct {
	// Origin is the canonical checkpoint origin we mint for this auditor.
	Origin string

	// Endpoint defaults to Signal production.
	Endpoint string

	// AuditorKey is the hex Ed25519 key of the auditor this source tracks.
	AuditorKey string

	// SigningKey and VRFKey are the service's keys. They are not used to verify
	// anything directly here, but they are mixed into the signature preimage, so
	// getting them wrong makes every signature fail.
	SigningKey string
	VRFKey     string
}

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" || cfg.AuditorKey == "" {
		return nil, fmt.Errorf("signal: origin and auditor_key are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://chat.signal.org"
	}
	if cfg.SigningKey == "" {
		cfg.SigningKey = ProdSigningKey
	}
	if cfg.VRFKey == "" {
		cfg.VRFKey = ProdVRFKey
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")

	s := &Source{cfg: cfg}
	var err error
	if s.sigKey, err = decodeKey(cfg.SigningKey, "signing"); err != nil {
		return nil, err
	}
	if s.vrfKey, err = decodeKey(cfg.VRFKey, "VRF"); err != nil {
		return nil, err
	}
	if s.auditor, err = decodeKey(cfg.AuditorKey, "auditor"); err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(signalRoot)
	if err != nil {
		return nil, fmt.Errorf("signal: parse pinned root: %w", err)
	}
	roots.AddCert(cert)

	s.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Pinned, not added to the system pool: only Signal's own CA may
			// authenticate this host.
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
	return s, nil
}

func decodeKey(hexKey, kind string) ([]byte, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("signal: %s key not hex: %w", kind, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signal: %s key is %d bytes, want %d", kind, len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}

func (s *Source) Origin() string    { return s.cfg.Origin }
func (s *Source) Tier() source.Tier { return source.TierSignedHead }

// DerivedHead is false: the head is carried by an Ed25519 signature from the
// auditor, so a contradiction is the auditor contradicting its own key.
func (s *Source) DerivedHead() bool { return false }

// signable rebuilds the preimage libsignal signs (TreeHead::to_signable_header):
//
//	[0,0] ciphersuite ‖ mode ‖ len16‖signing_key ‖ len16‖vrf_key ‖
//	len16‖auditor_key ‖ tree_size u64be ‖ timestamp i64be ‖ root
//
// For an auditor tree head the signer and the embedded auditor key are the same
// key.
func (s *Source) signable(size uint64, timestamp int64, root []byte) []byte {
	var buf []byte
	buf = append(buf, 0, 0)
	buf = append(buf, deploymentModeThirdPartyAuditing)
	for _, k := range [][]byte{s.sigKey, s.vrfKey, s.auditor} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(k)))
		buf = append(buf, l[:]...)
		buf = append(buf, k...)
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], size)
	buf = append(buf, n[:]...)
	binary.BigEndian.PutUint64(n[:], uint64(timestamp))
	buf = append(buf, n[:]...)
	return append(buf, root...)
}

type auditorHead struct {
	treeSize  uint64
	timestamp int64
	root      []byte
}

func (s *Source) Fetch(ctx context.Context, _ *source.Head) (*source.Head, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.cfg.Endpoint+"/v1/key-transparency/distinguished", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signal: fetch distinguished: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signal: distinguished: HTTP %d", resp.StatusCode)
	}
	fetchedAt := time.Now()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var env struct {
		SerializedResponse string `json:"serializedResponse"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("signal: decode envelope: %w", err)
	}
	pb, err := base64.RawStdEncoding.DecodeString(env.SerializedResponse)
	if err != nil {
		return nil, fmt.Errorf("signal: decode serializedResponse: %w", err)
	}

	head, serviceSize, err := s.extract(pb)
	if err != nil {
		return nil, err
	}

	// An auditor claiming to be ahead of the service is incoherent; libsignal
	// rejects it too. Treated as unverifiable rather than as a fork, since we
	// cannot tell which of the two statements is the wrong one.
	if head.treeSize > serviceSize {
		return nil, fmt.Errorf("signal: auditor tree size %d exceeds service tree size %d",
			head.treeSize, serviceSize)
	}

	var hash tlog.Hash
	copy(hash[:], head.root)

	cp := torchwood.Checkpoint{
		Origin: s.cfg.Origin,
		Tree:   tlog.Tree{N: int64(head.treeSize), Hash: hash},
	}
	text := cp.String()
	return &source.Head{
		Origin:    s.cfg.Origin,
		Size:      int64(head.treeSize),
		Hash:      hash,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: fetchedAt,
	}, nil
}

// extract finds our auditor's tree head in the response and verifies its
// signature. It returns the service tree size alongside, for the coherence check.
func (s *Source) extract(pb []byte) (*auditorHead, uint64, error) {
	top := parse(pb)
	fthRaw := first(top, 1)
	if fthRaw == nil {
		return nil, 0, fmt.Errorf("signal: response has no FullTreeHead")
	}
	fth := parse(fthRaw)

	thRaw := first(fth, 1)
	if thRaw == nil {
		return nil, 0, fmt.Errorf("signal: response has no TreeHead")
	}
	th := parse(thRaw)
	serviceSize := varintOf(th, 1)

	for _, faRaw := range fth[4] {
		fa := parse(faRaw)
		pub := first(fa, 4)
		if pub == nil || !equalBytes(pub, s.auditor) {
			continue
		}
		root := first(fa, 2)
		if len(root) != 32 {
			return nil, 0, fmt.Errorf("signal: auditor root is %d bytes, want 32", len(root))
		}
		ahRaw := first(fa, 1)
		if ahRaw == nil {
			return nil, 0, fmt.Errorf("signal: auditor entry has no tree head")
		}
		ah := parse(ahRaw)
		size := varintOf(ah, 1)
		ts := int64(varintOf(ah, 2))
		sig := first(ah, 3)
		if len(sig) != ed25519.SignatureSize {
			return nil, 0, fmt.Errorf("signal: auditor signature is %d bytes, want %d",
				len(sig), ed25519.SignatureSize)
		}

		if !ed25519.Verify(ed25519.PublicKey(s.auditor), s.signable(size, ts, root), sig) {
			// The response is not authentic for this auditor. Withhold; we
			// cannot attribute it, so it is not evidence against anyone.
			return nil, 0, fmt.Errorf("signal: auditor %s: signature does not verify over tree head (size %d)",
				s.cfg.AuditorKey[:16], size)
		}
		return &auditorHead{treeSize: size, timestamp: ts, root: root}, serviceSize, nil
	}
	return nil, 0, fmt.Errorf("signal: no tree head from auditor %s in response", s.cfg.AuditorKey[:16])
}

// VerifyConsistency has nothing further to prove at this tier.
//
// Proving append-only between two auditor heads needs a consistency proof
// between their tree sizes. Signal's public API supplies consistency proofs only
// against the service tree, whose root is not served and must be reconstructed
// from the combined-tree search proof — not implemented here.
//
// What still holds, enforced by the witness core rather than by this function:
// the auditor's tree size may not go backwards, and two different roots signed
// at the same tree size are a conclusive contradiction. That is equivocation
// detection; it is not an append-only proof, and Tier() says so.
func (s *Source) VerifyConsistency(context.Context, *source.Head, *source.Head) error {
	return nil
}

// --- minimal protobuf reader -------------------------------------------------
//
// Hand-rolled rather than generated: we need four field numbers from two nested
// messages, and a hand-written reader is small enough to audit in full, which
// matters more here than convenience.

type message map[int][][]byte

func parse(b []byte) message {
	out := message{}
	i := 0
	for i < len(b) {
		k, ni, ok := uvarint(b, i)
		if !ok {
			return out
		}
		i = ni
		field, wire := int(k>>3), k&7
		switch wire {
		case 0:
			v, ni, ok := uvarint(b, i)
			if !ok {
				return out
			}
			i = ni
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], v)
			out[field] = append(out[field], buf[:])
		case 2:
			n, ni, ok := uvarint(b, i)
			if !ok || ni+int(n) > len(b) {
				return out
			}
			i = ni
			out[field] = append(out[field], b[i:i+int(n)])
			i += int(n)
		case 5:
			i += 4
		case 1:
			i += 8
		default:
			return out
		}
	}
	return out
}

func uvarint(b []byte, i int) (uint64, int, bool) {
	var s uint64
	var sh uint
	for {
		if i >= len(b) || sh > 63 {
			return 0, i, false
		}
		x := b[i]
		i++
		s |= uint64(x&0x7f) << sh
		if x&0x80 == 0 {
			return s, i, true
		}
		sh += 7
	}
}

func first(m message, field int) []byte {
	if v := m[field]; len(v) > 0 {
		return v[0]
	}
	return nil
}

func varintOf(m message, field int) uint64 {
	v := first(m, field)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
