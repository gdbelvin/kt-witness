// Package hsm signs with a key held in a YubiHSM 2, reached over the HTTP
// interface of Yubico's yubihsm-connector.
//
// Why the connector and not PKCS#11: the witness image is CGO_ENABLED=0 on
// distroless/static, and yubihsm_pkcs11.so is a shared library reached through
// cgo. Speaking the session protocol in Go keeps the binary static and keeps
// USB out of the container — the connector owns the device, the witness owns a
// password.
//
// The private key never leaves the device. This package holds a public key and
// a session; a compromise of this process is a signing oracle for as long as it
// lasts, not a key disclosure.
package hsm

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

// ErrUnavailable reports that the signer could not be reached or could not
// sign. It is deliberately its own error: an HSM outage fails every origin at
// once, and so does a catastrophic ecosystem event. The witness must be able to
// tell those apart before it decides what to log, what to alert on, and whether
// any log actually misbehaved.
var ErrUnavailable = errors.New("hsm: signer unavailable")

// Config names the device-side objects. None of these are secret except
// Password, which comes from an environment variable populated by a file the
// operator owns.
type Config struct {
	// ConnectorURL is yubihsm-connector's address. Either "host:port" or
	// "http://host:port" — a scheme is stripped, because the connector's own
	// config file writes a bare host:port while every other reference to it
	// here is a URL, and an operator should not have to know which form this
	// field wants.
	ConnectorURL string

	// AuthKeyID is the authentication key the witness opens sessions with. It
	// should hold sign-eddsa and nothing else.
	AuthKeyID uint16

	// Password authenticates AuthKeyID.
	Password string

	// KeyID is the asymmetric key object to sign with.
	KeyID uint16
}

// Signer is a crypto.Signer backed by a YubiHSM object. It satisfies what
// torchwood's cosignature signer asks for: an Ed25519 Public() and a Sign that
// takes the whole message with crypto.Hash(0).
type Signer struct {
	cfg Config
	pub ed25519.PublicKey

	mu sync.Mutex
	sm session
}

// session is the part of yubihsm.SessionManager this package uses.
//
// It exists so the logic here — labelling transport failures, refusing a
// prehash, checking what the device says its key is — can be tested without
// hardware. The session protocol itself is the library's job and is verified
// against the real device by the KT_HSM_LIVE test; faking it at the HTTP layer
// would mean reimplementing its cryptography to test our error handling, which
// would prove nothing about either.
type session interface {
	SendEncryptedCommand(*commands.CommandMessage) (commands.Response, error)
	Destroy()
}

// Open connects, reads the public key of cfg.KeyID, and returns a Signer.
//
// Reading the public key is not a convenience: it is the only way to know which
// identity this device will sign as, and the caller is expected to compare it
// with the verifier key it publishes. Starting up as a different party is worse
// than not starting at all, and unlike a rename it cannot be repaired — nothing
// the old key attested can be re-attested by a new one.
func Open(cfg Config) (*Signer, error) {
	if cfg.ConnectorURL == "" || cfg.AuthKeyID == 0 || cfg.KeyID == 0 || cfg.Password == "" {
		return nil, fmt.Errorf("%w: incomplete configuration", ErrUnavailable)
	}
	addr, err := connectorAddr(cfg.ConnectorURL)
	if err != nil {
		return nil, err
	}
	c := connector.NewHTTPConnector(addr)
	sm, err := yubihsm.NewSessionManager(c, cfg.AuthKeyID, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: authenticate key 0x%04x: %w", ErrUnavailable, cfg.AuthKeyID, err)
	}
	return newSigner(cfg, sm)
}

// newSigner completes construction against any session, which is what lets the
// tests drive the same path Open does.
func newSigner(cfg Config, sm session) (*Signer, error) {
	s := &Signer{cfg: cfg, sm: sm}
	pub, err := s.publicKey()
	if err != nil {
		sm.Destroy()
		return nil, err
	}
	s.pub = pub
	return s, nil
}

func (s *Signer) publicKey() (ed25519.PublicKey, error) {
	cmd, err := commands.CreateGetPubKeyCommand(s.cfg.KeyID)
	if err != nil {
		return nil, fmt.Errorf("hsm: build get-public-key: %w", err)
	}
	resp, err := s.send(cmd)
	if err != nil {
		return nil, err
	}
	parsed, ok := resp.(*commands.GetPubKeyResponse)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected response %T to get-public-key", ErrUnavailable, resp)
	}
	if parsed.Algorithm != commands.AlgorithmED25519 {
		return nil, fmt.Errorf("hsm: object 0x%04x is algorithm %d, want ed25519", s.cfg.KeyID, parsed.Algorithm)
	}
	if len(parsed.KeyData) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hsm: object 0x%04x returned a %d-byte public key, want %d",
			s.cfg.KeyID, len(parsed.KeyData), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(parsed.KeyData), nil
}

// Public returns the Ed25519 public key read from the device at Open.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign issues sign-eddsa on the device.
//
// opts must ask for no hashing: Ed25519 signs the message itself, and torchwood
// calls this with crypto.Hash(0) and the full cosignature/v1 message. Ed25519ph
// is not supported by the YubiHSM, so a caller asking for a prehash is refused
// rather than silently given a signature over the wrong thing.
func (s *Signer) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("hsm: Ed25519 signs the message, not a %s digest", opts.HashFunc())
	}
	cmd, err := commands.CreateSignDataEddsaCommand(s.cfg.KeyID, message)
	if err != nil {
		return nil, fmt.Errorf("hsm: build sign-eddsa: %w", err)
	}
	resp, err := s.send(cmd)
	if err != nil {
		return nil, err
	}
	parsed, ok := resp.(*commands.SignDataEddsaResponse)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected response %T to sign-eddsa", ErrUnavailable, resp)
	}
	if len(parsed.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("hsm: device returned a %d-byte signature, want %d",
			len(parsed.Signature), ed25519.SignatureSize)
	}
	return parsed.Signature, nil
}

// send serialises access to the session manager and labels every transport
// failure as ErrUnavailable, so callers can distinguish "we could not sign" from
// "this log misbehaved" without matching on strings.
func (s *Signer) send(cmd *commands.CommandMessage) (commands.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp, err := s.sm.SendEncryptedCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return resp, nil
}

// Alive reports whether the device is reachable right now.
//
// This is the round's pre-flight. An unreachable signer fails every origin
// identically, which is indistinguishable from every log equivocating at once
// unless it is detected before the per-origin loop starts — so the witness asks
// once, skips the round, and leaves every origin's failure counters untouched.
func (s *Signer) Alive() error {
	cmd, err := commands.CreateEchoCommand([]byte("kt-witness"))
	if err != nil {
		return fmt.Errorf("hsm: build echo: %w", err)
	}
	_, err = s.send(cmd)
	return err
}

// Close tears down the session. The device expires it anyway after inactivity;
// this just does not wait.
func (s *Signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sm != nil {
		s.sm.Destroy()
		s.sm = nil
	}
}

// connectorAddr reduces whatever the operator wrote to the host:port the client
// wants.
//
// The client builds "http://" + addr + "/connector/api" itself, so handing it a
// URL produces "http://http//host:port/connector/api" and a DNS lookup for the
// host "http" — which is what the first containerised run of this package did.
// The error names a resolver failure and says nothing about a malformed
// address, so it is worth normalising here rather than leaving to a reader.
func connectorAddr(s string) (string, error) {
	if strings.HasPrefix(s, "https://") {
		return "", fmt.Errorf("%w: connector address %q uses https, which this client does not speak; terminate TLS in front of it or use http", ErrUnavailable, s)
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/connector/api")
	s = strings.TrimSuffix(s, "/")
	if s == "" || strings.Contains(s, "/") {
		return "", fmt.Errorf("%w: %q is not a host:port", ErrUnavailable, s)
	}
	return s, nil
}
