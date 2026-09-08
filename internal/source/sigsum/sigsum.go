// Package sigsum witnesses sigsum logs.
//
// # Why this turned out to be small
//
// sigsum looked like a third ecosystem needing its own cryptography, and the
// open question in TODO.md was whether to join the sigsum witness network or
// reimplement its protocol. Reading sigsum-go settles it: neither. Modern
// sigsum signs a C2SP checkpoint body,
//
//	sigsum.org/v1/tree/<hex sha256(log public key)>
//	<size>
//	<base64 root hash>
//
// with plain Ed25519 — no SSH wrapper, no prehashing — and its cosignatures are
// literally `cosignature/v1`, the construction this project already implements
// and has verified against two independent witnesses. sigsum is therefore not a
// separate ecosystem at all. It is a C2SP signed-note log wearing an ASCII
// transport.
//
// So this package is a transcoder, not a verifier. It parses the ASCII
// `get-tree-head` response, reconstructs the checkpoint body the log actually
// signed, checks the log's signature over it, and synthesizes the equivalent
// signed note. Everything downstream — cosigning, publication, the store — then
// treats sigsum exactly like any other note-carrying log.
//
// # Why the note is synthesized rather than fetched
//
// sigsum does not serve its checkpoint in note form; it serves the same
// information as key=value lines. Rebuilding the note locally is safe here
// precisely because the body is fully determined by the response: the origin is
// a function of the log's pinned public key, and the size and root come from
// the response whose signature we then check against that reconstruction. If
// any of those three were wrong, the signature would not verify. The note is a
// re-encoding of verified data, never a claim we invented.
//
// # Assurance
//
// Tier A. sigsum serves `get-consistency-proof/<old>/<new>`, so append-only
// between observations is proven, and a failure there is a genuine
// self-contradiction by the log. sigsum is an append-only log of signed
// checksums rather than a key directory, so there is no separate construction
// step to audit and no higher tier to reach here.
package sigsum

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// CheckpointNamePrefix and the origin construction come from sigsum-go's
// types.SigsumCheckpointOrigin. The origin is derived from the log's key, so a
// log cannot choose a name that collides with another's.
const CheckpointNamePrefix = "sigsum.org/v1/tree/"

// OriginFor returns the checkpoint origin for a log public key.
func OriginFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return CheckpointNamePrefix + hex.EncodeToString(sum[:])
}

// TreeHead is a parsed get-tree-head response.
type TreeHead struct {
	Size      uint64
	RootHash  [32]byte
	Signature []byte

	// Cosignatures are the witness cosignatures the log chose to attach, keyed
	// by witness key hash. Retained as corroboration only: like every
	// cosignature read off a document we fetched ourselves, they sit over the
	// same body as the log's own signature and so agree by construction. They
	// cannot detect a split view. See internal/cosig.
	Cosignatures map[string]Cosignature
}

// Cosignature is one witness's countersignature on a tree head.
type Cosignature struct {
	KeyHash   string
	Timestamp uint64
	Signature []byte
}

// Body returns the checkpoint body the log signs: exactly the bytes passed to
// Ed25519, trailing newline included.
func (th *TreeHead) Body(origin string) string {
	return fmt.Sprintf("%s\n%d\n%s\n",
		origin, th.Size, base64.StdEncoding.EncodeToString(th.RootHash[:]))
}

// ParseTreeHead reads sigsum's ASCII key=value response.
//
// Unknown keys are ignored rather than rejected: sigsum has added fields before
// and a witness that refuses to parse a response because it learned something
// new is a witness that stops working on an upstream release.
func ParseTreeHead(r io.Reader) (*TreeHead, error) {
	th := &TreeHead{Cosignatures: map[string]Cosignature{}}
	var sawSize, sawRoot, sawSig bool

	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("sigsum: malformed line %q", line)
		}
		switch key {
		case "size":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("sigsum: size %q: %w", val, err)
			}
			th.Size, sawSize = n, true
		case "root_hash":
			b, err := hex.DecodeString(val)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("sigsum: root_hash %q is not 32 hex bytes", val)
			}
			copy(th.RootHash[:], b)
			sawRoot = true
		case "signature":
			b, err := hex.DecodeString(val)
			if err != nil || len(b) != ed25519.SignatureSize {
				return nil, fmt.Errorf("sigsum: signature %q is not %d hex bytes", val, ed25519.SignatureSize)
			}
			th.Signature, sawSig = b, true
		case "cosignature":
			cs, err := parseCosignature(val)
			if err != nil {
				// One malformed cosignature is not a reason to discard a tree
				// head that is otherwise fully verifiable. Cosignatures are
				// corroboration here, not the assertion.
				continue
			}
			th.Cosignatures[cs.KeyHash] = cs
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("sigsum: reading response: %w", err)
	}
	if !sawSize || !sawRoot || !sawSig {
		return nil, fmt.Errorf("sigsum: response missing size, root_hash or signature")
	}
	return th, nil
}

// parseCosignature reads "<keyhash hex> <timestamp> <signature hex>".
func parseCosignature(val string) (Cosignature, error) {
	f := strings.Fields(val)
	if len(f) != 3 {
		return Cosignature{}, fmt.Errorf("sigsum: cosignature has %d fields, want 3", len(f))
	}
	ts, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return Cosignature{}, err
	}
	sig, err := hex.DecodeString(f[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Cosignature{}, fmt.Errorf("sigsum: cosignature signature malformed")
	}
	return Cosignature{KeyHash: f[0], Timestamp: ts, Signature: sig}, nil
}

// noteKeyID is the standard signed-note key hash: SHA-256 over the signer name,
// a newline, the algorithm byte, and the key.
//
// Unlike CT and Rekor — each of which needed its own bespoke key-hash rule —
// sigsum uses the plain note convention, which is what lets the synthesized
// note be opened by any stock note verifier.
func noteKeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', 0x01})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

// Config configures one witnessed sigsum log.
type Config struct {
	// Endpoint is the log's base URL, e.g. https://seasalp.glasklar.is.
	Endpoint string

	// PublicKey is the log's Ed25519 key, pinned by the operator. The origin is
	// derived from it, so this is the log's identity: there is no way to point
	// this adapter at a log without knowing which log it is.
	PublicKey ed25519.PublicKey

	Client *http.Client
}

// Source witnesses one sigsum log.
type Source struct {
	cfg      Config
	origin   string
	verifier note.Verifier
	client   *http.Client
}

var _ source.Source = (*Source)(nil)

func New(cfg Config) (*Source, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("sigsum: endpoint is required")
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sigsum: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(cfg.PublicKey))
	}
	origin := OriginFor(cfg.PublicKey)

	// A stock note verifier, so the synthesized note is openable by anything
	// that speaks notes rather than only by this package.
	v := &verifier{name: origin, keyHash: noteKeyID(origin, cfg.PublicKey), pub: cfg.PublicKey}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Source{
		cfg:      cfg,
		origin:   origin,
		verifier: v,
		client:   client,
	}, nil
}

func (s *Source) Origin() string          { return s.origin }
func (s *Source) Tier() source.Tier       { return source.TierA }
func (s *Source) DerivedHead() bool       { return false }
func (s *Source) Verifier() note.Verifier { return s.verifier }

// verifier is a plain Ed25519 note verifier over the sigsum origin.
type verifier struct {
	name    string
	keyHash uint32
	pub     ed25519.PublicKey
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.keyHash }
func (v *verifier) Verify(msg, sig []byte) bool { return ed25519.Verify(v.pub, msg, sig) }

// Fetch reads and verifies the log's current tree head.
func (s *Source) Fetch(ctx context.Context, _ *source.Head) (*source.Head, error) {
	th, err := s.getTreeHead(ctx)
	if err != nil {
		return nil, err
	}

	body := th.Body(s.origin)
	if !ed25519.Verify(s.cfg.PublicKey, []byte(body), th.Signature) {
		// The log's own signature does not cover the head it served. This is
		// not a fork — it is a head we cannot authenticate at all — so the
		// witness withholds rather than accuses.
		return nil, fmt.Errorf("sigsum: %s: log signature does not verify over size %d",
			s.origin, th.Size)
	}

	signed := fmt.Sprintf("%s\n— %s %s\n", body, s.origin,
		base64.StdEncoding.EncodeToString(sigLine(s.verifier.KeyHash(), th.Signature)))

	n, err := note.Open([]byte(signed), note.VerifierList(s.verifier))
	if err != nil {
		return nil, fmt.Errorf("sigsum: synthesized note did not verify: %w", err)
	}

	var h tlog.Hash
	copy(h[:], th.RootHash[:])
	// The cosignatures the log attached, surfaced by key hash. They cannot be
	// folded into the synthesised note — that format is keyed by name and
	// sigsum's is keyed by hash — but dropping them entirely is how twelve
	// witnesses on one log came to be invisible.
	cosigners := make([]string, 0, len(th.Cosignatures))
	for kh := range th.Cosignatures {
		cosigners = append(cosigners, "keyhash:"+kh)
	}
	sort.Strings(cosigners)

	return &source.Head{
		Origin:    s.origin,
		Size:      int64(th.Size),
		Hash:      h,
		Signed:    []byte(signed),
		Note:      n,
		Cosigners: cosigners,
		FetchedAt: time.Now().UTC(),
	}, nil
}

// sigLine is the note signature payload: the 4-byte key hash followed by the
// signature.
func sigLine(keyHash uint32, sig []byte) []byte {
	out := make([]byte, 4, 4+len(sig))
	binary.BigEndian.PutUint32(out, keyHash)
	return append(out, sig...)
}

// VerifyConsistency proves next extends prev using the log's own proof.
func (s *Source) VerifyConsistency(ctx context.Context, prev, next *source.Head) error {
	if prev == nil || prev.Size == 0 || prev.Size == next.Size {
		// Trust on first use. sigsum serves no tiles, so unlike the C2SP
		// adapter there is no independent structure to spot-check here; the
		// signature over the head is all we have on the first observation.
		return nil
	}
	if next.Size < prev.Size {
		return &source.ForkError{
			Origin: s.origin,
			Reason: fmt.Sprintf("tree shrank: signed size %d is below witnessed size %d",
				next.Size, prev.Size),
			Prev: prev, Next: next,
		}
	}

	proof, err := s.getConsistencyProof(ctx, prev.Size, next.Size)
	if err != nil {
		// No proof is not evidence of misbehaviour. Withhold and retry.
		return fmt.Errorf("sigsum: consistency proof %d->%d: %w", prev.Size, next.Size, err)
	}
	if err := tlog.CheckTree(proof, next.Size, next.Hash, prev.Size, prev.Hash); err != nil {
		// The log signed both heads, and they are not append-only compatible.
		// That is the log contradicting itself, and it is conclusive.
		return &source.ForkError{
			Origin: s.origin,
			Reason: fmt.Sprintf("consistency proof %d->%d failed: size %d (root %x) does not extend witnessed size %d (root %x): %v",
				prev.Size, next.Size, next.Size, next.Hash[:], prev.Size, prev.Hash[:], err),
			Prev: prev, Next: next,
		}
	}
	return nil
}

// --- transport -------------------------------------------------------------

func (s *Source) get(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return resp.Body, nil
}

func (s *Source) getTreeHead(ctx context.Context) (*TreeHead, error) {
	body, err := s.get(ctx, "/get-tree-head")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ParseTreeHead(body)
}

// getConsistencyProof reads the node_hash lines sigsum returns.
func (s *Source) getConsistencyProof(ctx context.Context, old, new int64) (tlog.TreeProof, error) {
	body, err := s.get(ctx, fmt.Sprintf("/get-consistency-proof/%d/%d", old, new))
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ParseProof(body)
}

// ParseProof reads a sigsum proof response into a tlog proof.
//
// sigsum uses RFC 6962 Merkle hashing, which is the same construction
// golang.org/x/mod/sumdb/tlog implements, so the node list transfers directly.
func ParseProof(r io.Reader) (tlog.TreeProof, error) {
	var out tlog.TreeProof
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || key != "node_hash" {
			continue
		}
		b, err := hex.DecodeString(val)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("sigsum: node_hash %q is not 32 hex bytes", val)
		}
		var h tlog.Hash
		copy(h[:], b)
		out = append(out, h)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
