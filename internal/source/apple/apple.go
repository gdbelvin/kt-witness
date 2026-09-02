// Package apple witnesses Apple's Key Transparency Top-Level Tree.
//
// # This surface exists, contrary to the usual account of it
//
// Apple's public position is that Contact Key Verification is verified on-device
// and that a "public auditing strategy" was coming in 2024. That strategy was
// never published — but the infrastructure is live and reachable today with no
// Apple ID, no device, and no coordination:
//
//	POST https://kttcc-prod.ess.apple.com/at_researcher/log_head
//
// found via Apple's own bootstrap bag (init-kt.apple.com/init/getBag?ix=3&p=atresearch),
// which supplies URLs only — no credentials. It returns ECDSA-P256 signed tree
// heads that verify against a pinned public key.
//
// # What can and cannot be witnessed
//
// The public listing exposes the shared TOP_LEVEL_TREE and the
// PRIVATE_CLOUD_COMPUTE application trees. It does NOT expose the
// IDS_MESSAGING (application 1) tree, and the iMessage client endpoints require
// device attestation plus Apple ID auth.
//
// So this witnesses the shared root that iMessage's log is committed into — not
// iMessage's own tree. That is worth having and worth not overstating.
//
// # Why tier S
//
// Apple's consistency_proof endpoint rejects every size-to-size range: its own
// auditor reconstructs consistency from log_leaves and a revision tree instead.
// So append-only between observations cannot be proven here, only authenticity
// and equivocation at a given size. See NOTES.md.
package apple

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/pbwire"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// TopLevelTreeID is the shared tree every application's log commits into.
const TopLevelTreeID = 410322746470160

// TopLevelTreePublicKey is the DER SPKI (EC P-256) for the Top-Level Tree.
//
// Pinned deliberately. The key is also served by list_trees — the same endpoint
// that serves the heads — so trusting it from there would be circular: whoever
// could lie about a head could lie about the key that authenticates it.
const TopLevelTreePublicKey = "3059301306072a8648ce3d020106082a8648ce3d030107034200049b18e1d0" +
	"f1de8644c97b009e4c877c4b688951fc30e59d36d9d89019c548fd8cdd24e99cbffb128df88c9ef811f873" +
	"53a15e5e983b4073583d9fdaa0d6d71c7c"

// requestVersion is the API version field Apple's own client sends.
const requestVersion = 3

// latestRevision asks for the current head.
//
// This must be sent explicitly. Omitting the field defaults it to 0, and the
// server then answers HTTP 200 with the head of the *empty* tree — size 0 and
// the SHA-256 of the empty string. A silently wrong answer, not an error.
const latestRevision = int64(-1)

type Source struct {
	cfg    Config
	client *http.Client
	pub    *ecdsa.PublicKey
	pubDER []byte
	keyID  [32]byte
}

type Config struct {
	// Origin is the canonical checkpoint origin we mint.
	Origin string

	// Endpoint defaults to Apple's researcher API.
	Endpoint string

	// TreeID defaults to the Top-Level Tree.
	TreeID uint64

	// PublicKeyDER is the hex DER SPKI to pin. Defaults to the Top-Level Tree's.
	PublicKeyDER string
}

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" {
		return nil, fmt.Errorf("apple: origin is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://kttcc-prod.ess.apple.com/at_researcher"
	}
	if cfg.TreeID == 0 {
		cfg.TreeID = TopLevelTreeID
	}
	if cfg.PublicKeyDER == "" {
		cfg.PublicKeyDER = TopLevelTreePublicKey
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")

	der, err := hex.DecodeString(cfg.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("apple: public key not hex: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("apple: parse public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("apple: public key is %T, want ECDSA", parsed)
	}

	return &Source{
		cfg: cfg, pub: pub, pubDER: der,
		keyID:  sha256.Sum256(der),
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *Source) Origin() string    { return s.cfg.Origin }
func (s *Source) Tier() source.Tier { return source.TierSignedHead }

// DerivedHead is false: the head carries Apple's ECDSA signature, so a
// contradiction is Apple contradicting its own key.
func (s *Source) DerivedHead() bool { return false }

// logHeadRequest builds LogHeadRequest{version, treeId, revision}.
func (s *Source) logHeadRequest() []byte {
	var b []byte
	b = pbwire.AppendTag(b, 1, 0)
	b = pbwire.AppendVarint(b, requestVersion)
	b = pbwire.AppendTag(b, 2, 0)
	b = pbwire.AppendVarint(b, s.cfg.TreeID)
	b = pbwire.AppendTag(b, 4, 0)
	// int64 -1 encodes as a 10-byte varint of its two's-complement value. Via a
	// variable because converting the constant directly is a compile error.
	rev := latestRevision
	b = pbwire.AppendVarint(b, uint64(rev))
	return b
}

func (s *Source) Fetch(ctx context.Context, _ *source.Head) (*source.Head, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.Endpoint+"/log_head", bytes.NewReader(s.logHeadRequest()))
	if err != nil {
		return nil, err
	}
	// Only this content type is accepted; application/octet-stream is rejected.
	req.Header.Set("Content-Type", "application/protobuf")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apple: log_head: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple: log_head: HTTP %d", resp.StatusCode)
	}
	fetchedAt := time.Now()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	size, root, err := s.verifyLogHead(body)
	if err != nil {
		return nil, err
	}

	var h tlog.Hash
	copy(h[:], root)
	cp := torchwood.Checkpoint{Origin: s.cfg.Origin, Tree: tlog.Tree{N: int64(size), Hash: h}}
	text := cp.String()
	return &source.Head{
		Origin:    s.cfg.Origin,
		Size:      int64(size),
		Hash:      h,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: fetchedAt,
	}, nil
}

// verifyLogHead checks Apple's signature over the tree head and returns the
// attested size and root.
func (s *Source) verifyLogHead(body []byte) (uint64, []byte, error) {
	// LogHeadResponse{status = 1, logHead = 4}. Note field 4, not 2.
	resp := pbwire.Parse(body)
	signedObj := pbwire.First(resp, 4)
	if signedObj == nil {
		return 0, nil, fmt.Errorf("apple: response carries no log head (status %d)",
			pbwire.Uint64(resp, 1))
	}

	// SignedObject{object = 1, signature = 2}.
	so := pbwire.Parse(signedObj)
	obj := pbwire.First(so, 1)
	sigMsg := pbwire.First(so, 2)
	if obj == nil || sigMsg == nil {
		return 0, nil, fmt.Errorf("apple: malformed SignedObject")
	}

	// Signature{signature = 1, signingKeySPKIHash = 2, algorithm = 3}.
	sm := pbwire.Parse(sigMsg)
	sig := pbwire.First(sm, 1)
	keyHash := pbwire.First(sm, 2)
	if alg := pbwire.Uint64(sm, 3); alg != 1 {
		return 0, nil, fmt.Errorf("apple: signature algorithm %d, want 1 (ECDSA_SHA256)", alg)
	}
	if len(keyHash) != 32 || !bytes.Equal(keyHash, s.keyID[:]) {
		return 0, nil, fmt.Errorf("apple: head signed by key %x, not the pinned key %x",
			keyHash, s.keyID[:8])
	}

	// The signature covers the inner object bytes exactly as transmitted, so
	// they are verified as received and never re-serialized: protobuf encoding
	// is not guaranteed to round-trip byte-for-byte.
	digest := sha256.Sum256(obj)
	if !ecdsa.VerifyASN1(s.pub, digest[:], sig) {
		return 0, nil, fmt.Errorf("apple: signature does not verify over the tree head")
	}

	// LogHead{logSize = 2, logHeadHash = 3, revision = 4, logType = 5, treeId = 7}.
	lh := pbwire.Parse(obj)
	size := pbwire.Uint64(lh, 2)
	root := pbwire.First(lh, 3)
	treeID := pbwire.Uint64(lh, 7)

	if treeID != s.cfg.TreeID {
		return 0, nil, fmt.Errorf("apple: head is for tree %d, expected %d", treeID, s.cfg.TreeID)
	}
	if len(root) != 32 {
		return 0, nil, fmt.Errorf("apple: log head hash is %d bytes, want 32", len(root))
	}
	if size == 0 {
		// The empty-tree head, which is what the server returns — signed, with
		// HTTP 200 — when the revision field is missing. Correctly signed and
		// completely useless, so it is rejected explicitly rather than being
		// witnessed as a real head that later appears to regress.
		return 0, nil, fmt.Errorf("apple: server returned the empty tree head; " +
			"the request is missing an explicit revision")
	}
	return size, root, nil
}

// VerifyConsistency has nothing further to prove at this tier.
//
// Apple's consistency_proof rejects every size-to-size range; its own auditor
// rebuilds consistency from log_leaves and a revision tree instead, which is not
// implemented here. What still holds, enforced by the witness core: the tree
// size may not go backwards, and two different roots signed at the same size are
// a conclusive contradiction. Tier() says exactly this much and no more.
func (s *Source) VerifyConsistency(context.Context, *source.Head, *source.Head) error {
	return nil
}
