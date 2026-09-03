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
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
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

// appleRoot is the Apple Root CA.
//
// kttcc-prod.ess.apple.com is issued by "Apple Server Authentication CA", a
// private Apple CA that chains to this root rather than to a public one. macOS
// trusts it from the system keychain, so this works on a Mac and fails in any
// container with only a public CA bundle — a difference that shows up at deploy
// time, not in development. Pinned rather than trusted from the host, since only
// Apple's own CA should be able to authenticate this host.
//
// SHA-256: b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024
//
//go:embed apple-root.cer
var appleRoot []byte

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

	// latest caches the most recent verified head, so the revision behind a
	// witnessed size is usually known without searching for it.
	latest *treeState
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

	// ClientEndpoint is the at_client surface, which serves consistency proofs.
	// Defaults to the at_client path on the same host as Endpoint.
	ClientEndpoint string

	// LogType and Application name the tree in consistency requests, which are
	// keyed by those rather than by TreeID. They default to the Top-Level Tree.
	//
	// Getting these wrong does not fail: Apple answers about whichever tree the
	// request names, so a stale LogType returns a perfectly valid proof about
	// the wrong log. That is why they are explicit rather than inferred.
	LogType     uint64
	Application uint64
}

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" {
		return nil, fmt.Errorf("apple: origin is required")
	}
	// A minted origin is a name we invent, so it has to be the name everyone
	// else invents: cosignatures aggregate by origin, and a private spelling
	// produces attestations nobody can combine with another witness's.
	if err := source.CheckMintedOrigin(cfg.Origin); err != nil {
		return nil, err
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
	if cfg.LogType == 0 {
		cfg.LogType = logTypeTopLevelTree
	}
	if cfg.TreeID != TopLevelTreeID && cfg.Application == 0 {
		// Only the Top-Level Tree is application-agnostic; every other tree must
		// say which application it belongs to or the request is rejected.
		return nil, fmt.Errorf("apple: tree %d needs an application", cfg.TreeID)
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

	roots := x509.NewCertPool()
	rootCert, err := x509.ParseCertificate(appleRoot)
	if err != nil {
		return nil, fmt.Errorf("apple: parse pinned root CA: %w", err)
	}
	roots.AddCert(rootCert)

	return &Source{
		cfg: cfg, pub: pub, pubDER: der,
		keyID: sha256.Sum256(der),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: netmeter.Wrap(&http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			}, cfg.Origin),
		},
	}, nil
}

func (s *Source) Origin() string    { return s.cfg.Origin }
func (s *Source) Tier() source.Tier { return source.TierA }

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

	st, err := s.verifyHeadResponse(body)
	if err != nil {
		return nil, err
	}
	s.latest = st

	cp := torchwood.Checkpoint{Origin: s.cfg.Origin, Tree: tlog.Tree{N: int64(st.size), Hash: st.root}}
	text := cp.String()
	return &source.Head{
		Origin:    s.cfg.Origin,
		Size:      int64(st.size),
		Hash:      st.root,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: fetchedAt,
	}, nil
}

// verifyHeadResponse verifies a LogHeadResponse and returns the head it carries.
func (s *Source) verifyHeadResponse(body []byte) (*treeState, error) {
	// LogHeadResponse{status = 1, logHead = 4}. Note field 4, not 2.
	resp := pbwire.Parse(body)
	signedObj := pbwire.First(resp, 4)
	if signedObj == nil {
		return nil, fmt.Errorf("apple: response carries no log head (status %d)",
			pbwire.Uint64(resp, 1))
	}
	return s.verifySignedHead(signedObj)
}

// VerifyConsistency proves the new tree extends the one we witnessed.
//
// Both endpoints of the proof are signed heads verified against the pinned key,
// and the proof itself is checked with RFC 6962 consistency verification —
// confirmed empirically to be Apple's construction by checking a production
// proof against golang.org/x/mod/sumdb/tlog.
//
// The server may split a range into several adjoining proofs, so they are
// chained: each must start where the previous ended, and the chain must run from
// the head we witnessed to the head we are about to attest.
func (s *Source) VerifyConsistency(ctx context.Context, prev, next *source.Head) error {
	if prev == nil {
		return nil // trust on first use
	}

	startRev, err := s.revisionForSize(ctx, uint64(prev.Size), s.latest)
	if err != nil {
		return fmt.Errorf("apple: locating revision for witnessed size %d: %w", prev.Size, err)
	}
	endRev := uint64(0)
	if s.latest != nil && s.latest.size == uint64(next.Size) {
		endRev = s.latest.revision
	} else {
		if endRev, err = s.revisionForSize(ctx, uint64(next.Size), s.latest); err != nil {
			return fmt.Errorf("apple: locating revision for size %d: %w", next.Size, err)
		}
	}
	if startRev >= endRev {
		return fmt.Errorf("apple: revisions do not advance (%d -> %d)", startRev, endRev)
	}

	body, err := s.postTo(ctx, s.clientBase(), consistencyEndpoint, s.consistencyRequest(startRev, endRev))
	if err != nil {
		return err
	}
	resp := pbwire.Parse(body)
	if st := pbwire.Uint64(resp, 1); st != 1 {
		return fmt.Errorf("apple: consistency proof %d->%d: status %d", startRev, endRev, st)
	}
	if len(resp[3]) == 0 {
		return fmt.Errorf("apple: consistency proof %d->%d: no proofs returned", startRev, endRev)
	}

	cur := &treeState{size: uint64(prev.Size), root: prev.Hash}
	for i, segRaw := range resp[3] {
		seg := pbwire.Parse(segRaw)
		from, err := s.verifySignedHead(pbwire.First(seg, 3))
		if err != nil {
			return fmt.Errorf("apple: proof segment %d start head: %w", i, err)
		}
		to, err := s.verifySignedHead(pbwire.First(seg, 4))
		if err != nil {
			return fmt.Errorf("apple: proof segment %d end head: %w", i, err)
		}
		if from.size != cur.size || from.root != cur.root {
			return fmt.Errorf("apple: proof segment %d starts at size %d, expected %d (chain broken)",
				i, from.size, cur.size)
		}

		var proof tlog.TreeProof
		for _, h := range seg[5] {
			if len(h) != 32 {
				return fmt.Errorf("apple: proof hash is %d bytes, want 32", len(h))
			}
			var ph tlog.Hash
			copy(ph[:], h)
			proof = append(proof, ph)
		}
		if err := tlog.CheckTree(proof, int64(to.size), to.root, int64(from.size), from.root); err != nil {
			// Both heads carry Apple\'s signature, so no valid proof connecting
			// them would mean Apple signed two roots that cannot share a
			// history. But a broken proof looks the same from here, and the
			// accusation is permanent, so we withhold instead. A genuine split
			// view is caught by comparing what different witnesses cosigned.
			return fmt.Errorf("apple: no valid consistency proof %d->%d: %w", from.size, to.size, err)
		}
		cur = to
	}

	if cur.size != uint64(next.Size) || cur.root != next.Hash {
		return fmt.Errorf("apple: proof chain ends at size %d, not the head being attested (%d)",
			cur.size, next.Size)
	}
	return nil
}

// Applications are the enum values Apple uses in its log heads.
var Applications = map[uint64]string{
	1: "IDS_MESSAGING",
	2: "IDS_FACETIME",
	3: "IDS_MULTIPLEX",
	5: "PRIVATE_CLOUD_COMPUTE",
}

// scanWindow is how many trailing leaves to read. Applications appear
// interleaved, so a window well above the number of applications is needed to
// see each one at least once; 200 covers every application observed in practice
// several times over.
const scanWindow = 200

// ScanApplications reads the tail of the Top-Level Tree and returns the
// per-application heads committed into it.
//
// This is the only public route to iMessage's Key Transparency state. Its own
// tree is absent from list_trees and the API rejects requests for it by id — but
// the Top-Level Tree is a log of per-application heads, and IDS_MESSAGING heads
// are in there, readable by anyone.
//
// # What these observations are worth
//
// Each head is a SignedObject, but signed by that application's own key, which
// Apple does not publish anywhere reachable — the leaf carries only the key's
// hash. And the leaf is not yet bound to the Top-Level Tree root we do verify,
// because the inclusion-proof request schema is absent from Apple's published
// protos and could not be determined by probing.
//
// So these are observations, not attestations. They are never cosigned. What
// they still support is real: tracking each application's head over time makes a
// rollback, a repeated revision with a different root, or a change of signing key
// visible — none of which requires verifying a signature.
func (s *Source) ScanApplications(ctx context.Context) ([]source.AppHead, error) {
	// Only the Top-Level Tree is a log of per-application heads. Every other
	// Apple tree this adapter can be pointed at — the PCC Apple Transparency
	// log, say — has leaves of an entirely different shape, and parsing those as
	// application heads would write nonsense into applications.json, which is
	// published output. Returning nothing is right: there is nothing to observe.
	if s.cfg.TreeID != TopLevelTreeID {
		return nil, nil
	}

	head, err := s.Fetch(ctx, nil)
	if err != nil {
		return nil, err
	}
	size := uint64(head.Size)
	start := uint64(0)
	if size > scanWindow {
		start = size - scanWindow
	}

	body, err := s.post(ctx, "log_leaves", s.logLeavesRequest(start, size))
	if err != nil {
		return nil, err
	}

	resp := pbwire.Parse(body)
	if len(resp[3]) == 0 {
		return nil, fmt.Errorf("apple: log_leaves returned no leaves (status %d)", pbwire.Uint64(resp, 1))
	}

	var out []source.AppHead
	for _, leaf := range resp[3] {
		lf := pbwire.Parse(leaf)
		// Only TLT_NODE (3) leaves carry a per-application head.
		if pbwire.Uint64(lf, 1) != 3 {
			continue
		}
		node := pbwire.Parse(pbwire.First(lf, 2))

		// TopLevelTreeNode{patHead = 1} wrapping SignedObject{object=1, signature=2}.
		so := pbwire.Parse(pbwire.First(node, 1))
		inner := pbwire.First(so, 1)
		if inner == nil {
			continue
		}
		sig := pbwire.Parse(pbwire.First(so, 2))

		// LogHead{logSize=2, logHeadHash=3, revision=4, application=6, treeId=7}.
		lh := pbwire.Parse(inner)
		treeID := pbwire.Uint64(lh, 7)
		if treeID == 0 {
			continue
		}
		app := pbwire.Uint64(lh, 6)
		out = append(out, source.AppHead{
			TreeID:         treeID,
			Application:    app,
			Name:           Applications[app],
			LogSize:        pbwire.Uint64(lh, 2),
			Revision:       pbwire.Uint64(lh, 4),
			RootHash:       pbwire.First(lh, 3),
			SigningKeyHash: pbwire.First(sig, 2),
			LeafIndex:      pbwire.Uint64(lf, 3),
		})
	}

	// Reduce to the newest head per tree.
	//
	// The Top-Level Tree is a *log of heads over time*, so a 200-leaf window
	// contains many heads for the same application at successive revisions, and
	// they are not guaranteed to appear in revision order. Returning all of them
	// makes the caller record an older head after a newer one, which reads as
	// the application's log going backwards — a contradiction that never
	// happened. On the first deployment this fired for five trees at once, each
	// "backwards" by exactly one revision, which is the signature of a scan
	// artifact rather than five simultaneous rollbacks.
	//
	// What an observation should say is what the application's head *is*, not
	// replay how it got there.
	newest := make(map[uint64]source.AppHead, len(out))
	for _, h := range out {
		prev, seen := newest[h.TreeID]
		if !seen || h.Revision > prev.Revision ||
			(h.Revision == prev.Revision && h.LogSize > prev.LogSize) {
			newest[h.TreeID] = h
		}
	}
	latest := make([]source.AppHead, 0, len(newest))
	for _, h := range newest {
		latest = append(latest, h)
	}
	// Deterministic order, so the published applications.json does not churn.
	sort.Slice(latest, func(i, j int) bool { return latest[i].TreeID < latest[j].TreeID })
	return latest, nil
}

// logLeavesRequest builds LogLeavesRequest{version, treeId, startIndex, endIndex,
// startMergeGroup, endMergeGroup}.
//
// The merge-group fields are not optional in practice: omitting them returns
// HTTP 200 with an empty leaf list rather than an error, which reads exactly
// like a log that has no leaves.
func (s *Source) logLeavesRequest(start, end uint64) []byte {
	var b []byte
	b = pbwire.AppendTag(b, 1, 0)
	b = pbwire.AppendVarint(b, requestVersion)
	b = pbwire.AppendTag(b, 2, 0)
	b = pbwire.AppendVarint(b, s.cfg.TreeID)
	b = pbwire.AppendTag(b, 4, 0)
	b = pbwire.AppendVarint(b, start)
	b = pbwire.AppendTag(b, 5, 0) // exclusive
	b = pbwire.AppendVarint(b, end)
	b = pbwire.AppendTag(b, 7, 0)
	b = pbwire.AppendVarint(b, 0)
	b = pbwire.AppendTag(b, 8, 0)
	b = pbwire.AppendVarint(b, 1)
	return b
}

func (s *Source) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	return s.postTo(ctx, s.cfg.Endpoint, path, body)
}

func (s *Source) postTo(ctx context.Context, base, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/protobuf")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apple: %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple: %s: HTTP %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// consistencyEndpoint is on the at_client surface, not at_researcher.
//
// This distinction is the whole reason append-only is provable here:
// at_researcher/consistency_proof rejects every request, while
// at_client/consistency_proof answers the same question unauthenticated. The
// researcher bag does not mention it; it comes from the *client* bag.
const consistencyEndpoint = "consistency_proof"

// clientBase derives the at_client URL from the configured at_researcher one,
// since the two live on the same host.
func (s *Source) clientBase() string {
	if s.cfg.ClientEndpoint != "" {
		return s.cfg.ClientEndpoint
	}
	return strings.TrimSuffix(s.cfg.Endpoint, "/at_researcher") + "/at_client"
}

// consistencyRequest builds ConsistencyProofRequest{version, requests, logType}.
//
// Note the proof is keyed by *revision*, not by tree size — asking in sizes is
// rejected, which is an easy way to conclude wrongly that the endpoint is
// broken. application is omitted because logType is TOP_LEVEL_TREE.
func (s *Source) consistencyRequest(startRev, endRev uint64) []byte {
	var sub []byte
	sub = pbwire.AppendTag(sub, 3, 0)
	sub = pbwire.AppendVarint(sub, startRev)
	sub = pbwire.AppendTag(sub, 4, 0)
	sub = pbwire.AppendVarint(sub, endRev)

	var b []byte
	b = pbwire.AppendTag(b, 1, 0)
	b = pbwire.AppendVarint(b, requestVersion)
	b = pbwire.AppendTag(b, 2, 2)
	b = pbwire.AppendVarint(b, uint64(len(sub)))
	b = append(b, sub...)
	b = pbwire.AppendTag(b, 3, 0)
	b = pbwire.AppendVarint(b, s.cfg.LogType)
	if s.cfg.Application != 0 {
		b = pbwire.AppendTag(b, 4, 0)
		b = pbwire.AppendVarint(b, s.cfg.Application)
	}
	return b
}

const logTypeTopLevelTree = 3

// treeState is one signed head, verified.
type treeState struct {
	size     uint64
	revision uint64
	root     tlog.Hash
}

// verifySignedHead checks a SignedObject carrying a LogHead and returns it.
// Shared by the head and consistency paths so both hold to the same standard.
func (s *Source) verifySignedHead(signedObj []byte) (*treeState, error) {
	so := pbwire.Parse(signedObj)
	obj := pbwire.First(so, 1)
	sigMsg := pbwire.First(so, 2)
	if obj == nil || sigMsg == nil {
		return nil, fmt.Errorf("apple: malformed SignedObject")
	}
	sm := pbwire.Parse(sigMsg)
	sig := pbwire.First(sm, 1)
	keyHash := pbwire.First(sm, 2)
	if alg := pbwire.Uint64(sm, 3); alg != 1 {
		return nil, fmt.Errorf("apple: signature algorithm %d, want 1 (ECDSA_SHA256)", alg)
	}
	if len(keyHash) != 32 || !bytes.Equal(keyHash, s.keyID[:]) {
		return nil, fmt.Errorf("apple: head signed by key %x, not the pinned key %x", keyHash, s.keyID[:8])
	}
	digest := sha256.Sum256(obj)
	if !ecdsa.VerifyASN1(s.pub, digest[:], sig) {
		return nil, fmt.Errorf("apple: signature does not verify over the tree head")
	}

	lh := pbwire.Parse(obj)
	if tid := pbwire.Uint64(lh, 7); tid != s.cfg.TreeID {
		return nil, fmt.Errorf("apple: head is for tree %d, expected %d", tid, s.cfg.TreeID)
	}
	rootBytes := pbwire.First(lh, 3)
	if len(rootBytes) != 32 {
		return nil, fmt.Errorf("apple: log head hash is %d bytes, want 32", len(rootBytes))
	}
	st := &treeState{size: pbwire.Uint64(lh, 2), revision: pbwire.Uint64(lh, 4)}
	copy(st.root[:], rootBytes)
	if st.size == 0 {
		return nil, fmt.Errorf("apple: server returned the empty tree head; " +
			"the request is missing an explicit revision")
	}
	return st, nil
}

// revisionForSize finds the revision whose head has the given tree size.
//
// Consistency proofs are keyed by revision, but a witnessed head is identified
// by size, and the mapping is not derivable. Rather than carry extra state that
// a restart would lose, it is recovered by binary search over log_head — which
// accepts a revision — costing about twenty requests and always working from a
// cold start.
func (s *Source) revisionForSize(ctx context.Context, size uint64, hint *treeState) (uint64, error) {
	if hint != nil && hint.size == size {
		return hint.revision, nil
	}
	lo, hi := uint64(1), hint.revision
	if hint == nil {
		cur, err := s.head(ctx, latestRevision)
		if err != nil {
			return 0, err
		}
		hi = cur.revision
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		st, err := s.head(ctx, int64(mid))
		if err != nil {
			return 0, err
		}
		switch {
		case st.size == size:
			return mid, nil
		case st.size < size:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	st, err := s.head(ctx, int64(lo))
	if err != nil {
		return 0, err
	}
	if st.size != size {
		return 0, fmt.Errorf("apple: no revision has tree size %d (revision %d has %d)", size, lo, st.size)
	}
	return lo, nil
}

// head fetches and verifies the head at a revision (-1 for latest).
func (s *Source) head(ctx context.Context, revision int64) (*treeState, error) {
	var b []byte
	b = pbwire.AppendTag(b, 1, 0)
	b = pbwire.AppendVarint(b, requestVersion)
	b = pbwire.AppendTag(b, 2, 0)
	b = pbwire.AppendVarint(b, s.cfg.TreeID)
	b = pbwire.AppendTag(b, 4, 0)
	b = pbwire.AppendVarint(b, uint64(revision))

	body, err := s.post(ctx, "log_head", b)
	if err != nil {
		return nil, err
	}
	resp := pbwire.Parse(body)
	signedObj := pbwire.First(resp, 4)
	if signedObj == nil {
		return nil, fmt.Errorf("apple: response carries no log head (status %d)", pbwire.Uint64(resp, 1))
	}
	return s.verifySignedHead(signedObj)
}

// Enum values from Apple's Transparency.proto, needed where a request must name
// a log other than the Top-Level Tree.
const (
	statusOK = 1

	// LogTypeATLog and ApplicationPCC name Apple's Transparency log for Private
	// Cloud Compute, which is the one Apple tree a third party can verify
	// inclusion proofs against. See docs/apple.md.
	LogTypeATLog   = 5
	ApplicationPCC = 5
)

// The PCC Apple Transparency log, from at_researcher/list_trees. Its signing
// key is not the Top-Level Tree's, so both must be configured together.
const (
	ATLogTreeID    = 5296182921832599
	ATLogPublicKey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004" +
		"c4ad1582c97e1a89371e10051e815b87abdb1473394a4ddae7ff0892a50be59b" +
		"105547a637f0ca875bd8927f810169ca5e6fa1fe0f2819aeadd76a9a909fc31e"
)
