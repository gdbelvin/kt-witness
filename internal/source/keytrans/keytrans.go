// Package keytrans witnesses a log that speaks IETF Key Transparency
// (draft-ietf-keytrans-protocol-05) at tier A.
//
// The draft specifies no transport, so there is no IETF KT deployment in
// general to point this at. It speaks the HTTP binding of the keytrans
// reference log (POST /v1/distinguished, TLS-encoded bodies), which is the
// binding we operate.
//
// # Why this is close to the Signal adapter
//
// Signal's Key Transparency is an early version of this same protocol, by the
// same author. The log tree is identical, down to the leaf/interior tag byte
// in each node hash. What changed is the proof format: IETF proofs carry only
// balanced-subtree heads and batch inclusion with consistency, and a
// consistency proof is checked against the full subtree heads and frontier
// entries the verifier kept from the previous head, not just its root. So this
// adapter persists that view between rounds (source.StateStore). A witness
// that loses it cannot prove the next head and withholds until the view is
// restored or the log is re-observed from scratch.
//
// # What a round checks
//
//   - The log's signature over TreeHeadTBS, binding the pinned Configuration,
//     the size and the root.
//   - That the new tree extends the retained view (batched consistency proof),
//     with entry timestamps non-decreasing.
//   - In third-party auditing mode, the auditor's signature over the root at
//     its own size, derived from the same proof, and that it lags the log by
//     no more than max_auditor_lag. The auditor is recorded as a cosigner.
//
// It does not check that the prefix trees are built correctly: that is the
// auditor's job (§15.2) and would be this adapter's tier B.
package keytrans

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// OriginPrefix is the namespace of keytrans checkpoint origins.
const OriginPrefix = "ietf-keytrans/"

// OriginFor derives a log's checkpoint origin from its encoded Configuration.
//
// The configuration is the log's identity: it carries the signing key, the VRF
// key, the deployment mode and every parameter, and every tree head signature
// covers it. Deriving the origin from it, as the sigsum adapter derives its
// origin from the log key, means every witness of the same log mints the same
// origin and their cosignatures aggregate, without anyone choosing a name.
func OriginFor(configuration []byte) string {
	h := sha256.Sum256(configuration)
	return OriginPrefix + hex.EncodeToString(h[:])
}

// Config configures a Source.
type Config struct {
	// Origin, if set, must equal OriginFor(Configuration).
	Origin string
	// Endpoint is the log's base URL.
	Endpoint string
	// Configuration is the log's encoded Configuration, hex. It must be
	// pinned out of band, never taken from the log.
	Configuration string
	// State persists the retained view. Without it a restart loses the view
	// and the next head cannot be proven.
	State  source.StateStore
	Client *http.Client
}

// Source witnesses one keytrans log.
type Source struct {
	cfg    *configuration
	origin string
	url    string
	state  source.StateStore
	client *http.Client

	mu sync.Mutex
	// views are recent verified views, newest last, so the one matching the
	// witness's last cosigned head is still here even if a later round's
	// view was saved but its head never stored.
	views  []*view
	loaded bool
	// pending is the view Fetch verified, and the size it was proven from.
	pending     *view
	pendingFrom int64
}

// keptViews bounds the retained views.
const keptViews = 4

// New validates the pinned configuration and derives the origin.
func New(c Config) (*Source, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(c.Configuration))
	if err != nil {
		return nil, fmt.Errorf("keytrans: configuration is not hex: %w", err)
	}
	cfg, err := parseConfiguration(raw)
	if err != nil {
		return nil, err
	}
	origin := OriginFor(raw)
	if c.Origin != "" && c.Origin != origin {
		return nil, fmt.Errorf("keytrans: configured origin %q does not match the configuration, which implies %q", c.Origin, origin)
	}
	if c.Endpoint == "" {
		return nil, errors.New("keytrans: endpoint is required")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Source{cfg: cfg, origin: origin, url: strings.TrimSuffix(c.Endpoint, "/"), state: c.State, client: client}, nil
}

func (s *Source) Origin() string    { return s.origin }
func (s *Source) Tier() source.Tier { return source.TierA }
func (s *Source) DerivedHead() bool { return false }

func (s *Source) load() error {
	if s.loaded || s.state == nil {
		s.loaded = true
		return nil
	}
	raw, err := s.state.SourceState(s.origin)
	if err != nil {
		return err
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &s.views); err != nil {
			return fmt.Errorf("keytrans: stored view: %w", err)
		}
	}
	s.loaded = true
	return nil
}

func (s *Source) find(size int64, root tlog.Hash) *view {
	for i := len(s.views) - 1; i >= 0; i-- {
		if v := s.views[i]; int64(v.Size) == size && v.Root == [32]byte(root) {
			return v
		}
	}
	return nil
}

func (s *Source) keep(v *view) error {
	if old := s.find(int64(v.Size), tlog.Hash(v.Root)); old == nil {
		s.views = append(s.views, v)
	}
	if len(s.views) > keptViews {
		s.views = slices.Clone(s.views[len(s.views)-keptViews:])
	}
	if s.state == nil {
		return nil
	}
	raw, err := json.Marshal(s.views)
	if err != nil {
		return err
	}
	return s.state.PutSourceState(s.origin, raw)
}

// Fetch requests and fully verifies the log's current head, proving it
// against the view retained for prev.
func (s *Source) Fetch(ctx context.Context, prev *source.Head) (*source.Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	var old *view
	var last *uint64
	if prev != nil {
		if old = s.find(prev.Size, prev.Hash); old == nil {
			return nil, fmt.Errorf("keytrans: no retained view for size %d, so no proof from it can be checked; "+
				"the view is kept in the witness database and must have been lost", prev.Size)
		}
		size := old.Size
		last = &size
	}

	body, err := s.post(ctx, distinguishedRequest(last, math.MaxUint64))
	if err != nil {
		return nil, err
	}
	fetchedAt := time.Now()
	d, err := parseDistinguishedResponse(body, s.cfg)
	if err != nil {
		return nil, err
	}
	v, err := verifyHead(s.cfg, d, old)
	if err != nil {
		return nil, err
	}

	s.pending, s.pendingFrom = v.view, 0
	if prev != nil {
		s.pendingFrom = prev.Size
	}
	h := tlog.Hash(v.view.Root)
	text := torchwood.Checkpoint{Origin: s.origin, Tree: tlog.Tree{N: int64(v.view.Size), Hash: h}}.String()
	head := &source.Head{
		Origin:    s.origin,
		Size:      int64(v.view.Size),
		Hash:      h,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: fetchedAt,
	}
	if v.auditor != nil {
		k := sha256.Sum256(s.cfg.auditorKey)
		head.Cosigners = append(head.Cosigners, "keytrans-auditor:"+hex.EncodeToString(k[:8]))
	}
	return head, nil
}

// VerifyConsistency confirms that the proof Fetch checked was from prev to
// next, then retains next's view.
//
// The batched proof was already verified against prev's retained view in
// Fetch, so a mismatch here is a sequencing problem, not evidence: withhold.
func (s *Source) VerifyConsistency(_ context.Context, prev, next *source.Head) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending
	if p == nil || int64(p.Size) != next.Size || tlog.Hash(p.Root) != next.Hash {
		return fmt.Errorf("keytrans: no verified view for size %d", next.Size)
	}
	if prev != nil && s.pendingFrom != prev.Size {
		return fmt.Errorf("keytrans: proof was checked from size %d, not %d", s.pendingFrom, prev.Size)
	}
	return s.keep(p)
}

func (s *Source) post(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/v1/distinguished", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keytrans: %w", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keytrans: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(out))
	}
	return out, nil
}
