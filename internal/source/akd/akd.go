// Package akd witnesses Meta's AKD-based Key Transparency logs (Messenger,
// WhatsApp) at tier A+.
//
// # What this adapter can and cannot attest
//
// Meta publishes its audit proofs in an openly listable object store, keyed
//
//	<epoch>/<previous_root_hash>/<current_root_hash>
//
// so the root chain is self-linking in the listing metadata alone. Walking that
// chain proves the published history is continuous — no rollback, no gap, no
// fork — for the cost of listing, without downloading any of the ~284 MB proof
// blobs. That is tier A+.
//
// What it does NOT do is verify a signature by Meta. Meta's epoch signing key
// is not published anywhere we can find: the signatures exposed on Cloudflare's
// plexi /reports endpoint are reporters' own, and that endpoint accepts open
// submissions (it currently carries obviously synthetic digests). So a
// cosignature produced here attests "kt-witness observed this root chain, and
// it was continuous", NOT "Meta signed this". That distinction must survive
// into anything published.
//
// As partial compensation, Fetch cross-checks the tip against Cloudflare's
// independently published root: two unrelated parties having to agree is a
// meaningfully stronger statement than either alone.
//
// Tier B (replaying the proof blobs with the akd crate to verify construction)
// is a separate, much more expensive path; see the README.
package akd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Source witnesses one AKD namespace.
type Source struct {
	cfg    Config
	client *http.Client
}

type Config struct {
	// Origin is the canonical checkpoint origin we mint for this log, e.g.
	// "meta.messenger.kt/v1". Meta does not publish checkpoints itself; this
	// adapter canonicalises its epochs into the c2sp.org/tlog-checkpoint shape
	// so the existing witness ecosystem can consume a KT log at all.
	Origin string

	// LogDirectory is Meta's publicly listable proof store.
	LogDirectory string

	// PlexiNamespaceURL, if set, is Cloudflare's namespace endpoint, used to
	// learn the current epoch and to cross-check the root we derive.
	PlexiNamespaceURL string

	// StartEpoch pins where a first observation begins. Full replay from
	// genesis is not attempted: it would be ~175 TB of proofs and, for chain
	// continuity alone, hundreds of thousands of listing requests.
	StartEpoch int64

	// MaxEpochsPerRound bounds catch-up work in a single round.
	MaxEpochsPerRound int64
}

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" || cfg.LogDirectory == "" {
		return nil, fmt.Errorf("akd: origin and log_directory are required")
	}
	if cfg.MaxEpochsPerRound == 0 {
		// Sized so a full catch-up walk finishes well inside a typical
		// max_sign_delay: each epoch costs one listing request (~100 ms), so
		// 200 epochs is ~20 s. Larger values risk a walk that cannot complete
		// before the head goes stale, which never advances and never converges.
		cfg.MaxEpochsPerRound = 200
	}
	cfg.LogDirectory = strings.TrimSuffix(cfg.LogDirectory, "/")
	return &Source{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second, Transport: netmeter.Wrap(nil, cfg.Origin)},
	}, nil
}

func (s *Source) Origin() string    { return s.cfg.Origin }
func (s *Source) Tier() source.Tier { return source.TierAPlus }

// DerivedHead is true: Meta publishes no signed checkpoint, so our head is
// assembled from object listings. A head that appears to regress is far more
// likely to be our misreading than Meta rewriting history, so the core must
// withhold rather than accuse. See the package comment.
func (s *Source) DerivedHead() bool { return true }

// link is one epoch transition, recovered from an object key.
type link struct {
	epoch int64
	prev  tlog.Hash
	curr  tlog.Hash
}

// listResult is the subset of the S3 ListObjectsV2 response we need.
type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated bool `xml:"IsTruncated"`
}

func parseHash(s string) (tlog.Hash, error) {
	var h tlog.Hash
	raw, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(raw) != len(h) {
		return h, fmt.Errorf("want %d-byte hash, got %d", len(h), len(raw))
	}
	copy(h[:], raw)
	return h, nil
}

// linkAt returns the epoch transition published for a given epoch, or a nil
// link if no object exists yet.
func (s *Source) linkAt(ctx context.Context, epoch int64) (*link, error) {
	// Cache-bust. CloudFront serves stale *negative* listings (observed
	// x-cache: Hit with age 180 returning zero keys for an epoch that had since
	// been published), and a Cache-Control: no-cache request header does not
	// bypass it. A stale "absent" in the middle of a chain walk would otherwise
	// look like a hole in Meta's history — so this is a correctness fix, not an
	// optimisation. Request volume here is a handful per minute.
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/?list-type=2&prefix=%d/&max-keys=2&cb=%s",
		s.cfg.LogDirectory, epoch, hex.EncodeToString(nonce))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("akd: list epoch %d: %w", epoch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("akd: list epoch %d: HTTP %d", epoch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var lr listResult
	if err := xml.Unmarshal(body, &lr); err != nil {
		return nil, fmt.Errorf("akd: parse listing for epoch %d: %w", epoch, err)
	}
	if len(lr.Contents) == 0 {
		return nil, nil
	}
	if len(lr.Contents) > 1 {
		// Two objects for one epoch would be two published histories at the same
		// point. Reported as a plain error, so the cosignature is withheld
		// without a permanent accusation: confirming it as equivocation means
		// checking both keys deliberately, not acting on one listing.
		return nil, fmt.Errorf("akd: epoch %d has %d objects, expected 1", epoch, len(lr.Contents))
	}

	parts := strings.Split(lr.Contents[0].Key, "/")
	if len(parts) != 3 {
		return nil, fmt.Errorf("akd: malformed key %q", lr.Contents[0].Key)
	}
	got, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || got != epoch {
		return nil, fmt.Errorf("akd: key %q does not belong to epoch %d", lr.Contents[0].Key, epoch)
	}
	prev, err := parseHash(parts[1])
	if err != nil {
		return nil, fmt.Errorf("akd: epoch %d previous hash: %w", epoch, err)
	}
	curr, err := parseHash(parts[2])
	if err != nil {
		return nil, fmt.Errorf("akd: epoch %d current hash: %w", epoch, err)
	}
	return &link{epoch: epoch, prev: prev, curr: curr}, nil
}

// plexiView is Cloudflare's independently published view of a namespace.
//
// Note that Root and LastVerifiedEpoch are unrelated: Root lags a long way
// behind (observed at epoch 89,527 while LastVerifiedEpoch was 624,707), so it
// is a historical anchor to cross-check, not the tip.
type plexiView struct {
	AnchorEpoch  int64
	AnchorRoot   tlog.Hash
	LastVerified int64
}

func (s *Source) plexi(ctx context.Context) (*plexiView, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.PlexiNamespaceURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("akd: plexi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("akd: plexi: HTTP %d", resp.StatusCode)
	}
	var ns struct {
		Root              string `json:"root"`
		LastVerifiedEpoch int64  `json:"last_verified_epoch"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ns); err != nil {
		return nil, fmt.Errorf("akd: plexi decode: %w", err)
	}
	e, h, ok := strings.Cut(ns.Root, "/")
	if !ok {
		return nil, fmt.Errorf("akd: plexi root %q not in epoch/hash form", ns.Root)
	}
	epoch, err := strconv.ParseInt(e, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("akd: plexi epoch: %w", err)
	}
	hash, err := parseHash(h)
	if err != nil {
		return nil, fmt.Errorf("akd: plexi hash: %w", err)
	}
	return &plexiView{AnchorEpoch: epoch, AnchorRoot: hash, LastVerified: ns.LastVerifiedEpoch}, nil
}

// findTip locates the highest published epoch, starting from a hint. There is
// no "latest" endpoint, and listing every key would be hundreds of thousands of
// requests, so we do an exponential probe followed by a binary search:
// O(log n) requests rather than O(n).
func (s *Source) findTip(ctx context.Context, hint int64) (*link, error) {
	if hint < 1 {
		hint = 1
	}

	// If the hint itself is absent, walk backwards to find solid ground.
	present, err := s.linkAt(ctx, hint)
	if err != nil {
		return nil, err
	}
	for step := int64(1); present == nil; step *= 2 {
		probe := hint - step
		if probe < 1 {
			// Clamp rather than give up: the populated range may lie below the
			// last doubling, and epoch 1 is the floor worth checking.
			probe = 1
		}
		if probe == hint {
			return nil, fmt.Errorf("akd: no published epochs at or below hint %d", hint)
		}
		hint = probe
		if present, err = s.linkAt(ctx, hint); err != nil {
			return nil, err
		}
	}

	// Exponentially probe upward for an absent epoch.
	lo, last := hint, present
	var hi int64
	for step := int64(1); ; step *= 2 {
		probe := lo + step
		l, err := s.linkAt(ctx, probe)
		if err != nil {
			return nil, err
		}
		if l == nil {
			hi = probe
			break
		}
		lo, last = probe, l
		if step > 1<<40 {
			return nil, fmt.Errorf("akd: tip search did not converge")
		}
	}

	// Binary search the boundary: lo is present, hi is absent.
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		l, err := s.linkAt(ctx, mid)
		if err != nil {
			return nil, err
		}
		if l == nil {
			hi = mid
		} else {
			lo, last = mid, l
		}
	}
	return last, nil
}

// Fetch determines the current tip.
//
// The epoch comes from Cloudflare as a hint, but the root we attest is always
// the one read from Meta's own store; when the two disagree we refuse rather
// than pick a side.
func (s *Source) Fetch(ctx context.Context, prev *source.Head) (*source.Head, error) {
	fetchedAt := time.Now()

	hint := s.cfg.StartEpoch
	if s.cfg.PlexiNamespaceURL != "" {
		pv, err := s.plexi(ctx)
		if err != nil {
			return nil, err
		}

		// Cross-check Cloudflare's anchor against Meta's own store. Two
		// unrelated parties having to agree is a stronger statement than
		// either alone, and it is the only signature-adjacent check available
		// to us given Meta's epoch signing key is unpublished.
		anchor, err := s.linkAt(ctx, pv.AnchorEpoch)
		if err != nil {
			return nil, err
		}
		if anchor == nil {
			return nil, fmt.Errorf("akd: Cloudflare anchors epoch %d but Meta's store has no such object", pv.AnchorEpoch)
		}
		if anchor.curr != pv.AnchorRoot {
			// We cannot tell which party is wrong, so we sign neither.
			return nil, fmt.Errorf("akd: epoch %d root mismatch: Cloudflare claims %x, Meta's store publishes %x",
				pv.AnchorEpoch, pv.AnchorRoot[:], anchor.curr[:])
		}

		if pv.LastVerified > hint {
			hint = pv.LastVerified
		}
	}

	l, err := s.findTip(ctx, hint)
	if err != nil {
		return nil, err
	}

	// Step forward at most MaxEpochsPerRound. Proving consistency means walking
	// every intervening epoch, so reporting a tip far ahead of our stored head
	// would make each round attempt a walk too long to finish inside the sign
	// deadline — and, failing, never advance the stored head, so the next round
	// would attempt the same walk against a still-larger gap. Returning an
	// intermediate head instead lets catch-up converge a step at a time.
	if prev != nil && l.epoch-prev.Size > s.cfg.MaxEpochsPerRound {
		target := prev.Size + s.cfg.MaxEpochsPerRound
		if l, err = s.linkAt(ctx, target); err != nil {
			return nil, err
		}
		if l == nil {
			return nil, fmt.Errorf("akd: no object for intermediate epoch %d", target)
		}
	}

	cp := torchwood.Checkpoint{
		Origin: s.cfg.Origin,
		Tree:   tlog.Tree{N: l.epoch, Hash: l.curr},
	}
	text := cp.String()

	return &source.Head{
		Origin:    s.cfg.Origin,
		Size:      l.epoch,
		Hash:      l.curr,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: fetchedAt,
	}, nil
}

// VerifyConsistency walks every epoch between our last witnessed root and the
// new tip, checking that each object's previous-root field equals the preceding
// object's current-root. A break in that chain is conclusive: Meta published two
// incompatible histories.
func (s *Source) VerifyConsistency(ctx context.Context, prev, next *source.Head) error {
	if prev == nil {
		// First observation. There is no earlier root to link to, so we pin
		// here and attest continuity only from this epoch forward.
		return nil
	}
	if gap := next.Size - prev.Size; gap > s.cfg.MaxEpochsPerRound {
		return fmt.Errorf("akd: %d epochs behind (max %d per round); catching up",
			gap, s.cfg.MaxEpochsPerRound)
	}

	expected := prev.Hash
	for epoch := prev.Size + 1; epoch <= next.Size; epoch++ {
		l, err := s.linkAt(ctx, epoch)
		if err != nil {
			return err
		}
		if l == nil {
			// A hole in published history. Tempting to call this a rollback,
			// since later epochs exist — but "absent" is the one observation we
			// cannot fully trust: a CDN edge, a partially-completed write, or an
			// out-of-order upload all produce it transiently. Accusing a log of
			// forking is permanent and public, so absence alone never qualifies.
			// We withhold and retry; a real rollback will persist, and a genuine
			// contradiction shows up as a broken link below.
			return fmt.Errorf("akd: no object for epoch %d while epoch %d exists; withholding pending retry",
				epoch, next.Size)
		}
		if l.prev != expected {
			return &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf("root chain broken at epoch %d: object declares previous root %x, but epoch %d published current root %x",
					epoch, l.prev[:], epoch-1, expected[:]),
				Prev: prev, Next: next,
			}
		}
		expected = l.curr
	}

	if expected != next.Hash {
		return &source.ForkError{
			Origin: s.cfg.Origin,
			Reason: fmt.Sprintf("chain walk to epoch %d ends at root %x, but the tip published %x",
				next.Size, expected[:], next.Hash[:]),
			Prev: prev, Next: next,
		}
	}
	return nil
}

// ResolveEpoch locates one epoch's construction proof, for tier-B auditing.
//
// The roots come from the object key itself, so the auditor verifies the proof
// against the very roots the log published — not against anything we derived.
func (s *Source) ResolveEpoch(ctx context.Context, epoch int64) (*audit.EpochRef, error) {
	l, err := s.linkAt(ctx, epoch)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("akd: no object published for epoch %d", epoch)
	}
	return &audit.EpochRef{
		LogDirectory: s.cfg.LogDirectory,
		PrevRoot:     hex.EncodeToString(l.prev[:]),
		CurrRoot:     hex.EncodeToString(l.curr[:]),
	}, nil
}

// Backfill verifies Meta's entire published root chain.
//
// Trust-on-first-use leaves everything before we showed up unattested, which for
// this log is hundreds of thousands of epochs. They can all be checked from
// listing metadata alone, because each object key names both the epoch's
// previous and current roots — no proof blob is downloaded.
//
// The bulk listing is what makes this affordable: paging 1,000 keys at a time is
// ~625 requests for ~625,000 epochs, rather than one request each.
func (s *Source) Backfill(ctx context.Context, log *slog.Logger) (*source.BackfillResult, error) {
	links := make(map[int64]*link, 1<<20)

	var token string
	pages := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, next, err := s.listPage(ctx, token)
		if err != nil {
			return nil, err
		}
		for _, l := range page {
			// Two objects for one epoch would be two published histories at the
			// same point. Reported rather than accused: confirming it means
			// fetching both keys deliberately.
			if prior, ok := links[l.epoch]; ok && (prior.prev != l.prev || prior.curr != l.curr) {
				return nil, fmt.Errorf("akd: epoch %d has two differing objects", l.epoch)
			}
			links[l.epoch] = l
		}
		pages++
		if log != nil && pages%50 == 0 {
			log.Info("backfill listing", "origin", s.cfg.Origin, "pages", pages, "epochs", len(links))
		}
		if next == "" {
			break
		}
		token = next
	}

	if len(links) == 0 {
		return nil, fmt.Errorf("akd: no published history found")
	}

	epochs := make([]int64, 0, len(links))
	for e := range links {
		epochs = append(epochs, e)
	}
	slices.Sort(epochs)

	res := &source.BackfillResult{
		Epochs: len(epochs),
		From:   epochs[0],
		To:     epochs[len(epochs)-1],
	}
	for i := 1; i < len(epochs); i++ {
		prev, cur := links[epochs[i-1]], links[epochs[i]]

		if epochs[i] != epochs[i-1]+1 {
			// Missing epochs. Not evidence: retention limits and partial writes
			// both look like this, and linkage cannot be checked across a hole.
			res.Gaps = append(res.Gaps,
				fmt.Sprintf("%d..%d missing", epochs[i-1]+1, epochs[i]-1))
			continue
		}

		if cur.prev != prev.curr {
			// Adjacent epochs that do not link. This cannot be absence or a
			// stale read: both objects exist and their names disagree.
			return nil, &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf(
					"published history breaks at epoch %d: it follows root %x, but epoch %d published root %x",
					cur.epoch, cur.prev[:], prev.epoch, prev.curr[:]),
			}
		}
	}
	return res, nil
}

// listPage fetches one page of the object listing.
func (s *Source) listPage(ctx context.Context, token string) ([]*link, string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	url := fmt.Sprintf("%s/?list-type=2&max-keys=1000&cb=%s", s.cfg.LogDirectory, hex.EncodeToString(nonce))
	if token != "" {
		url += "&continuation-token=" + neturl.QueryEscape(token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("akd: list page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("akd: list page: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", err
	}

	var lr struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
		IsTruncated bool   `xml:"IsTruncated"`
		NextToken   string `xml:"NextContinuationToken"`
	}
	if err := xml.Unmarshal(body, &lr); err != nil {
		return nil, "", fmt.Errorf("akd: parse listing page: %w", err)
	}

	out := make([]*link, 0, len(lr.Contents))
	for _, c := range lr.Contents {
		parts := strings.Split(c.Key, "/")
		if len(parts) != 3 {
			continue
		}
		epoch, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		prev, err := parseHash(parts[1])
		if err != nil {
			continue
		}
		curr, err := parseHash(parts[2])
		if err != nil {
			continue
		}
		out = append(out, &link{epoch: epoch, prev: prev, curr: curr})
	}

	next := ""
	if lr.IsTruncated {
		next = lr.NextToken
	}
	return out, next, nil
}
