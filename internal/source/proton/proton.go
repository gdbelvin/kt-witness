// Package proton witnesses Proton Mail's Key Transparency epochs.
//
// Proton's design is unusual and convenient: rather than signing tree heads
// with a dedicated key, it obtains a WebPKI certificate whose SAN encodes the
// epoch's chain hash, and lets that certificate land in Certificate Transparency
// logs. The CA's signature is what makes an epoch non-repudiable, and CT is the
// equivocation-detection channel.
//
// Two things are therefore verifiable by anyone, with no account and no
// coordination with Proton:
//
//   - Epoch chaining. chain_hash(t) = SHA-256(chain_hash(t-1) || tree_hash(t)),
//     so the published history is a hash chain that can be walked and recomputed.
//   - The certificate binding. The chain hash we were served must appear in a
//     WebPKI-valid certificate's SAN, in a format Proton's own client checks.
//
// Given a CT log list (Config.CTLogs), a third thing becomes verifiable: that
// the certificate is *in* a Certificate Transparency log, rather than merely
// carrying a log's promise to include it. Since CT is the channel Proton's whole
// design relies on to make equivocation visible, that is the check the design
// was built around; see ct.go.
//
// What this adapter does NOT do is re-verify the tree itself (Proton's §3.11
// external audit), which needs a ~13.6 GB dump and ~16 GB RAM — the analogue of
// tier B, and a separate command, cmd/kt-proton-audit.
package proton

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type Source struct {
	cfg    Config
	client *http.Client
}

type Config struct {
	// Origin is the canonical checkpoint origin we mint, e.g. "proton.me/kt/v1".
	Origin string

	// APIBase is https://api.protonmail.ch (or https://mail.proton.me/api).
	APIBase string

	// MaxEpochsPerRound bounds catch-up work per round.
	MaxEpochsPerRound int64

	// CTLogs are the Certificate Transparency logs the tip's certificate may be
	// confirmed in. Left empty, the adapter behaves as it always has and trusts
	// the certificate's embedded SCTs; supplied, every fetch additionally
	// confirms the certificate's *presence* in one of these logs, which is the
	// channel Proton's whole design leans on. See ct.go.
	//
	// Supply the full witnessed log list rather than a hand-picked log: CT logs
	// are temporally sharded and rotate under Proton's ~90-day certificates, and
	// the CA issuing them alternates, so which log will hold the next epoch's
	// certificate is not something to guess at.
	CTLogs []CTLog
}

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" {
		return nil, fmt.Errorf("proton: origin is required")
	}
	if cfg.APIBase == "" {
		cfg.APIBase = "https://api.protonmail.ch"
	}
	if cfg.MaxEpochsPerRound == 0 {
		// Epochs are ~4h apart, so even a long outage is a handful of epochs.
		cfg.MaxEpochsPerRound = 200
	}
	cfg.APIBase = strings.TrimSuffix(cfg.APIBase, "/")
	return &Source{cfg: cfg, client: &http.Client{
		Timeout:   30 * time.Second,
		Transport: netmeter.Wrap(nil, cfg.Origin),
	}}, nil
}

func (s *Source) Origin() string    { return s.cfg.Origin }
func (s *Source) Tier() source.Tier { return source.TierAPlus }

// DerivedHead is false. The chain hash is bound into a certificate signed by a
// public CA, so two different chain hashes for one epoch would mean two valid
// CA-signed bindings — a contradiction Proton cannot explain away, and not
// something our own misreading can manufacture.
func (s *Source) DerivedHead() bool { return false }

// epoch is Proton's wire representation.
//
// Note the field name: the API sends PrevChainHash, while Proton's own Go client
// struct calls it PreviousChainHash. The two do not match, so the client struct
// cannot be unmarshalled directly from the API response.
type epoch struct {
	EpochID         int64  `json:"EpochID"`
	TreeHash        string `json:"TreeHash"`
	ChainHash       string `json:"ChainHash"`
	PrevChainHash   string `json:"PrevChainHash"`
	ClaimedTime     int64  `json:"ClaimedTime"`
	Certificate     string `json:"Certificate"`
	CertificateTime int64  `json:"CertificateTime"`
	Domain          string `json:"Domain"`
	StartEpochID    int64  `json:"StartEpochID"`
}

// verifyChainHash recomputes the epoch's own chain hash. This is the invariant
// that makes the epoch list a hash chain rather than a list of assertions.
func (e *epoch) verifyChainHash() error {
	prev, err := hex.DecodeString(e.PrevChainHash)
	if err != nil {
		return fmt.Errorf("epoch %d: previous chain hash: %w", e.EpochID, err)
	}
	tree, err := hex.DecodeString(e.TreeHash)
	if err != nil {
		return fmt.Errorf("epoch %d: tree hash: %w", e.EpochID, err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(tree)
	got := hex.EncodeToString(h.Sum(nil))
	if got != e.ChainHash {
		return fmt.Errorf("epoch %d: chain hash mismatch: published %s, but SHA-256(prev||tree) = %s",
			e.EpochID, e.ChainHash, got)
	}
	return nil
}

// expectedSAN rebuilds the DNS name Proton commits the chain hash into:
//
//	<chainhash[0:32]>.<chainhash[32:64]>.<certificateTime>.<epochID>.<nameVersion>.<domain>
//
// The split into two 32-character halves exists because a DNS label may not
// exceed 63 characters.
func (e *epoch) expectedSAN() (string, error) {
	if len(e.ChainHash) != 64 {
		return "", fmt.Errorf("epoch %d: chain hash is %d hex chars, want 64", e.EpochID, len(e.ChainHash))
	}
	const nameVersion = 1
	return fmt.Sprintf("%s.%s.%d.%d.%d.%s",
		e.ChainHash[:32], e.ChainHash[32:], e.CertificateTime, e.EpochID, nameVersion, e.Domain), nil
}

// certificates parses the PEM chain the epoch carries, leaf first.
func (e *epoch) certificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(e.Certificate)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("epoch %d: parse certificate: %w", e.EpochID, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("epoch %d: no certificate supplied", e.EpochID)
	}
	return certs, nil
}

// verifyCertificate checks that a publicly trusted CA signed a certificate
// committing to this epoch's chain hash.
//
// This is the step that makes an epoch non-repudiable: Proton cannot later
// disown a chain hash a CA attested to, and the certificate is destined for CT.
func (e *epoch) verifyCertificate(now time.Time) error {
	certs, err := e.certificates()
	if err != nil {
		return err
	}

	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	want, err := e.expectedSAN()
	if err != nil {
		return err
	}
	found := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, want) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("epoch %d: certificate does not commit to this epoch; expected SAN %q, got %v",
			e.EpochID, want, leaf.DNSNames)
	}

	// Verified against the host's trust store. DNSName is deliberately left
	// empty: we already matched the SAN ourselves, and the commitment name is
	// not a name anyone connects to.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("epoch %d: certificate chain: %w", e.EpochID, err)
	}
	return nil
}

func (s *Source) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.APIBase+path, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("proton: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proton: GET %s: HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("proton: decode %s: %w", path, err)
	}
	return nil
}

func hashOf(hexStr string) (tlog.Hash, error) {
	var h tlog.Hash
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return h, err
	}
	if len(raw) != len(h) {
		return h, fmt.Errorf("want %d-byte hash, got %d", len(h), len(raw))
	}
	copy(h[:], raw)
	return h, nil
}

func (s *Source) Fetch(ctx context.Context, prev *source.Head) (*source.Head, error) {
	var resp struct {
		Epochs []epoch `json:"Epochs"`
	}
	if err := s.get(ctx, "/kt/v1/epochs", &resp); err != nil {
		return nil, err
	}
	if len(resp.Epochs) == 0 {
		return nil, fmt.Errorf("proton: no epochs returned")
	}
	fetchedAt := time.Now()

	e := resp.Epochs[0]
	for _, cand := range resp.Epochs {
		if cand.EpochID > e.EpochID {
			e = cand
		}
	}

	if err := e.verifyChainHash(); err != nil {
		return nil, fmt.Errorf("proton: %w", err)
	}
	// The certificate is checked on the tip only. Older epochs' certificates
	// legitimately expire (they live ~90 days), so demanding validity during a
	// historical walk would report normal expiry as misbehaviour.
	if err := e.verifyCertificate(fetchedAt); err != nil {
		return nil, fmt.Errorf("proton: %w", err)
	}
	// Confirming the certificate in a CT log turns the SCT's promise into a
	// fact. Failure here withholds and never accuses: a log we cannot reach or a
	// checkpoint that has not caught up with a fresh certificate both mean we
	// could not check, and even a leaf-hash mismatch is far likelier to be our
	// reconstruction than a conspiracy between a CA, a CT log and Proton.
	if _, err := s.ConfirmCertificate(ctx, &e); err != nil {
		return nil, err
	}

	head, err := s.stepTowards(ctx, prev, &e)
	if err != nil {
		return nil, err
	}
	head.FetchedAt = fetchedAt
	return head, nil
}

// stepTowards caps how far ahead of prev we report.
//
// Proving consistency means walking every intervening epoch, so reporting a tip
// far ahead would make each round attempt a walk it cannot finish before the
// head goes stale — and, failing, never advance, leaving the next round the same
// walk against a larger gap. Returning an intermediate head lets catch-up
// converge a step at a time.
func (s *Source) stepTowards(ctx context.Context, prev *source.Head, tip *epoch) (*source.Head, error) {
	e := tip
	if prev != nil && e.EpochID-prev.Size > s.cfg.MaxEpochsPerRound {
		got, err := s.epochAt(ctx, prev.Size+s.cfg.MaxEpochsPerRound)
		if err != nil {
			return nil, err
		}
		if err := got.verifyChainHash(); err != nil {
			return nil, fmt.Errorf("proton: %w", err)
		}
		e = got
	}

	hash, err := hashOf(e.ChainHash)
	if err != nil {
		return nil, fmt.Errorf("proton: epoch %d chain hash: %w", e.EpochID, err)
	}

	cp := torchwood.Checkpoint{
		Origin: s.cfg.Origin,
		Tree:   tlog.Tree{N: e.EpochID, Hash: hash},
	}
	text := cp.String()
	return &source.Head{
		Origin: s.cfg.Origin,
		Size:   e.EpochID,
		Hash:   hash,
		Signed: []byte(text),
		Note:   &note.Note{Text: text},
	}, nil
}

// ConfirmCertificate confirms the epoch's certificate is present in one of the
// configured CT logs. With no logs configured it does nothing and says so by
// returning a nil confirmation, so an unwired deployment is unchanged.
func (s *Source) ConfirmCertificate(ctx context.Context, e *epoch) (*CTConfirmation, error) {
	if len(s.cfg.CTLogs) == 0 {
		return nil, nil
	}
	certs, err := e.certificates()
	if err != nil {
		return nil, fmt.Errorf("proton: %w", err)
	}
	conf, err := ConfirmInCT(ctx, certs, s.cfg.CTLogs)
	if err != nil {
		return nil, fmt.Errorf("proton: epoch %d: %w", e.EpochID, err)
	}
	return conf, nil
}

func (s *Source) epochAt(ctx context.Context, id int64) (*epoch, error) {
	var e epoch
	if err := s.get(ctx, fmt.Sprintf("/kt/v1/epochs/%d", id), &e); err != nil {
		return nil, err
	}
	if e.EpochID != id {
		return nil, fmt.Errorf("proton: asked for epoch %d, got %d", id, e.EpochID)
	}
	return &e, nil
}

// VerifyConsistency walks the epoch chain from our last witnessed epoch to the
// new one, recomputing each chain hash and checking each link.
//
// A break here is conclusive: the chain hash is a hash of the previous chain
// hash, so a mismatch means Proton published two incompatible histories. It is
// not something a transient read error can produce.
func (s *Source) VerifyConsistency(ctx context.Context, prev, next *source.Head) error {
	if prev == nil {
		return nil // trust on first use
	}
	if gap := next.Size - prev.Size; gap > s.cfg.MaxEpochsPerRound {
		return fmt.Errorf("proton: %d epochs behind (max %d per round); catching up", gap, s.cfg.MaxEpochsPerRound)
	}

	expected := hex.EncodeToString(prev.Hash[:])
	for id := prev.Size + 1; id <= next.Size; id++ {
		e, err := s.epochAt(ctx, id)
		if err != nil {
			// Could not read it. Withhold and retry; absence is never evidence.
			return err
		}
		if err := e.verifyChainHash(); err != nil {
			return &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: err.Error(),
				Prev:   prev, Next: next,
			}
		}
		if e.PrevChainHash != expected {
			return &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf("chain broken at epoch %d: it follows chain hash %s, but epoch %d published %s",
					id, e.PrevChainHash, id-1, expected),
				Prev: prev, Next: next,
			}
		}
		expected = e.ChainHash
	}

	if expected != hex.EncodeToString(next.Hash[:]) {
		return &source.ForkError{
			Origin: s.cfg.Origin,
			Reason: fmt.Sprintf("chain walk to epoch %d ends at %s, but the tip published %x",
				next.Size, expected, next.Hash[:]),
			Prev: prev, Next: next,
		}
	}
	return nil
}

// Backfill verifies Proton's retained epoch history.
//
// Proton keeps roughly 90 days (StartEpochID on any epoch names the oldest
// retained one), so this is a few hundred requests rather than a bulk download.
// Certificates are not re-checked: they live ~90 days and expire on the same
// schedule as retention, so demanding validity on historical epochs would report
// ordinary expiry as a problem. The chain hashes are what carry the history.
func (s *Source) Backfill(ctx context.Context, log *slog.Logger) (*source.BackfillResult, error) {
	var latest struct {
		Epochs []epoch `json:"Epochs"`
	}
	if err := s.get(ctx, "/kt/v1/epochs", &latest); err != nil {
		return nil, err
	}
	if len(latest.Epochs) == 0 {
		return nil, fmt.Errorf("proton: no epochs returned")
	}
	tip := latest.Epochs[0]
	for _, e := range latest.Epochs {
		if e.EpochID > tip.EpochID {
			tip = e
		}
	}

	from := tip.StartEpochID
	if from <= 0 {
		from = 1
	}

	res := &source.BackfillResult{From: from, To: tip.EpochID}
	var expected string
	for id := from; id <= tip.EpochID; id++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		e, err := s.epochAt(ctx, id)
		if err != nil {
			// Absence is not evidence; note it and resume linking from the next
			// epoch we can read.
			res.Gaps = append(res.Gaps, fmt.Sprintf("%d unreadable", id))
			expected = ""
			continue
		}
		res.Epochs++

		if err := e.verifyChainHash(); err != nil {
			return nil, &source.ForkError{Origin: s.cfg.Origin, Reason: err.Error()}
		}
		if expected != "" && e.PrevChainHash != expected {
			return nil, &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf("published history breaks at epoch %d: it follows %s, but epoch %d published %s",
					id, e.PrevChainHash, id-1, expected),
			}
		}
		expected = e.ChainHash

		if log != nil && res.Epochs%100 == 0 {
			log.Info("backfill", "origin", s.cfg.Origin, "epoch", id, "verified", res.Epochs)
		}
	}
	return res, nil
}
