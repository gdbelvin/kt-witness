// Package signal witnesses Signal's Key Transparency deployment at tier A.
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
// # How the service root is obtained
//
// Signal never serves the service tree's root directly; libsignal reconstructs
// it from the combined-tree search proof, which is a large piece of machinery.
// There is a much shorter path.
//
// Because Signal deploys in third-party-auditing mode, the response carries one
// FullAuditorTreeHead per auditor, each with the auditor's Ed25519-signed root
// at its own (smaller) tree size, plus a consistency proof up to the service's
// size. A consistency proof does not merely check a root — run forwards, it
// *determines* one. So each auditor independently yields the service root.
//
// That gives three checks that all have to line up:
//
//  1. Every auditor's signature over its own root must verify.
//  2. All auditors must derive the *same* service root. They start from
//     different sizes with different proofs, so agreement is meaningful.
//  3. Signal's own signature over the derived root must verify. Signal emits one
//     signature per auditor key, each binding that key into the preimage.
//
// With a verified service root in hand, append-only across our own observations
// follows from the consistency proof the endpoint returns for lastTreeHeadSize —
// which is what makes this tier A rather than merely a signed-head observation.
//
// # What is opened, and what is not
//
// Every fetch also verifies a full search proof for the well-known
// "distinguished" key — VRF, prefix tree, batch inclusion, commitment — and
// requires the root it implies to equal the one the auditors and Signal's
// signature agree on. See search.go. That is the only check here that looks
// inside the log rather than at its shape, and it ships in the same response as
// the tree head, so it costs nothing extra.
//
// It remains a spot check. Signal's proofs are per-label and the VRF exists
// precisely so a third party cannot enumerate labels, so no amount of search
// proofs adds up to a construction audit of the directory. This source
// therefore stays at tier A and does not claim tier B; full coverage needs
// Signal's auditor feed, which is bilateral.
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
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/vrf"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// signalRoot is Signal's private CA. chat.signal.org does not chain to public
// roots, so it must be pinned. Taken verbatim from libsignal
// (rust/net/res/signal.cer), which is where Signal's own clients get it.
//
//go:embed signal-root.cer
var signalRoot []byte

// Production key material, pinned in libsignal rust/net/src/env.rs and
// cross-checked against the live wire.
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
	cfg      Config
	client   *http.Client
	sigKey   []byte
	vrfKey   []byte
	vrfPub   *vrf.PublicKey
	auditors [][]byte

	// lastSearch records the most recent verified search proof, so the witness
	// loop can report what it opened without re-running the check.
	lastSearch *SearchResult

	// ledger accumulates the log entries every verified search has opened, so
	// successive observations can be checked against each other.
	ledger       entryLedger
	ledgerLoaded bool

	// lastProof is the consistency proof carried by the most recent Fetch, for
	// the VerifyConsistency call that follows it. The witness core always pairs
	// those two calls for a given source, but that is coupling, so
	// lastProofFrom records which starting size the proof was requested for and
	// VerifyConsistency refuses to use it against any other.
	lastProof     []hash
	lastProofFrom uint64
}

type Config struct {
	// Origin is the canonical checkpoint origin we mint for Signal's tree.
	Origin string

	// Endpoint defaults to Signal production.
	Endpoint string

	// AuditorKeys defaults to all production auditors. More is strictly better:
	// each independently derives the service root and they are cross-checked.
	AuditorKeys []string

	// MinAuditors is how many auditor-derived roots must agree before we will
	// sign. Defaults to 2, so no single auditor can move our view alone.
	MinAuditors int

	// SigningKey and VRFKey are the service's keys. They are mixed into every
	// signature preimage, so getting them wrong makes verification fail closed.
	SigningKey string
	VRFKey     string

	// Entries, if set, makes the cross-observation ledger durable. Without it
	// the between-snapshot check only covers a single process lifetime.
	Entries source.EntryStore

	// SkipSearchProof disables opening the "distinguished" key. The proof ships
	// in the same response as the tree head, so verifying it is free and on by
	// default; this exists for tests that build synthetic tree heads.
	SkipSearchProof bool

	// Log, if set, reports each auditor's tree size so lag between them stays
	// observable.
	Log *slog.Logger
}

// DistinguishedKey is the well-known search key Signal publishes for every
// client to anchor on. It is the one label a third party can name without
// knowing anybody's identifier, which is what makes it the witness's handle on
// the log's contents.
var DistinguishedKey = []byte("distinguished")

func New(cfg Config) (*Source, error) {
	if cfg.Origin == "" {
		return nil, fmt.Errorf("signal: origin is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://chat.signal.org"
	}
	if len(cfg.AuditorKeys) == 0 {
		cfg.AuditorKeys = ProdAuditorKeys
	}
	if cfg.MinAuditors == 0 {
		cfg.MinAuditors = 2
	}
	if cfg.MinAuditors > len(cfg.AuditorKeys) {
		return nil, fmt.Errorf("signal: min_auditors %d exceeds %d configured auditor keys",
			cfg.MinAuditors, len(cfg.AuditorKeys))
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
	if s.vrfPub, err = vrf.NewPublicKey(s.vrfKey); err != nil {
		return nil, fmt.Errorf("signal: %w", err)
	}
	for _, k := range cfg.AuditorKeys {
		raw, err := decodeKey(k, "auditor")
		if err != nil {
			return nil, err
		}
		s.auditors = append(s.auditors, raw)
	}

	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(signalRoot)
	if err != nil {
		return nil, fmt.Errorf("signal: parse pinned root: %w", err)
	}
	roots.AddCert(cert)

	s.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: netmeter.Wrap(&http.Transport{
			// Pinned, not added to the system pool: only Signal's own CA may
			// authenticate this host.
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		}, cfg.Origin),
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

func (s *Source) Origin() string { return s.cfg.Origin }

// Tier is A, and deliberately not promoted by the search-proof verification.
//
// Tier B means the tree is checked to be *correctly built*, which for Proton
// means rebuilding 200 million published leaves. Signal publishes no leaf set
// and its proofs answer only about labels the asker can name — the VRF exists
// to make enumeration impossible — so verifying every proof we can obtain still
// examines a vanishing fraction of the directory. Calling that tier B would
// claim coverage we do not have.
func (s *Source) Tier() source.Tier { return source.TierA }

// LastSearch returns the most recently verified search proof, or nil.
func (s *Source) LastSearch() *SearchResult { return s.lastSearch }

// DerivedHead is false: the head carries Signal's own Ed25519 signature over
// the root, so a contradiction is Signal contradicting its own key.
func (s *Source) DerivedHead() bool { return false }

// signable rebuilds the preimage libsignal signs (TreeHead::to_signable_header):
//
//	[0,0] ciphersuite ‖ mode ‖ len16‖signing_key ‖ len16‖vrf_key ‖
//	len16‖auditor_key ‖ tree_size u64be ‖ timestamp i64be ‖ root
//
// For an auditor's own tree head the signer and the embedded auditor key are the
// same key; for the service's tree head the signer is the service key and the
// embedded key selects which of its signatures is being checked.
func (s *Source) signable(auditorKey []byte, size uint64, timestamp int64, root []byte) []byte {
	var buf []byte
	buf = append(buf, 0, 0)
	buf = append(buf, deploymentModeThirdPartyAuditing)
	for _, k := range [][]byte{s.sigKey, s.vrfKey, auditorKey} {
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

func (s *Source) known(key []byte) bool {
	for _, k := range s.auditors {
		if len(k) == len(key) && subtleEqual(k, key) {
			return true
		}
	}
	return false
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func (s *Source) Fetch(ctx context.Context, prev *source.Head) (*source.Head, error) {
	url := s.cfg.Endpoint + "/v1/key-transparency/distinguished"
	if prev != nil && prev.Size > 0 {
		// Asks the service for a consistency proof from the size we last
		// witnessed, which is what VerifyConsistency will check.
		url += "?lastTreeHeadSize=" + strconv.FormatInt(prev.Size, 10)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

	size, root, proof, err := s.verifyResponse(pb)
	if err != nil {
		return nil, err
	}

	s.lastProof = proof
	s.lastProofFrom = 0
	if prev != nil {
		s.lastProofFrom = uint64(prev.Size)
	}

	var h tlog.Hash
	copy(h[:], root[:])
	cp := torchwood.Checkpoint{
		Origin: s.cfg.Origin,
		Tree:   tlog.Tree{N: int64(size), Hash: h},
	}
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

// verifyResponse performs the three-way check described in the package comment
// and returns the verified service tree size, its root, and the consistency
// proof against our previously witnessed size.
func (s *Source) verifyResponse(pb []byte) (uint64, hash, []hash, error) {
	var zero hash

	top := parse(pb)
	fthRaw := first(top, 1)
	if fthRaw == nil {
		return 0, zero, nil, fmt.Errorf("signal: response has no FullTreeHead")
	}
	fth := parse(fthRaw)

	thRaw := first(fth, 1)
	if thRaw == nil {
		return 0, zero, nil, fmt.Errorf("signal: response has no TreeHead")
	}
	th := parse(thRaw)
	serviceSize := varintOf(th, 1)
	serviceTS := int64(varintOf(th, 2))
	if serviceSize == 0 {
		return 0, zero, nil, fmt.Errorf("signal: service tree is empty")
	}

	// Step 1 and 2: each auditor's signed root, run forward to the service size.
	derived := map[string]hash{}
	sizes := map[string]uint64{}
	for _, faRaw := range fth[4] {
		fa := parse(faRaw)
		pub := first(fa, 4)
		if pub == nil || !s.known(pub) {
			continue // an auditor we are not configured to trust
		}

		ahRaw := first(fa, 1)
		if ahRaw == nil {
			continue
		}
		ah := parse(ahRaw)
		aSize := varintOf(ah, 1)
		aTS := int64(varintOf(ah, 2))
		sig := first(ah, 3)
		rootBytes := first(fa, 2)

		if aSize > serviceSize {
			return 0, zero, nil, fmt.Errorf("signal: auditor %s claims size %d beyond service size %d",
				hex.EncodeToString(pub)[:16], aSize, serviceSize)
		}

		var serviceRoot hash
		switch {
		case aSize == serviceSize:
			// Caught up: the auditor's own root is the service root. It still
			// has to be signed — an unsigned root must never count towards the
			// quorum, or MinAuditors quietly means less than it says.
			if len(rootBytes) != 32 || len(sig) != ed25519.SignatureSize {
				continue
			}
			if !ed25519.Verify(pub, s.signable(pub, aSize, aTS, rootBytes), sig) {
				return 0, zero, nil, fmt.Errorf("signal: auditor %s signature does not verify",
					hex.EncodeToString(pub)[:16])
			}
			copy(serviceRoot[:], rootBytes)
		default:
			if len(rootBytes) != 32 || len(sig) != ed25519.SignatureSize {
				continue
			}
			if !ed25519.Verify(pub, s.signable(pub, aSize, aTS, rootBytes), sig) {
				return 0, zero, nil, fmt.Errorf("signal: auditor %s signature does not verify over its tree head",
					hex.EncodeToString(pub)[:16])
			}
			var aRoot hash
			copy(aRoot[:], rootBytes)

			proof := make([]hash, 0, len(fa[3]))
			for _, p := range fa[3] {
				if len(p) != 32 {
					return 0, zero, nil, fmt.Errorf("signal: auditor %s consistency hash is %d bytes",
						hex.EncodeToString(pub)[:16], len(p))
				}
				var ph hash
				copy(ph[:], p)
				proof = append(proof, ph)
			}
			if serviceRoot, err2 := deriveRoot(aSize, serviceSize, proof, aRoot); err2 != nil {
				return 0, zero, nil, fmt.Errorf("signal: auditor %s: %w", hex.EncodeToString(pub)[:16], err2)
			} else {
				derived[hex.EncodeToString(pub)] = serviceRoot
				sizes[hex.EncodeToString(pub)] = aSize
				continue
			}
		}
		derived[hex.EncodeToString(pub)] = serviceRoot
		sizes[hex.EncodeToString(pub)] = aSize
	}

	if s.cfg.Log != nil {
		// Per-auditor lag was visible when each auditor was its own log; now
		// that they are cross-checked into one head, log it explicitly or it
		// disappears.
		for key, size := range sizes {
			s.cfg.Log.Info("signal auditor",
				"auditor", key[:16], "size", size, "behind_service", serviceSize-size)
		}
	}

	if len(derived) < s.cfg.MinAuditors {
		return 0, zero, nil, fmt.Errorf("signal: only %d auditor(s) yielded a service root, need %d",
			len(derived), s.cfg.MinAuditors)
	}

	// All auditors must land on the same root. They start from different sizes
	// with different proofs, so disagreement means at least one signed a root
	// belonging to a different history — conclusive misbehaviour by someone,
	// though the response alone does not say by whom.
	var root hash
	var refKey string
	for k, v := range derived {
		if refKey == "" {
			root, refKey = v, k
			continue
		}
		if v != root {
			return 0, zero, nil, &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf(
					"auditors disagree on the service root at size %d: %s implies %x, %s implies %x "+
						"(at least one signed a root from a different history; the response does not say which)",
					serviceSize, refKey[:16], root, k[:16], v),
				// The whole response, verbatim, so the disagreement can be
				// reproduced by anyone from the signed bytes alone.
				Next: &source.Head{Origin: s.cfg.Origin, Size: int64(serviceSize), Signed: pb},
			}
		}
	}

	// Step 3: Signal's own signature over the derived root.
	verified := 0
	for _, sigRaw := range th[3] {
		sm := parse(sigRaw)
		auditorKey := first(sm, 1)
		sig := first(sm, 2)
		if len(auditorKey) != 32 || len(sig) != ed25519.SignatureSize || !s.known(auditorKey) {
			continue
		}
		if ed25519.Verify(s.sigKey, s.signable(auditorKey, serviceSize, serviceTS, root[:]), sig) {
			verified++
		}
	}
	if verified == 0 {
		return 0, zero, nil, fmt.Errorf(
			"signal: no service signature verifies over the derived root at size %d", serviceSize)
	}

	// Step 4: open the "distinguished" key against the root just established.
	//
	// The response already carries a full search proof — VRF, prefix tree, batch
	// inclusion, commitment — so this costs no extra request. It is the only
	// check here that looks inside the log rather than at its shape, and its
	// root must match the one three auditors and Signal's own signature agree
	// on, which is a demanding thing for a wrong proof to manage.
	//
	// A failure withholds and never accuses. We cannot distinguish a malformed
	// proof from a dishonest one, and the accusation would be permanent.
	if !s.cfg.SkipSearchProof {
		condensed := first(top, 2)
		if condensed == nil {
			return 0, zero, nil, fmt.Errorf("signal: response carries no distinguished search proof")
		}
		res, err := verifySearch(s.vrfPub, DistinguishedKey, nil, parse(condensed), serviceSize)
		if err != nil {
			return 0, zero, nil, err
		}
		if res.Root != root {
			return 0, zero, nil, fmt.Errorf(
				"signal: the distinguished search proof implies root %x, but the signed tree head at "+
					"size %d has root %x; withholding", res.Root[:], serviceSize, root[:])
		}

		// Step 5: cross-check against every previous observation. A log entry is
		// immutable once written, so an entry that changes contents between two
		// proofs — both chaining to roots Signal signed — is a contradiction the
		// append-only checks cannot see.
		//
		// It is reported as a withholding rather than a fork. The evidence would
		// support an accusation, but a fork is permanent and public, and this
		// path is a fresh reimplementation of somebody else's tree math; a bug
		// here would libel Signal irreversibly. Withholding costs Signal nothing
		// and gets a human's attention, which is the right trade until this code
		// has a production record. See TODO.md.
		if err := s.loadLedger(); err != nil {
			return 0, zero, nil, err
		}
		if err := s.ledger.merge(res.Opened); err != nil {
			return 0, zero, nil, fmt.Errorf(
				"signal: %w; this contradicts append-only and needs a human look, but "+
					"withholding rather than accusing", err)
		}

		if s.cfg.Entries != nil {
			if err := s.cfg.Entries.PutLogEntries(s.cfg.Origin, res.Opened); err != nil {
				// Persisting is best effort: failing to remember is not a reason
				// to withhold a cosignature that is otherwise fully verified.
				if s.cfg.Log != nil {
					s.cfg.Log.Warn("persisting verified log entries", "origin", s.cfg.Origin, "err", err)
				}
			}
		}

		s.lastSearch = res
		if s.cfg.Log != nil {
			s.cfg.Log.Info("signal search proof verified",
				"key", string(DistinguishedKey), "index", hex.EncodeToString(res.Index[:8]),
				"first_position", res.Pos, "version", res.Version,
				"entries_opened", res.Entries, "entries_cross_checked", len(s.ledger.seen))
		}
	}

	// FullTreeHead.distinguished (field 3) is the consistency proof against the
	// size we asked about; field 2 is the equivalent for a plain search.
	raw := fth[3]
	if len(raw) == 0 {
		raw = fth[2]
	}
	proof := make([]hash, 0, len(raw))
	for _, p := range raw {
		if len(p) != 32 {
			return 0, zero, nil, fmt.Errorf("signal: consistency hash is %d bytes, want 32", len(p))
		}
		var ph hash
		copy(ph[:], p)
		proof = append(proof, ph)
	}

	return serviceSize, root, proof, nil
}

// VerifyConsistency proves the new service tree extends the one we witnessed.
//
// Both roots carry Signal's signature, so a proof that fails to connect them
// means Signal either forked or served a broken proof. Tempting to call that a
// fork — but we cannot tell which, and the accusation is permanent, so we
// withhold instead. That is not a loss: withholding is the enforcement
// mechanism, and a genuine split view is detected by comparing what different
// witnesses cosigned, which is exactly what our published checkpoints are for.
// A persistent failure here is worth a human look.
func (s *Source) VerifyConsistency(_ context.Context, prev, next *source.Head) error {
	if prev == nil {
		return nil // trust on first use
	}
	if s.lastProofFrom != uint64(prev.Size) {
		// The proof we hold was requested against a different starting size, so
		// it cannot speak to this transition. Withhold rather than misuse it.
		return fmt.Errorf("signal: consistency proof was fetched for size %d, not %d",
			s.lastProofFrom, prev.Size)
	}

	derived, err := deriveRoot(uint64(prev.Size), uint64(next.Size), s.lastProof, prev.Hash)
	if err != nil {
		// Malformed or absent proof: we could not check, which is not evidence.
		return fmt.Errorf("signal: consistency %d->%d unproven: %w", prev.Size, next.Size, err)
	}
	if derived != next.Hash {
		return fmt.Errorf(
			"signal: no valid consistency proof from size %d (root %x) to size %d (root %x): "+
				"the proof supplied implies root %x; withholding",
			prev.Size, prev.Hash[:], next.Size, next.Hash[:], derived[:])
	}
	return nil
}

// --- minimal protobuf reader -------------------------------------------------
//
// Hand-rolled rather than generated: we need a handful of field numbers from a
// few nested messages, and a hand-written reader is small enough to audit in
// full, which matters more here than convenience.

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

// loadLedger populates the cross-observation ledger from durable storage, once.
//
// A restart would otherwise reset between-snapshot coverage to nothing while
// still reporting success, which is the quiet kind of wrong.
func (s *Source) loadLedger() error {
	if s.ledgerLoaded || s.cfg.Entries == nil {
		s.ledgerLoaded = true
		return nil
	}
	seen, err := s.cfg.Entries.LogEntries(s.cfg.Origin)
	if err != nil {
		return fmt.Errorf("signal: loading verified entries: %w", err)
	}
	if s.ledger.seen == nil {
		s.ledger.seen = make(map[uint64]hash, len(seen))
	}
	for id, h := range seen {
		s.ledger.seen[id] = h
	}
	s.ledgerLoaded = true
	if s.cfg.Log != nil && len(seen) > 0 {
		s.cfg.Log.Info("restored verified log entries",
			"origin", s.cfg.Origin, "entries", len(seen))
	}
	return nil
}
