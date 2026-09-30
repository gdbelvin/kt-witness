package push

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// DefaultMaxBodyBytes bounds a request body. A checkpoint with a full 63-line
// proof is a few kilobytes; anything near this is not a checkpoint.
const DefaultMaxBodyBytes = 1 << 20

// maxProofLines is the spec's own bound: "The client MUST NOT send more than 63
// consistency proof lines."
const maxProofLines = 63

const metricRequests = "kt_witness_push_requests_total"

// Config configures a Handler.
type Config struct {
	// Witness is the core every pushed checkpoint goes through. Required.
	Witness *witness.Witness
	// Store is read for our current size. Defaults to Witness.Store; it must be
	// the same store, or the old-size check would be against the wrong view.
	Store *store.Store
	// Registry resolves an origin to a log that may push. Required.
	Registry Registry
	Log      *slog.Logger
	// Now is the clock for rate limiting and for the head's FetchedAt.
	// Defaults to time.Now.
	Now func() time.Time
	// MaxBodyBytes defaults to DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Handler serves POST /add-checkpoint.
type Handler struct {
	cfg     Config
	limiter *limiter
}

// New returns a Handler. It panics if Witness or Registry is nil: both are
// wiring, and a handler without them could only fail every request.
func New(cfg Config) *Handler {
	if cfg.Witness == nil || cfg.Registry == nil {
		panic("push: New needs a Witness and a Registry")
	}
	if cfg.Store == nil {
		cfg.Store = cfg.Witness.Store
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	metrics.Describe(metricRequests, metrics.Counter,
		"add-checkpoint requests, by response status.")
	return &Handler{cfg: cfg, limiter: newLimiter()}
}

// response is what one request resolves to. Deciding it in one place and
// writing it in another keeps the status accounting to a single line.
type response struct {
	status      int
	contentType string
	body        []byte
	retryAfter  time.Duration
}

func plain(status int, format string, args ...any) *response {
	return &response{
		status:      status,
		contentType: "text/plain; charset=utf-8",
		body:        []byte(fmt.Sprintf(format, args...) + "\n"),
	}
}

// conflict is the spec's 409: our latest cosigned size, so the log can retry
// with a proof from there.
func conflict(size int64) *response {
	return &response{
		status:      http.StatusConflict,
		contentType: "text/x.tlog.size",
		body:        []byte(strconv.FormatInt(size, 10) + "\n"),
	}
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	resp := h.serve(rw, r)
	metrics.Inc(metricRequests, map[string]string{"status": strconv.Itoa(resp.status)})
	if resp.status == http.StatusMethodNotAllowed {
		rw.Header().Set("Allow", http.MethodPost)
	}
	if resp.retryAfter > 0 {
		rw.Header().Set("Retry-After", strconv.FormatInt(int64(resp.retryAfter/time.Second), 10))
	}
	rw.Header().Set("Content-Type", resp.contentType)
	rw.WriteHeader(resp.status)
	if _, err := rw.Write(resp.body); err != nil {
		h.cfg.Log.Debug("push: writing response", "err", err)
	}
}

// request is a parsed add-checkpoint body.
type request struct {
	old   int64
	proof tlog.TreeProof
	note  []byte // the checkpoint note exactly as sent, signatures included
}

// parseRequest splits the body per c2sp.org/tlog-witness: an "old N" line, up
// to 63 base64 proof lines, an empty line, then the signed checkpoint.
func parseRequest(body []byte) (*request, error) {
	head, noteBytes, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, errors.New("missing empty line before the checkpoint")
	}
	lines := strings.Split(string(head), "\n")
	size, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return nil, errors.New(`first line must be "old <size>"`)
	}
	old, err := strconv.ParseInt(size, 10, 64)
	// Canonical decimal only, so one size has one spelling.
	if err != nil || old < 0 || strconv.FormatInt(old, 10) != size {
		return nil, fmt.Errorf("malformed old size %q", size)
	}
	proofLines := lines[1:]
	if len(proofLines) > maxProofLines {
		return nil, fmt.Errorf("%d consistency proof lines, more than %d", len(proofLines), maxProofLines)
	}
	proof := make(tlog.TreeProof, len(proofLines))
	for i, ln := range proofLines {
		if proof[i], err = tlog.ParseHash(ln); err != nil {
			return nil, fmt.Errorf("consistency proof line %d: %v", i+1, err)
		}
	}
	return &request{old: old, proof: proof, note: noteBytes}, nil
}

func (h *Handler) serve(rw http.ResponseWriter, r *http.Request) *response {
	if r.Method != http.MethodPost {
		return plain(http.StatusMethodNotAllowed, "add-checkpoint takes POST")
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, h.cfg.MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return plain(http.StatusRequestEntityTooLarge, "request body over %d bytes", tooBig.Limit)
		}
		return plain(http.StatusBadRequest, "reading request body: %v", err)
	}
	req, err := parseRequest(body)
	if err != nil {
		return plain(http.StatusBadRequest, "malformed request: %v", err)
	}

	origin, _, _ := bytes.Cut(req.note, []byte("\n"))
	lg, ok := h.cfg.Registry.Lookup(string(origin))
	if !ok || lg == nil || lg.Verifier == nil {
		return plain(http.StatusNotFound, "unknown log")
	}
	l := h.cfg.Log.With("origin", lg.Origin, "old", req.old)

	// Signatures from keys we do not hold — other witnesses' cosignatures on a
	// note the log is collecting — are ignored, as the spec requires; note.Open
	// puts them in UnverifiedSigs and fails only if the log's own is missing.
	n, err := note.Open(req.note, note.VerifierList(lg.Verifier))
	if err != nil {
		var unverified *note.UnverifiedNoteError
		var invalid *note.InvalidSignatureError
		if errors.As(err, &unverified) || errors.As(err, &invalid) {
			return plain(http.StatusForbidden, "invalid signature")
		}
		return plain(http.StatusBadRequest, "malformed checkpoint note: %v", err)
	}
	cp, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return plain(http.StatusBadRequest, "malformed checkpoint: %v", err)
	}
	if cp.Origin != lg.Origin {
		// Lookup was by this very line, so only a registry that normalises
		// origins could get here. Refuse rather than let one log's key speak
		// for another's name.
		return plain(http.StatusNotFound, "unknown log")
	}
	l = l.With("size", cp.N)

	// Rate limited only once the log's signature has verified, so nobody but
	// the log can spend its allowance.
	if ok, wait := h.limiter.allow(lg.Origin, lg.QPD, h.cfg.Now()); !ok {
		resp := plain(http.StatusTooManyRequests, "rate limit of %d requests per day exceeded", lg.QPD)
		resp.retryAfter = wait
		return resp
	}

	if req.old > cp.N {
		return plain(http.StatusBadRequest, "old size %d is larger than checkpoint size %d", req.old, cp.N)
	}
	if req.old == 0 && len(req.proof) != 0 {
		return plain(http.StatusBadRequest, "consistency proof must be empty when old size is 0")
	}

	rec, err := h.cfg.Store.Get(lg.Origin)
	if err != nil {
		l.Error("push: reading stored head", "err", err)
		return plain(http.StatusInternalServerError, "internal error")
	}
	var known int64
	if rec != nil {
		known = rec.Size
	}
	// Includes "old 0" for a log we already hold: the log has lost track of
	// us, and our size is exactly what it needs to build a proof.
	if req.old != known {
		return conflict(known)
	}

	// A signed checkpoint at the size we hold with a different root is the log
	// contradicting its own signature. Process records it as a fork; the spec
	// answers it with a 409. Noted here, before Process, because afterwards a
	// ForkError alone cannot tell this from a log that was already poisoned.
	//
	// Only the push that reveals the split gets the 409. Once the fork is on
	// record, the same conflicting root pushed again is a forked log asking,
	// and gets the forked log's 403 — a 409 would invite it to retry forever.
	split := rec != nil && cp.N == rec.Size && cp.Hash != rec.Hash
	if split {
		forked, err := h.cfg.Store.IsForked(lg.Origin)
		if err != nil {
			return plain(http.StatusInternalServerError, "store: %v", err)
		}
		split = !forked
	}

	src := &pushedSource{
		old:   req.old,
		proof: req.proof,
		head: &source.Head{
			Origin:    cp.Origin,
			Size:      cp.N,
			Hash:      cp.Hash,
			Signed:    req.note,
			Note:      n,
			FetchedAt: h.cfg.Now(),
		},
	}
	// A re-push of the tree we hold is cosigned afresh, as litewitness does.
	// A log re-pushing an unchanged tree usually wants exactly that: a current
	// timestamp, which the stored cosignature (up to RefreshInterval old) would
	// not give it. The tree is one we have already proved, so a fresh signature
	// attests nothing new beyond liveness, and the log's own signature and its
	// qpd budget bound how often it can ask.
	if rec != nil && cp.N == rec.Size && !split {
		src.refresh = true
	}

	out, err := h.cfg.Witness.Process(r.Context(), src)
	if err != nil {
		return h.processError(l, lg.Origin, split, err)
	}

	var signed []byte
	switch {
	case out.Cosigned:
		signed = out.Note
	case out.Unchanged:
		// Re-read: the record Process compared against may not be the one we
		// read above, and the poller may have refreshed it in between.
		cur, err := h.cfg.Store.Get(lg.Origin)
		if err != nil {
			l.Error("push: re-reading stored head", "err", err)
			return plain(http.StatusInternalServerError, "internal error")
		}
		if cur == nil || cur.Size != cp.N || !h.storedMatches(cur, n.Text) {
			var size int64
			if cur != nil {
				size = cur.Size
			}
			return conflict(size)
		}
		signed = cur.Cosigned
	default:
		l.Error("push: Process returned neither a cosignature nor an error", "outcome", out)
		return plain(http.StatusInternalServerError, "internal error")
	}

	sigs, err := h.ourSignatures(signed)
	if err != nil {
		l.Error("push: extracting our cosignature", "err", err)
		return plain(http.StatusInternalServerError, "internal error")
	}
	l.Info("push: cosigned", "refreshed", out.Refreshed, "unchanged", out.Unchanged)
	return &response{status: http.StatusOK, contentType: "text/plain; charset=utf-8", body: sigs}
}

// processError maps a refusal from the witness core to a status.
func (h *Handler) processError(l *slog.Logger, origin string, split bool, err error) *response {
	var fe *source.ForkError
	switch {
	case errors.As(err, &fe):
		if split {
			// The spec's answer to a same-size conflict. The fork is already
			// recorded by now; the log learns nothing from us but our size.
			return h.currentConflict(l, origin)
		}
		// A log we have recorded forking. The spec has no code for this, and a
		// 409 would be wrong: the log would fetch a proof and retry, forever.
		// 403 says "this witness will not sign for you", which is the truth
		// until a human has reviewed the evidence.
		return plain(http.StatusForbidden,
			"log previously forked; cosigning is permanently withheld pending human review")
	case errors.Is(err, errBadProof):
		return plain(http.StatusUnprocessableEntity, "invalid consistency proof")
	case errors.Is(err, store.ErrRaced), errors.Is(err, errMoved):
		// The poller advanced our view of this log while the request was in
		// flight. Answer as though the request had arrived a moment later.
		return h.currentConflict(l, origin)
	case errors.Is(err, witness.ErrStale):
		return plain(http.StatusServiceUnavailable, "witness too slow to cosign; retry")
	}
	// Everything else is the core withholding because it could not establish
	// consistency — not a verdict on the log, so the log may retry.
	l.Warn("push: withheld", "err", err)
	return plain(http.StatusServiceUnavailable, "cosignature withheld: %v", err)
}

func (h *Handler) currentConflict(l *slog.Logger, origin string) *response {
	rec, err := h.cfg.Store.Get(origin)
	if err != nil {
		l.Error("push: reading stored head", "err", err)
		return plain(http.StatusInternalServerError, "internal error")
	}
	if rec == nil {
		return conflict(0)
	}
	return conflict(rec.Size)
}

// storedMatches reports whether rec's cosigned note verifies under our key and
// carries exactly text as its body.
func (h *Handler) storedMatches(rec *store.Record, text string) bool {
	if len(rec.Cosigned) == 0 {
		return false
	}
	stored, err := note.Open(rec.Cosigned, note.VerifierList(h.cfg.Witness.Signer.Verifier()))
	return err == nil && stored.Text == text
}

// ourSignatures returns just this witness's signature lines from a signed
// note, which is what the spec's 200 body is.
//
// Torchwood can take everything after the last blank line, because it signs a
// bare note. The core signs the note it was handed, which still carries the
// log's own signature, so that would echo the log's line back to it. Lines are
// matched on name AND key hash: a name alone could be claimed by anyone.
func (h *Handler) ourSignatures(signed []byte) ([]byte, error) {
	i := bytes.LastIndex(signed, []byte("\n\n"))
	if i < 0 {
		return nil, errors.New("signed note has no signature block")
	}
	name, hash := h.cfg.Witness.Signer.Name(), h.cfg.Witness.Signer.KeyHash()
	var out []byte
	for _, ln := range strings.SplitAfter(string(signed[i+2:]), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSuffix(ln, "\n"), "— ")
		if !ok {
			continue
		}
		n, b64, ok := strings.Cut(rest, " ")
		if !ok || n != name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 4 || binary.BigEndian.Uint32(raw) != hash {
			continue
		}
		out = append(out, strings.TrimSuffix(ln, "\n")+"\n"...)
	}
	if len(out) == 0 {
		return nil, errors.New("signed note carries no signature of ours")
	}
	return out, nil
}

var (
	// errBadProof is a pushed consistency proof that does not verify. It is
	// deliberately NOT a ForkError: the proof is the client's, not the log's
	// signed statement, and a buggy client sending garbage must not be able
	// to get a log permanently refused.
	errBadProof = errors.New("push: consistency proof does not verify")

	// errMoved means the stored head Process compared against is not the one
	// the request's old size named, so the request's proof is about a
	// different pair of trees. Racing the poller, not misbehaviour.
	errMoved = errors.New("push: stored head moved while the request was in flight")
)

// pushedSource presents one pushed checkpoint to the witness core as a Source,
// so it passes the same gates as a polled one.
type pushedSource struct {
	head    *source.Head
	old     int64
	proof   tlog.TreeProof
	refresh bool
}

func (s *pushedSource) Origin() string { return s.head.Origin }

// Tier is A: the log proves append-only growth with every push, and we check
// that proof. Entries are never seen, so nothing stronger is claimed.
func (s *pushedSource) Tier() source.Tier { return source.TierA }

// DerivedHead is false: the head is the log's own signed statement.
func (s *pushedSource) DerivedHead() bool { return false }

func (s *pushedSource) Fetch(context.Context, *source.Head) (*source.Head, error) {
	return s.head, nil
}

func (s *pushedSource) RefreshNow() bool { return s.refresh }

// VerifyConsistency checks the proof the client sent.
//
// Only the pushed proof is available, and it only speaks to the pair of trees
// the request named: from the old size to the pushed checkpoint. Any other
// pair — the core asking whether a smaller tree is a prefix, or a stored head
// that moved under us — is answered with errMoved rather than a verdict.
func (s *pushedSource) VerifyConsistency(_ context.Context, prev, next *source.Head) error {
	var prevSize int64
	if prev != nil {
		prevSize = prev.Size
	}
	if prevSize != s.old || next != s.head {
		return errMoved
	}
	if prevSize == 0 {
		// Every tree extends the empty one, and tlog.CheckTree refuses an old
		// size of zero, so there is nothing to check.
		return nil
	}
	if err := tlog.CheckTree(s.proof, next.Size, next.Hash, prev.Size, prev.Hash); err != nil {
		return fmt.Errorf("%w: %d -> %d: %v", errBadProof, prev.Size, next.Size, err)
	}
	return nil
}
