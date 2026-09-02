// Package server exposes the witness's cosigned checkpoints.
//
// The read side of c2sp.org/tlog-witness is
//
//	GET <monitoring-prefix>/<origin-hash>/checkpoint
//
// returning the latest checkpoint we have cosigned for that log. Serving this
// is what makes our output consumable by the existing witness ecosystem rather
// than a private log file.
package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

type Server struct {
	Store   *store.Store
	VKey    string // our published cosignature verifier key
	Version string
}

// originHashes returns the identifiers a log may be addressed by. The spec
// identifies a log by a hash of its origin string; we accept both hex and
// unpadded base64url so that clients using either convention interoperate.
//
// TODO: pin this to the exact encoding in c2sp.org/tlog-witness and drop the
// other. Accepting both is a compatibility hedge, not a considered design.
func originHashes(origin string) []string {
	sum := sha256.Sum256([]byte(origin))
	return []string{
		hex.EncodeToString(sum[:]),
		base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// /<origin-hash>/checkpoint is routed through index, which dispatches on
	// the suffix; ServeMux cannot express the variable prefix directly.
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/.well-known/tlog-witness-key", s.key)
	mux.HandleFunc("/forks", s.forks)
	mux.HandleFunc("/audits", s.audits)
	mux.HandleFunc("/history", s.history)
	return mux
}

func (s *Server) key(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, s.VKey)
}

func (s *Server) checkpoint(w http.ResponseWriter, r *http.Request) {
	// Path is /<origin-hash>/checkpoint; ServeMux gives us the trailing part,
	// so recover the prefix from the raw path.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[1] != "checkpoint" {
		http.NotFound(w, r)
		return
	}
	want := parts[0]

	recs, err := s.Store.List()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for _, rec := range recs {
		for _, h := range originHashes(rec.Origin) {
			if h == want {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Write(rec.Cosigned)
				return
			}
		}
	}
	// 404 means "no cosignature on record for this log", which is a meaningful
	// answer: it is also what a monitor sees if we have withheld.
	http.Error(w, "no cosigned checkpoint for that origin", http.StatusNotFound)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Route /<origin-hash>/checkpoint here too.
		if strings.HasSuffix(r.URL.Path, "/checkpoint") {
			s.checkpoint(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	recs, err := s.Store.List()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "kt-witness %s\n\nwitness key:\n  %s\n\nwitnessed logs (%d):\n", s.Version, s.VKey, len(recs))
	for _, rec := range recs {
		fmt.Fprintf(w, "\n  origin: %s\n  size:   %d\n  path:   /%s/checkpoint\n  seen:   %s\n",
			rec.Origin, rec.Size, originHashes(rec.Origin)[0], rec.WitnessedAt.Format("2006-01-02T15:04:05Z"))
	}
	if hs, err := s.Store.Histories(); err == nil && len(hs) > 0 {
		fmt.Fprintf(w, "\nbackfilled history:\n")
		for _, h := range hs {
			fmt.Fprintf(w, "  %s: %d..%d (%d entries, %d gaps)\n",
				h.Origin, h.From, h.To, h.Epochs, len(h.Gaps))
		}
	}
	forks, err := s.Store.Forks()
	if err == nil && len(forks) > 0 {
		fmt.Fprintf(w, "\n!! %d FORK(S) RECORDED — see /forks\n", len(forks))
	}
}

// forks publishes recorded misbehaviour evidence. Disclosure is out-of-band by
// convention, but the evidence must be fetchable for anyone to reproduce it.
func (s *Server) forks(w http.ResponseWriter, r *http.Request) {
	forks, err := s.Store.Forks()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if len(forks) == 0 {
		fmt.Fprintln(w, "no forks recorded")
		return
	}
	for _, f := range forks {
		fmt.Fprintf(w, "origin: %s\ndetected: %s\nreason: %s\n\n--- previously witnessed ---\n%s\n--- conflicting ---\n%s\n\n",
			f.Origin, f.DetectedAt.Format("2006-01-02T15:04:05Z"), f.Reason, f.PrevSigned, f.NextSigned)
	}
}

// audits publishes tier-B sampling decisions and verification results.
//
// Declined epochs are shown alongside verified ones, with the beacon round that
// decided each: a coverage claim nobody can recompute is not a claim, and the
// whole point of beacon-driven selection is that a third party can check we
// sampled at the rate we advertise.
func (s *Server) audits(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		http.Error(w, "usage: /audits?origin=<log origin>", http.StatusBadRequest)
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	records, err := s.Store.Audits(origin, limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	var verified, sampled int
	for _, a := range records {
		if a.Sampled {
			sampled++
		}
		if a.Verified {
			verified++
		}
	}
	enc.Encode(map[string]any{
		"origin":            origin,
		"epochs_considered": len(records),
		"epochs_sampled":    sampled,
		"epochs_verified":   verified,
		"note": "construction verified for the sampled subset only; " +
			"chain continuity is verified for every epoch. Recompute selection as " +
			"first 8 bytes of SHA-256(beacon_randomness || \":\" || big-endian uint64 epoch) < rate * 2^64.",
		"audits": records,
	})
}

// history publishes what backfill established about each log's past.
//
// Worth publishing separately from the live head: it is a different claim, over
// a range we did not observe as it happened, and gaps in it are normal rather
// than suspicious.
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	hs, err := s.Store.Histories()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]any{
		"note": "verified published history, from a backfill pass. Gaps are recorded, " +
			"not treated as evidence: retention limits and partial writes both produce them.",
		"histories": hs,
	})
}
