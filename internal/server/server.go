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
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

type Server struct {
	Store   *store.Store
	VKey    string // our published cosignature verifier key
	Version string

	// Tiers maps an origin to the assurance tier it is witnessed at. Published
	// because it is the single thing a reader must not misjudge: a tier-A
	// cosignature says the log is append-only and nothing whatever about
	// whether its contents are correctly constructed.
	Tiers map[string]string

	// Kinds maps an origin to what it makes transparent: kt, ct, software.
	// Orthogonal to Tiers — a tier-A certificate log and a tier-A key
	// transparency log are the same strength of claim about different things.
	Kinds map[string]string

	// Storage locates the database and mirror so their size can be reported.
	Storage StoragePaths

	// CoverageTTL bounds how stale a coverage figure may be. Zero uses the
	// default of one minute; negative disables caching entirely and pays the
	// full audit scan on every read.
	//
	// Coverage moves by a few hundred epochs an hour, so a minute of staleness
	// is invisible on the dashboard and removes a scan of the whole audit
	// history from the request path. It is configurable because the tier is
	// derived from the same figure, and a caller that wants the tier to be
	// exact the instant an audit lands should be able to say so.
	CoverageTTL time.Duration

	// coverage caches the per-origin audit scan, which is otherwise recomputed
	// from every audit record on every scrape and every page load.
	coverage coverageCache

	coverageOnce sync.Once
}

// cov returns the coverage cache, applying CoverageTTL on first use.
func (s *Server) cov() *coverageCache {
	s.coverageOnce.Do(func() { s.coverage.ttl = s.CoverageTTL })
	return &s.coverage
}

// originHashes returns the identifiers a log may be addressed by.
//
// This was carried as a TODO to "pin the encoding to the spec". Checked, and
// there is nothing to pin to: c2sp.org/tlog-witness specifies only
// "POST <submission prefix>/add-checkpoint" and never defines what the
// submission prefix contains. The path is deliberately opaque and
// operator-chosen.
//
// So accepting both lowercase hex and unpadded base64url of SHA-256(origin) is
// the considered design rather than a hedge: it costs one extra map entry and
// makes us reachable by either convention a client might have inferred.
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
	mux.HandleFunc("/status.json", s.statusJSON)
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/.well-known/tlog-witness-key", s.key)
	mux.HandleFunc("/forks", s.forks)
	mux.HandleFunc("/audits", s.audits)
	mux.HandleFunc("/history", s.history)
	mux.HandleFunc("/applications", s.applications)
	mux.HandleFunc("/log", s.logPage)
	mux.HandleFunc("/gossip", s.gossip)
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
	// A browser gets the status page; everything else keeps the plain-text
	// contract that monitors and the C2SP tooling already read. Same URL, so no
	// existing consumer has to change and no second address has to be published.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		s.ui(w, r)
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
		// A withdrawn finding is not a live one. Banner only what still stands,
		// and say separately that something was retracted — a reader who sees
		// neither cannot tell a clean witness from one that quietly buried a
		// mistake.
		retracted := s.retractedOrigins()
		live := 0
		for _, f := range forks {
			if !retracted[f.Origin] {
				live++
			}
		}
		if live > 0 {
			fmt.Fprintf(w, "\n!! %d FORK(S) RECORDED — see /forks\n", live)
		}
		if n := len(forks) - live; n > 0 {
			fmt.Fprintf(w, "\n%d withdrawn finding(s) — see /forks\n", n)
		}
	}
}

// retractedOrigins is the set of logs whose fork finding has been withdrawn.
func (s *Server) retractedOrigins() map[string]bool {
	out := map[string]bool{}
	rs, err := s.Store.Retractions()
	if err != nil {
		return out
	}
	for _, r := range rs {
		out[r.Origin] = true
	}
	return out
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
	// Retractions are shown against the finding they withdraw, not on a separate
	// page. An accusation and its withdrawal have to travel together: anyone
	// reading this is reading it because they want to know whether a log
	// misbehaved, and showing the claim without the retraction would leave them
	// believing something we no longer assert.
	byOrigin := map[string]*store.Retraction{}
	if rs, err := s.Store.Retractions(); err == nil {
		for _, r := range rs {
			byOrigin[r.Origin] = r
		}
	}
	for _, f := range forks {
		if r := byOrigin[f.Origin]; r != nil {
			fmt.Fprintf(w, "*** WITHDRAWN %s ***\nThis finding was retracted and is NOT an accusation against %s.\nreason: %s\n\nThe original evidence is kept below so the reversal can be checked as\nreadily as the claim.\n\n",
				r.RetractedAt.Format("2006-01-02T15:04:05Z"), f.Origin, r.Reason)
		}
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

// applications publishes per-application heads observed inside a witnessed log.
//
// Kept separate from the cosigned checkpoints on purpose. These are Apple
// per-application heads read out of the Top-Level Tree — including iMessage,
// whose own tree is not publicly served — but they are signed by keys Apple does
// not publish, and are not yet bound to the root we verify. So they are reported
// as observations and never cosigned, and the note says so rather than leaving a
// reader to assume the same footing as everything else here.
func (s *Server) applications(w http.ResponseWriter, r *http.Request) {
	heads, err := s.Store.AppHeads()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]any{
		"note": "OBSERVATIONS, NOT ATTESTATIONS. These are per-application tree heads " +
			"read from the leaves of a log we witness. They are signed by keys the operator " +
			"does not publish, and are not bound to the verified root, so they are never " +
			"cosigned. Contradictions are recorded for a human to judge.",
		"applications": heads,
	})
}
