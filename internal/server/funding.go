package server

import (
	"net/http"
	"os"
)

// The FLOSS/fund manifest, served at /funding.json.
//
// # Why a witness publishes one at all
//
// The independence rules in docs/cost.md say to publish who pays. A funding
// manifest is the machine-readable form of exactly that — it names the entity,
// the amounts asked for, and the terms money is accepted under, at a stable URL
// on the same domain as the audit findings. Someone reading a public accusation
// against a log operator can check, in one fetch, whether that operator funds
// the party making it.
//
// # Why it is loaded from disk and not embedded
//
// It was embedded, on the reasoning that a manifest which 404s after a deploy
// that forgot to copy a file is worse than none: the URL is submitted once to a
// directory and then fetched by strangers for years. That reasoning still
// holds, and the cost of it was that the manifest's contents — what this
// project asks to be paid, and the terms it will take money under — lived in a
// public repository. Those are the operator's business. The file is now read
// from FundingPath at startup, gitignored, and copied in by the deployment;
// deploy/funding.example.json documents the shape.
//
// A missing file is not fatal. A witness that refuses to start because nobody
// filled in a funding manifest would be a worse failure than the 404, and
// anyone running this from a clone has no manifest to publish. It is logged
// loudly once at startup instead, and the endpoint answers 404.

// loadFunding reads the manifest once, on first request.
//
// Lazily rather than in the constructor because every other field on Server is
// set by the caller and this one is read from the filesystem; deferring it
// keeps construction total and makes the test that swaps FundingPath trivial.
func (s *Server) loadFunding() []byte {
	s.fundingOnce.Do(func() {
		path := s.FundingPath
		if path == "" {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("no funding manifest; /funding.json will 404",
					"path", path, "err", err)
			}
			return
		}
		s.fundingBody = b
	})
	return s.fundingBody
}

func (s *Server) funding(w http.ResponseWriter, r *http.Request) {
	body := s.loadFunding()
	if len(body) == 0 {
		http.Error(w, "no funding manifest is published by this witness", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(body)
}

// fundingManifestURLs proves to floss.fund that whoever controls this domain
// also controls the repository the manifest points at.
//
// The check is deliberately one-directional: the manifest names a repository,
// and this file — which only the domain's operator can place — names the
// manifest back. Without it anyone could publish a funding.json claiming
// somebody else's project. One URL per line, text/plain.
//
// Suppressed when there is no manifest to point at, so a clone does not assert
// control over somebody else's funding URL.
func (s *Server) fundingManifestURLs(w http.ResponseWriter, r *http.Request) {
	if len(s.loadFunding()) == 0 {
		http.Error(w, "no funding manifest is published by this witness", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte("https://witness.gdbsecurity.com/funding.json\n"))
}
