package server

import (
	_ "embed"
	"net/http"
)

// The FLOSS/fund manifest, served at /funding.json.
//
// It is embedded rather than read from disk because everything else this server
// publishes is embedded, and a funding manifest that 404s after a deploy that
// forgot to copy a file is worse than none: the URL is submitted once to a
// directory and then fetched by strangers for years.
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
//go:embed funding.json
var fundingJSON []byte

func (s *Server) funding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(fundingJSON)
}

// fundingManifestURLs proves to floss.fund that whoever controls this domain
// also controls the repository the manifest points at.
//
// The check is deliberately one-directional: the manifest names a repository,
// and this file — which only the domain's operator can place — names the
// manifest back. Without it anyone could publish a funding.json claiming
// somebody else's project. One URL per line, text/plain.
func (s *Server) fundingManifestURLs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte("https://witness.gdbsecurity.com/funding.json\n"))
}
