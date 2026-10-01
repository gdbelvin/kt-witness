package server

import (
	"net/url"
	"path"
	"strings"
)

// What this witness knows about witness-network.org: the logs its lists name,
// and the witnesses that declare they follow those lists.
//
// Two very different grades of fact live here and the map must never blur
// them. A LOG on a list that has pushed to us is a log we cosign — we hold its
// checkpoint and our signature over it. A WITNESS in the network table is a
// declaration somebody wrote in a markdown file: it follows these lists. That
// says nothing whatever about whether it watches the same history we do, and
// it becomes evidence only when a cosignature of theirs verifies here under a
// key we hold. The map draws the first kind of witness solid and the second
// dashed, for exactly that reason.

// NetworkLog is one log named by a witness-network list.
type NetworkLog struct {
	Origin string
	// List is the short name of the first list known to name this log, e.g.
	// "staging/log-list-10qps-4klogs.1"; Lists is every one known.
	List    string
	Lists   []string
	QPD     int64
	Contact string
	// Static is true for a log that is also statically configured (and so
	// polled, and witnessed at whatever tier its source establishes). Such a
	// log is drawn in its own ecosystem's wedge with a marker, not as a
	// network log.
	Static bool
}

// NetworkWitness is one entry from the network's witness table.
type NetworkWitness struct {
	Operator string   `json:"operator"`
	Env      string   `json:"env"` // "staging" or "testing"
	Lists    []string `json:"lists"`
	About    string   `json:"about"`
	// VKey is the witness's cosignature/v1 verifier key, if the operator of
	// THIS witness has configured one. Empty means we cannot verify anything
	// it signs, and so it can only ever be drawn as a declaration.
	VKey string `json:"vkey"`
}

// Name is the witness's key name, or "" if no key is configured.
func (w NetworkWitness) Name() string {
	if i := strings.IndexByte(w.VKey, '+'); i > 0 {
		return w.VKey[:i]
	}
	return ""
}

// NetworkView is the network as this witness currently knows it. It is
// produced by a function rather than held as a value because the list fetcher
// adds logs while the process runs.
type NetworkView struct {
	// Lists are the short names of the lists this witness follows.
	Lists     []string
	Logs      []NetworkLog
	Witnesses []NetworkWitness
}

// networkKind is the ecosystem assigned to a list-discovered log that no
// Kinds entry names. networkTier is its tier: the push protocol carries a
// consistency proof from the previous size we cosigned, so what we establish
// is append-only, exactly as for a polled tier-A log.
const (
	networkKind = "network"
	networkTier = "A (checkpoint witness, pushed)"
)

// ShortListName reduces a list URL to the name the network's own tables use,
// such as "staging/log-list-10qps-4klogs.1". It understands the two shapes
// lists are published under — the repository's lists/ tree and the
// <env>.witness-network.org hosts — and otherwise falls back to the last path
// element.
func ShortListName(u string) string {
	if i := strings.Index(u, "/lists/"); i >= 0 {
		return u[i+len("/lists/"):]
	}
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return u
	}
	base := path.Base(p.Path)
	if h := p.Hostname(); strings.HasSuffix(h, ".witness-network.org") {
		env := strings.TrimSuffix(h, ".witness-network.org")
		if env != "" && !strings.Contains(env, ".") {
			return env + "/" + base
		}
	}
	if base == "/" || base == "." {
		return u
	}
	return base
}

// network returns the current network view, or nil when this witness is not
// configured to take part.
func (s *Server) network() *NetworkView {
	if s.Network == nil {
		return nil
	}
	v := s.Network()
	return &v
}
