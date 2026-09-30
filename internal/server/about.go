package server

import "net/http"

// AboutInfo is what the /about page states. witness-network.org requires a
// public page giving the cosignature/v1 vkey, the add-checkpoint URL, the
// lists followed, and how often they are re-read.
type AboutInfo struct {
	// PublicURL is the externally reachable base, e.g.
	// "https://witness.gdbsecurity.com". The add-checkpoint URL is derived
	// from it.
	PublicURL string
	// Operator is the operator name as registered.
	Operator string
	// Contact is how to reach the operator.
	Contact string
	// Lists are the witness-network log-list URLs this witness follows.
	Lists []string
	// ListRefresh is the configured re-read interval, as the config states it.
	ListRefresh string
}

// about is implemented by the /about task; this stub keeps the tree building.
func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
