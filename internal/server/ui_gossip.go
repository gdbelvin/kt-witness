package server

// The gossip page.
//
// It exists because the most important thing this witness can say about
// cross-witness comparison is what it *cannot* yet do, and that does not fit in
// a status table. A reader who sees "2 peers polled" and nothing else will
// reasonably conclude that split views are covered. They are not.

import (
	"github.com/gdbsecurity/kt-witness/internal/store"
	"html/template"
	"net/http"
	"sort"
	"strings"
)

type gossipPeer struct {
	Witness    string
	Views      int
	WithRoots  int
	Comparable int
	Agreed     int
	Origins    int
}

type gossipView struct {
	WitnessName string
	Peers       []gossipPeer

	// Seen are cosigners observed on checkpoints that this witness cannot
	// verify. Listed as work to do, not as corroboration: until a key is
	// fetched they prove nothing, and counting them as observers would flatter
	// the one number that must not be.
	//
	// Split in two because they are different problems. A NAMED cosigner is
	// somebody whose key can be gone and fetched — an errand. An anonymous one,
	// identified only by key hash because its log publishes no name, cannot be
	// looked up by anybody: sigsum's production log carries cosignatures whose
	// operators are not identifiable from any public source. A quorum you
	// cannot enumerate is not the same as a quorum that is not there.
	Seen      []store.SeenWitness
	Anonymous []store.SeenWitness

	TotalLogs    int
	SharedLogs   int
	Comparable   int
	Agreed       int
	SizeOnly     int
	AnyDivergent bool
}

// corroborated reports, per origin, whether any peer witness has attested it at
// a size we can compare. Used by the map to mark which logs have a second
// observer at all — which, on this deployment, is ten of eighty.
func (s *Server) corroborated(v *statusView) map[string][]string {
	out := map[string][]string{}
	for _, lv := range v.Logs {
		peers, err := s.Store.PeerAttestations(lv.Origin)
		if err != nil || len(peers) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, p := range peers {
			if p.Root == "" || seen[p.Witness] {
				continue
			}
			seen[p.Witness] = true
			out[lv.Origin] = append(out[lv.Origin], p.Witness)
		}
		sort.Strings(out[lv.Origin])
	}
	return out
}

// peerSummary aggregates what every peer witness has said. Shared by /gossip
// and the map so the two cannot disagree about the same fact.
func (s *Server) peerSummary(v *statusView) *gossipView {
	g := &gossipView{WitnessName: v.WitnessName, TotalLogs: len(v.Logs)}
	byWitness := map[string]*gossipPeer{}
	for _, lv := range v.Logs {
		rec, err := s.Store.Get(lv.Origin)
		if err != nil || rec == nil {
			continue
		}
		peers, err := s.Store.PeerAttestations(lv.Origin)
		if err != nil || len(peers) == 0 {
			continue
		}
		g.SharedLogs++
		for _, p := range peers {
			gp := byWitness[p.Witness]
			if gp == nil {
				gp = &gossipPeer{Witness: p.Witness}
				byWitness[p.Witness] = gp
			}
			gp.Views++
			gp.Origins++
			if p.Root == "" {
				g.SizeOnly++
				continue
			}
			gp.WithRoots++
			if p.Size != rec.Size {
				continue
			}
			gp.Comparable++
			g.Comparable++
			if p.Root == rootBase64(rec) {
				gp.Agreed++
				g.Agreed++
			} else {
				g.AnyDivergent = true
			}
		}
	}
	for _, gp := range byWitness {
		g.Peers = append(g.Peers, *gp)
	}
	sort.Slice(g.Peers, func(i, j int) bool { return g.Peers[i].Witness < g.Peers[j].Witness })
	if seen, err := s.Store.SeenWitnesses(); err == nil {
		for _, sw := range seen {
			if strings.HasPrefix(sw.Name, "keyhash:") {
				g.Anonymous = append(g.Anonymous, sw)
			} else {
				g.Seen = append(g.Seen, sw)
			}
		}
	}
	return g
}

func (s *Server) gossip(w http.ResponseWriter, r *http.Request) {
	v, err := s.buildStatus()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g := s.peerSummary(v)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = gossipTmpl.Execute(w, g)
}

var gossipTmpl = template.Must(template.New("gossip").Parse(gossipPageHTML))
