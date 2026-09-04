package server

// The gossip page.
//
// It exists because the most important thing this witness can say about
// cross-witness comparison is what it *cannot* yet do, and that does not fit in
// a status table. A reader who sees "2 peers polled" and nothing else will
// reasonably conclude that split views are covered. They are not.

import (
	"html/template"
	"net/http"
	"sort"
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

	TotalLogs    int
	SharedLogs   int
	Comparable   int
	Agreed       int
	SizeOnly     int
	AnyDivergent bool
}

func (s *Server) gossip(w http.ResponseWriter, r *http.Request) {
	v, err := s.buildStatus()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = gossipTmpl.Execute(w, g)
}

var gossipTmpl = template.Must(template.New("gossip").Parse(gossipPageHTML))
