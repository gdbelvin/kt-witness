package server

import (
	"strings"
	"testing"
	"time"
)

// TestPeerLayerCountsWhatIsNotWatched.
//
// The map's job here is not to show that peers exist — it is to show how few
// logs any second party is checking. A witness's own signature over a
// checkpoint it fetched itself agrees with itself by construction, so a log
// with no second observer has attestations that nothing in the world could
// contradict.
func TestPeerLayerCountsWhatIsNotWatched(t *testing.T) {
	g := &graphView{
		Nodes: []graphNode{
			{Origin: "a/kt"}, {Origin: "b/kt"}, {Origin: "c/kt"},
		},
		CX: graphCX, CY: graphCY,
	}
	gs := &gossipView{Peers: []gossipPeer{
		{Witness: "witness.example.org", Comparable: 2, Agreed: 2, Origins: 2},
	}}
	attachPeers(g, gs, map[string][]string{
		"a/kt": {"witness.example.org"},
		"b/kt": {"witness.example.org"},
	})

	if g.Corroborated != 2 || g.Unobserved != 1 {
		t.Fatalf("corroborated=%d unobserved=%d, want 2 and 1", g.Corroborated, g.Unobserved)
	}
	if !g.Nodes[0].Corroborated || g.Nodes[2].Corroborated {
		t.Error("the halo was attached to the wrong logs")
	}
	if len(g.Peers) != 1 || g.Peers[0].Comparable != 2 {
		t.Fatalf("peer layer: %+v", g.Peers)
	}
	// The edge is placed, and its weight follows comparability rather than
	// being decorative.
	if g.Peers[0].X <= 0 || g.Peers[0].Width <= 1 {
		t.Errorf("peer edge not laid out: %+v", g.Peers[0])
	}
}

// A peer that disagrees must be visually distinct from one that agrees. This is
// the only case on the whole map that would mean an operator has been caught.
func TestDivergentPeerIsMarked(t *testing.T) {
	g := &graphView{Nodes: []graphNode{{Origin: "a/kt"}}, CX: graphCX, CY: graphCY}
	attachPeers(g, &gossipView{Peers: []gossipPeer{
		{Witness: "w.example", Comparable: 5, Agreed: 4, Origins: 5},
	}}, map[string][]string{"a/kt": {"w.example"}})

	if !g.Peers[0].Divergent {
		t.Fatal("a peer agreeing on 4 of 5 comparable logs was not marked divergent")
	}
	if !strings.Contains(g.Peers[0].Title, "DISAGREEMENT") {
		t.Errorf("title does not say what happened: %q", g.Peers[0].Title)
	}
}

func TestGraphRendersWithNoPeersAtAll(t *testing.T) {
	// A witness with no peers configured must still render, and must still say
	// that nothing is checking it — that is the honest reading, not an empty
	// section.
	g := &graphView{Nodes: []graphNode{{Origin: "a/kt"}}, CX: graphCX, CY: graphCY,
		TotalLogs: 1, Generated: time.Now().Format(time.RFC3339)}
	attachPeers(g, &gossipView{}, nil)
	if g.Unobserved != 1 || g.PeerCount != 0 {
		t.Fatalf("unobserved=%d peers=%d, want 1 and 0", g.Unobserved, g.PeerCount)
	}
	var sb strings.Builder
	if err := graphTmpl.Execute(&sb, g); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "no second observer") {
		t.Error("a witness nobody is checking did not say so")
	}
}
