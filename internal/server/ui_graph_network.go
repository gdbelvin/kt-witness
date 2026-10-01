package server

// The witness-network layer of the ecosystem map.
//
// The rule is the one the peer layer follows, and it matters more here because
// the network publishes a table that makes claiming more very easy: EDGES MEAN
// EVIDENCE. A witness in the network's table has written down that it follows
// some lists. That is a declaration, and it is drawn as one — a thin dashed
// line to the network's wedge as a whole, never to an individual log, because
// we have no idea which of those logs it actually watches. Only when we hold
// its key and it has published a root at the same size as ours on some log
// does it get the solid edge a peer gets, since only then could it contradict
// us.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// graphNetColX is the x of the witness-network column: a little further in
// than the peer column on the left, because its labels are wider (a key name
// sits under each operator).
const graphNetColX = graphW - 110

// attachNetwork adds the witness network to an already laid-out map: markers on
// polled logs a list also names, the column of network witnesses on the right,
// and the counts for the prose under the map. A nil view leaves g untouched, so
// a witness outside the network renders exactly as it did before.
//
// It must run after attachPeers, because a peer that is also in the network
// table is moved from the left column to this one rather than drawn twice.
func attachNetwork(g *graphView, nv *NetworkView, gs *gossipView) {
	if nv == nil {
		return
	}
	g.Network = true
	g.NetLogs = len(nv.Logs)
	g.NetLists = len(nv.Lists)

	drawn := map[string]bool{}
	for _, nd := range g.Nodes {
		if !nd.Awaiting {
			drawn[nd.Origin] = true
		}
	}
	also := map[string]string{}
	for _, nl := range nv.Logs {
		if nl.Static {
			lists := nl.List
			if len(nl.Lists) > 0 {
				lists = strings.Join(nl.Lists, ", ")
			}
			if lists != "" {
				also[nl.Origin] = lists
			}
			continue
		}
		if drawn[nl.Origin] {
			g.NetPushed++
		}
	}

	// A polled log that a list also names gets a short notch on its spoke,
	// just inside the node. A notch rather than a colour or a halo: colour is
	// tier's and the halo is corroboration's, and being on a list is neither —
	// it is a fact about who else may be asked to watch the log, not about how
	// well we do.
	for i := range g.Nodes {
		nd := &g.Nodes[i]
		lists, ok := also[nd.Origin]
		if !ok || nd.Awaiting {
			continue
		}
		nd.AlsoListed = lists
		nd.TickX1, nd.TickY1 = polar(nd.angle, nd.orbit-nd.R-1.5)
		nd.TickX2, nd.TickY2 = polar(nd.angle, nd.orbit-nd.R-8)
		nd.Title += " · also on witness-network list " + lists
	}

	// The column, staging first: those are the witnesses the network asks log
	// operators to rely on, and testing ones "come and go".
	ws := append([]NetworkWitness(nil), nv.Witnesses...)
	envRank := func(e string) int {
		switch e {
		case "staging":
			return 0
		case "testing":
			return 1
		}
		return 2
	}
	sort.SliceStable(ws, func(i, j int) bool { return envRank(ws[i].Env) < envRank(ws[j].Env) })

	peerIdx := map[string]int{}
	for i, p := range g.Peers {
		peerIdx[p.Name] = i
	}
	byName := map[string]gossipPeer{}
	if gs != nil {
		for _, p := range gs.Peers {
			byName[p.Witness] = p
		}
	}

	// The network wedge, if one is drawn: declared edges end on its outer
	// edge. Without one — no list names anything yet — a declared witness is
	// drawn with no edge at all rather than one to the hub, which would claim
	// a relationship with this witness that nobody has declared.
	var netSector *graphSector
	for i := range g.Sectors {
		if g.Sectors[i].Kind == networkKind {
			netSector = &g.Sectors[i]
		}
	}

	// Vertical rhythm: a heading per environment, then one row per witness,
	// centred on the hub and compressed only if the table ever outgrows the
	// canvas.
	envs := 0
	for i := range ws {
		if i == 0 || ws[i].Env != ws[i-1].Env {
			envs++
		}
	}
	const head, gap = 24.0, 12.0
	row := 66.0
	if n := float64(len(ws)); n > 0 {
		if fit := (graphH - 60 - float64(envs)*(head+gap)) / n; fit < row {
			row = fit
		}
	}
	height := float64(len(ws))*row + float64(envs)*(head+gap) - gap
	y := graphCY - height/2

	for i, w := range ws {
		switch w.Env {
		case "staging":
			g.NetStaging++
		case "testing":
			g.NetTesting++
		}
		if i == 0 || w.Env != ws[i-1].Env {
			if i > 0 {
				y += gap
			}
			label := strings.ToUpper(w.Env)
			if label == "" {
				label = "OTHER"
			}
			g.NetEnvs = append(g.NetEnvs, graphNetEnv{Label: label + " WITNESSES", X: graphNetColX, Y: y + 10})
			y += head
		}
		nodeY := y + 11
		y += row

		name := w.Name()
		gw := graphNetWitness{
			Operator: w.Operator, Env: w.Env, Name: name, Lists: w.Lists,
			X: graphNetColX, Y: nodeY, R: 10,
			LabelX: graphNetColX, LabelY: nodeY + 24,
			Sub: name,
		}
		if strings.HasPrefix(w.About, "https://") {
			gw.About = w.About
		}
		if name == "" {
			gw.Sub = "key not configured"
		} else {
			g.NetVerified++
		}
		if pi, ok := peerIdx[name]; ok && name != "" {
			// Already a peer: drawn here, once, and not on the left.
			g.Peers[pi].OnRight = true
			g.NetMoved = append(g.NetMoved, name)
		}
		lists := strings.Join(w.Lists, ", ")
		if lists == "" {
			lists = "no lists"
		}
		p, known := byName[name]
		if name != "" && known && p.Comparable > 0 {
			gw.Verified = true
			g.NetComparable++
			gw.Comparable = p.Comparable
			gw.Divergent = p.Comparable > p.Agreed
			gw.Width = 1.0 + math.Min(6.0, float64(p.Comparable)/2.0)
			gw.Title = fmt.Sprintf("%s (%s) — declares it follows %s; %d logs comparable, %d agreed",
				w.Operator, name, lists, p.Comparable, p.Agreed)
			if gw.Divergent {
				gw.Title += " — DISAGREEMENT"
			}
		} else {
			gw.Title = fmt.Sprintf("%s — declares it follows %s; no cosignature of theirs verified here yet",
				w.Operator, lists)
			if name == "" {
				gw.Title += " · key not configured"
			} else {
				gw.Title += " · key configured as " + name
			}
			if netSector != nil {
				gw.Dashed = true
				gw.EdgeX, gw.EdgeY = declaredEnd(*netSector, gw.X, gw.Y)
			}
		}
		g.NetWitnesses = append(g.NetWitnesses, gw)
	}
}

// declaredEnd is where a declared edge from (x, y) meets the network wedge: on
// its outer edge, at the witness's own bearing from the hub where the wedge
// spans it, else at the nearer end of the wedge. Each edge therefore runs the
// shortest way in and the fan of them never crosses the column's labels.
func declaredEnd(s graphSector, x, y float64) (float64, float64) {
	bearing := math.Atan2(y-graphCY, x-graphCX)*180/math.Pi + 90
	lo, hi := s.Start+1.5, s.End-1.5
	if lo > hi {
		lo, hi = (s.Start+s.End)/2, (s.Start+s.End)/2
	}
	return polar(clampAngle(bearing, lo, hi), graphRMax+16)
}
