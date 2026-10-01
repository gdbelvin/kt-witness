package server

import (
	"fmt"
	"math"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	testList10   = "staging/log-list-10qps-4klogs.1"
	testList100  = "staging/log-list-100qps-40klogs.1"
	testListTest = "testing/log-list.1"
	stagemoleKey = "witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv"
)

// networkFixture is a realistically shaped witness in the network: a handful
// of polled logs (one of them also on a list), twelve listed logs of which
// three have pushed, the network's eight witnesses, and two peers — one of
// which (stagemole) is also in the network table and is the only network
// witness whose key we hold.
func networkFixture(t *testing.T) *Server {
	t.Helper()
	db, err := store.Open(t.TempDir() + "/n.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	now := time.Now().UTC()
	put := func(origin string, size int64, age time.Duration) *store.Record {
		var h tlog.Hash
		copy(h[:], origin)
		h[31] = byte(size)
		rec := &store.Record{
			Origin: origin, Size: size, Hash: h,
			Cosigned: []byte(origin + "\n"), WitnessedAt: now.Add(-age),
		}
		if err := db.CompareAndSet(nil, rec); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	peer := func(rec *store.Record, witness string, agree bool) {
		root := rootBase64(rec)
		if !agree {
			root = "AAAA" + root[4:]
		}
		if _, err := db.RecordPeer(&store.PeerAttestation{
			Origin: rec.Origin, Witness: witness, Size: rec.Size, Root: root,
		}); err != nil {
			t.Fatal(err)
		}
	}

	tiers := map[string]string{}
	kinds := map[string]string{}
	polled := func(origin, kind, tier string, size int64, age time.Duration) *store.Record {
		tiers[origin], kinds[origin] = tier, kind
		return put(origin, size, age)
	}
	ct1 := polled("ct1.example.com/2026h1", "ct", "A (checkpoint witness)", 800_000_000, 12*time.Minute)
	ct2 := polled("ct2.example.com/2026h1", "ct", "A (checkpoint witness)", 300_000_000, 31*time.Minute)
	polled("ct3.example.com/2026h2", "ct", "A (checkpoint witness)", 90_000_000, 44*time.Minute)
	coach := polled("coachandhorses2026h1.staging.ct.example", "ct", "A (checkpoint witness)", 40_000_000, 20*time.Minute)
	kt := polled("kt.example.com/directory", "kt", "B+ (construction audit across published history)", 250_000, 8*time.Minute)
	polled("rekor.staging.example/tree", "software", "A+ (root-chain continuity)", 5_000_000, 17*time.Minute)

	// Three listed logs have pushed and so have records; nine have not.
	var logs []NetworkLog
	for i := 0; i < 12; i++ {
		origin := fmt.Sprintf("listed%02d.example.net/log", i)
		list := testList10
		if i%3 == 0 {
			list = testListTest
		}
		if i < 3 {
			rec := put(origin, int64(1000+i*500), time.Duration(5+i*9)*time.Minute)
			if i == 0 {
				peer(rec, "witness.stagemole.eu", true)
			}
		}
		logs = append(logs, NetworkLog{Origin: origin, List: list, Lists: []string{list}, QPD: 24})
	}
	logs = append(logs, NetworkLog{Origin: coach.Origin, List: testList10,
		Lists: []string{testList10, testList100}, Static: true})

	// stagemole: a polled peer AND in the network table, agreeing on three.
	peer(ct1, "witness.stagemole.eu", true)
	peer(ct2, "witness.stagemole.eu", true)
	// navigli: a polled peer that is not in the table; stays on the left.
	peer(kt, "navigli.sunlight.geomys.org", true)

	all := []string{testListTest, testList10, testList100}
	ws := []NetworkWitness{
		{Operator: "Elias Rudberg", Env: "testing", Lists: []string{testListTest}, About: "https://witness1.smartit.nu/witness1/about.txt"},
		{Operator: "Geomys", Env: "staging", Lists: all, About: "https://geomys.org/witness/navigli"},
		{Operator: "Mullvad VPN AB", Env: "staging", Lists: all, About: "https://witness.stagemole.eu/about", VKey: stagemoleKey},
		{Operator: "TrustFabric", Env: "staging", Lists: all, About: "https://transparency.dev/witnesses"},
		{Operator: "Florian Larysch", Env: "testing", Lists: []string{testListTest}, About: "https://remora.n621.de"},
		{Operator: "Markovian Protocol", Env: "testing", Lists: []string{testListTest}, About: "https://witness.markovianprotocol.com/about"},
		{Operator: "rgdd", Env: "testing", Lists: []string{testListTest}, About: "https://www.rgdd.se/poc-witness/about",
			// A key we hold but no comparable root yet: still only declared.
			VKey: "poc-witness.rgdd.se+00000000+BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Operator: "TrustFabric", Env: "testing", Lists: []string{testListTest}, About: "https://transparency.dev/witnesses/"},
	}
	return &Server{
		Store: db, VKey: "witness.example.com+deadbeef+AAAA", Version: "test",
		Tiers: tiers, Kinds: kinds,
		Network: func() NetworkView {
			return NetworkView{Lists: all, Logs: logs, Witnesses: ws}
		},
	}
}

func render(t *testing.T, s *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.graphPage(rec, httptest.NewRequest("GET", "/graph", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

// squash collapses runs of whitespace so prose split across template lines can
// be matched as a sentence.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// A listed log that has never pushed is not a witnessed log. It is drawn —
// hollow, past the outer ring — so the gap is visible, but it must not count
// toward anything this witness claims to cover, and it must not collide with
// anything either.
func TestListedLogsAreHollowAndUncounted(t *testing.T) {
	s := networkFixture(t)
	g, err := s.buildGraph()
	if err != nil {
		t.Fatal(err)
	}

	var hollow, drawn int
	var entries int64
	for _, nd := range g.Nodes {
		if !nd.Awaiting {
			drawn++
			entries += nd.Size
			continue
		}
		hollow++
		if nd.Stale || nd.Forked || nd.Corroborated || nd.Labelled {
			t.Errorf("%s: awaiting log marked stale=%v forked=%v corroborated=%v labelled=%v",
				nd.Origin, nd.Stale, nd.Forked, nd.Corroborated, nd.Labelled)
		}
		if nd.Kind != networkKind || g.Sectors[nd.sector].Kind != networkKind {
			t.Errorf("%s: awaiting log drawn outside the network wedge", nd.Origin)
		}
		if r := math.Hypot(nd.X-graphCX, nd.Y-graphCY); r <= ageRadius(graphAgeClamp) {
			t.Errorf("%s: hollow node at r=%.1f, inside the outermost age ring", nd.Origin, r)
		}
		if !strings.Contains(nd.Title, "awaiting first push") {
			t.Errorf("%s: tooltip %q does not say it is awaiting a push", nd.Origin, nd.Title)
		}
	}
	if hollow != 9 || g.AwaitingCount != 9 {
		t.Fatalf("hollow=%d AwaitingCount=%d, want 9", hollow, g.AwaitingCount)
	}
	// 6 polled + 3 pushed.
	if g.TotalLogs != 9 || drawn != 9 || g.TotalEntries != entries {
		t.Errorf("TotalLogs=%d drawn=%d TotalEntries=%d (want 9, 9, %d)", g.TotalLogs, drawn, g.TotalEntries, entries)
	}
	if g.StaleCount != 0 || len(g.Flagged) != 0 {
		t.Errorf("stale=%d flagged=%d; nothing is stale", g.StaleCount, len(g.Flagged))
	}
	if g.Unobserved != g.TotalLogs-g.Corroborated {
		t.Errorf("unobserved %d counts hollow nodes", g.Unobserved)
	}
	// The three pushed logs are ordinary nodes in the network wedge, tier A.
	pushed := 0
	for _, nd := range g.Nodes {
		if nd.Kind == networkKind && !nd.Awaiting {
			pushed++
			if nd.Code != "A" {
				t.Errorf("%s: pushed log drawn at tier %q", nd.Origin, nd.Code)
			}
		}
	}
	if pushed != 3 {
		t.Errorf("%d pushed nodes in the network wedge, want 3", pushed)
	}
	assertNoOverlap(t, g.Nodes)

	body := render(t, s)
	if !strings.Contains(body, `class="node listed"`) || !strings.Contains(body, "9 awaiting push") {
		t.Error("hollow nodes, or the wedge's awaiting count, are not rendered")
	}
}

func assertNoOverlap(t *testing.T, nodes []graphNode) {
	t.Helper()
	for i := range nodes {
		a := nodes[i]
		if a.X-a.R < 0 || a.X+a.R > graphW || a.Y-a.R < 0 || a.Y+a.R > graphH {
			t.Errorf("%s drawn outside the viewBox", a.Origin)
		}
		for j := i + 1; j < len(nodes); j++ {
			b := nodes[j]
			if gap := math.Hypot(b.X-a.X, b.Y-a.Y) - (a.R + b.R); gap < 0 {
				t.Errorf("%s and %s overlap by %.2fpx", a.Origin, b.Origin, -gap)
			}
		}
	}
}

// The layout guarantee holds at the real network's scale too: eighty polled
// logs plus every log on all three lists hollow in one wedge.
func TestNetworkLayoutDoesNotOverlapAtScale(t *testing.T) {
	now := time.Now().UTC()
	var awaiting []NetworkLog
	for i := 0; i < 33; i++ {
		awaiting = append(awaiting, NetworkLog{Origin: fmt.Sprintf("n%02d.example.net/log", i), List: testList10})
	}
	g := layoutGraphNet(synthGroups(now, 80), awaiting, now)
	if g.TotalLogs != 80 || g.AwaitingCount != 33 {
		t.Fatalf("TotalLogs=%d AwaitingCount=%d", g.TotalLogs, g.AwaitingCount)
	}
	assertNoOverlap(t, g.Nodes)
	for _, nd := range g.Nodes {
		s := g.Sectors[nd.sector]
		if nd.angle < s.Start-0.001 || nd.angle > s.End+0.001 {
			t.Errorf("%s left its wedge", nd.Origin)
		}
	}
	// And the network wedge sits second, in the upper right, near the column.
	if len(g.Sectors) < 2 || g.Sectors[1].Kind != networkKind {
		t.Errorf("network wedge not placed second: %+v", g.Sectors)
	}

	// The age rings are labelled straight up from the hub, and the network
	// wedge spans twelve o'clock — so a hollow node must not sit on a label.
	if s := g.Sectors[1]; !(s.Start < 0 && s.End > 0) {
		t.Fatalf("fixture no longer puts the network wedge across twelve o'clock: [%.1f, %.1f]", s.Start, s.End)
	}
	for _, ring := range g.Rings {
		// A ~110x12 box above each ring, where its label is drawn.
		bx0, bx1 := graphCX-55, graphCX+55
		by1 := graphCY - ring.R - 2
		by0 := by1 - 12
		for _, nd := range g.Nodes {
			if !nd.Awaiting {
				continue // pre-existing: polled nodes are not kept off the labels
			}
			cx := math.Max(bx0, math.Min(nd.X, bx1))
			cy := math.Max(by0, math.Min(nd.Y, by1))
			if math.Hypot(nd.X-cx, nd.Y-cy) < nd.R {
				t.Errorf("hollow %s at (%.1f, %.1f) sits on the %s ring label", nd.Origin, nd.X, nd.Y, ring.Label)
			}
		}
	}
}

// Solid means verified, dashed means declared, and nothing in between.
// Drawn labels never overprint each other, except where both belong to logs a
// reader must not miss — and those are never the ones hidden.
func TestDrawnLabelsDoNotClash(t *testing.T) {
	now := time.Now().UTC()
	for _, n := range []int{6, 20, 80} {
		var listed []NetworkLog
		for i := 0; i < 12; i++ {
			listed = append(listed, NetworkLog{Origin: fmt.Sprintf("listed%02d.example.net", i), List: testList10})
		}
		g := layoutGraphNet(synthGroups(now, n), listed, now)
		var drawn []*graphNode
		for i := range g.Nodes {
			nd := &g.Nodes[i]
			if (nd.Stale || nd.Forked) && !nd.Labelled {
				t.Errorf("n=%d: flagged %s lost its label", n, nd.Origin)
			}
			if nd.Labelled {
				drawn = append(drawn, nd)
			}
		}
		for i := range drawn {
			for j := i + 1; j < len(drawn); j++ {
				a, b := drawn[i], drawn[j]
				if (a.Stale || a.Forked) && (b.Stale || b.Forked) {
					continue
				}
				ax0, ay0, ax1, ay1 := labelBox(a)
				bx0, by0, bx1, by1 := labelBox(b)
				if ax0 < bx1 && bx0 < ax1 && ay0 < by1 && by0 < ay1 {
					t.Errorf("n=%d: labels %q and %q overlap", n, a.Label, b.Label)
				}
			}
		}
	}
}

func TestNetworkWitnessEdges(t *testing.T) {
	g, err := networkFixture(t).buildGraph()
	if err != nil {
		t.Fatal(err)
	}
	if len(g.NetWitnesses) != 8 {
		t.Fatalf("%d network witnesses drawn, want 8", len(g.NetWitnesses))
	}
	by := map[string]graphNetWitness{}
	for _, w := range g.NetWitnesses {
		by[w.Operator+"/"+w.Env] = w
	}

	mv := by["Mullvad VPN AB/staging"]
	if !mv.Verified || mv.Dashed || mv.Comparable != 3 || mv.Width <= 1 || mv.Divergent {
		t.Errorf("Mullvad should have a solid evidence edge on 3 logs: %+v", mv)
	}
	geo := by["Geomys/staging"]
	if geo.Verified || !geo.Dashed {
		t.Errorf("Geomys has no key configured and must be declared only: %+v", geo)
	}
	for _, want := range []string{"declares it follows", "no cosignature of theirs verified here yet", "key not configured"} {
		if !strings.Contains(geo.Title, want) {
			t.Errorf("Geomys tooltip %q lacks %q", geo.Title, want)
		}
	}
	// A key we hold is not evidence until a root is comparable.
	rg := by["rgdd/testing"]
	if rg.Verified || !rg.Dashed || strings.Contains(rg.Title, "key not configured") {
		t.Errorf("rgdd (key held, nothing comparable) should be declared: %+v", rg)
	}
	// Staging first, and every witness on the canvas.
	if g.NetWitnesses[0].Env != "staging" || g.NetWitnesses[3].Env != "testing" {
		t.Errorf("column not grouped staging-first: %v, %v", g.NetWitnesses[0].Env, g.NetWitnesses[3].Env)
	}
	for _, w := range g.NetWitnesses {
		if w.Y-w.R < 0 || w.LabelY+14 > graphH || w.X+60 > graphW {
			t.Errorf("%s drawn off the canvas at (%.1f, %.1f)", w.Operator, w.X, w.Y)
		}
		// The dashed edge ends on the network wedge's outer edge.
		if w.Dashed {
			if r := math.Hypot(w.EdgeX-graphCX, w.EdgeY-graphCY); math.Abs(r-(graphRMax+16)) > 0.5 {
				t.Errorf("%s: declared edge ends at r=%.1f, not on the network wedge", w.Operator, r)
			}
		}
	}

	// A divergent network witness is marked the same way a divergent peer is.
	g2 := &graphView{Peers: nil}
	attachNetwork(g2, &NetworkView{Witnesses: []NetworkWitness{{Operator: "x", Env: "staging", VKey: stagemoleKey}}},
		&gossipView{Peers: []gossipPeer{{Witness: "witness.stagemole.eu", Comparable: 4, Agreed: 3}}})
	if w := g2.NetWitnesses[0]; !w.Divergent || !strings.Contains(w.Title, "DISAGREEMENT") {
		t.Errorf("divergent network witness not marked: %+v", w)
	}

	body := render(t, networkFixture(t))
	if !strings.Contains(body, `class="netedge"`) || !strings.Contains(body, "dashed</b> declared") ||
		!strings.Contains(body, "solid</b> verified") {
		t.Error("the declared edges, or the legend explaining them, are not rendered")
	}
}

// A witness that is both a polled peer and in the network table is drawn once,
// on the right, and stays in the peer table.
func TestPeerInNetworkIsDrawnOnce(t *testing.T) {
	s := networkFixture(t)
	g, err := s.buildGraph()
	if err != nil {
		t.Fatal(err)
	}
	var moved, stayed bool
	for _, p := range g.Peers {
		switch p.Name {
		case "witness.stagemole.eu":
			moved = p.OnRight
		case "navigli.sunlight.geomys.org":
			stayed = !p.OnRight
		}
	}
	if !moved || !stayed || g.PeerCount != 2 {
		t.Fatalf("moved=%v stayed=%v peers=%d; %+v", moved, stayed, g.PeerCount, g.Peers)
	}
	if len(g.NetMoved) != 1 || g.NetMoved[0] != "witness.stagemole.eu" {
		t.Errorf("NetMoved = %v", g.NetMoved)
	}

	body := render(t, s)
	// The left column's labels sit at x=96 and the right column's at
	// graphNetColX; stagemole's name may appear in the right one only.
	left := fmt.Sprintf(`x="%.1f"`, 96.0)
	right := fmt.Sprintf(`x="%.1f"`, graphNetColX)
	if n := strings.Count(body, left+` y="`); n == 0 {
		t.Fatal("no left-column labels found; the test's anchor is stale")
	}
	var inLeft, inRight int
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, ">witness.stagemole.eu</text>") {
			continue
		}
		switch {
		case strings.Contains(line, left):
			inLeft++
		case strings.Contains(line, right):
			inRight++
		}
	}
	if inLeft != 0 || inRight != 1 {
		t.Errorf("stagemole labelled %d times on the left and %d on the right, want 0 and 1", inLeft, inRight)
	}
	if !strings.Contains(body, left+` y="`) || !strings.Contains(body, ">navigli.sunlight.geomys.org</text>") {
		t.Error("the peer not in the network left the left column")
	}
	// Still in the peer table.
	if !strings.Contains(body, `<td class="origin">witness.stagemole.eu</td>`) {
		t.Error("the moved peer dropped out of the peer table")
	}
}

// The prose under the map states the network's shape in numbers.
func TestNetworkProseCounts(t *testing.T) {
	body := squash(render(t, networkFixture(t)))
	for _, want := range []string{
		"witness-network: 8 witnesses (3 staging, 5 testing); we verify cosignatures from 2 of them (1 with roots comparable to ours so far); " +
			"13 logs listed across 3 lists, of which 3 have pushed to us.",
		"9 listed logs have not pushed yet",
		"<code>witness.stagemole.eu</code> is both a peer",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("prose lacks %q", want)
		}
	}
}

// A polled log that a list also names carries a notch and says so.
func TestPolledLogAlsoListedIsMarked(t *testing.T) {
	g, err := networkFixture(t).buildGraph()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, nd := range g.Nodes {
		if nd.Origin != "coachandhorses2026h1.staging.ct.example" {
			if nd.AlsoListed != "" {
				t.Errorf("%s marked as listed", nd.Origin)
			}
			continue
		}
		found = true
		if nd.Kind != "ct" || nd.Awaiting {
			t.Errorf("a polled log on a list must stay in its own wedge: %+v", nd)
		}
		want := "also on witness-network list " + testList10 + ", " + testList100
		if !strings.Contains(nd.Title, want) || nd.TickX1 == 0 {
			t.Errorf("marker missing: title %q", nd.Title)
		}
	}
	if !found {
		t.Fatal("the polled, listed log was not drawn")
	}
}

// With no network configured, nothing network-related is drawn or said, and a
// pushed log's record is not invented into a wedge.
func TestGraphWithoutNetworkIsUnchanged(t *testing.T) {
	s := networkFixture(t)
	s.Network = nil
	g, err := s.buildGraph()
	if err != nil {
		t.Fatal(err)
	}
	if g.Network || len(g.NetWitnesses) != 0 || g.AwaitingCount != 0 {
		t.Fatalf("network drawn with Network nil: %+v", g.NetWitnesses)
	}
	for _, sec := range g.Sectors {
		if sec.Kind == networkKind {
			t.Error("a network wedge appeared with no network configured")
		}
	}
	for _, p := range g.Peers {
		if p.OnRight {
			t.Errorf("%s moved to a column that does not exist", p.Name)
		}
	}
	body := render(t, s)
	for _, absent := range []string{"witness-network:", `class="network"`, `class="netwit"`, `class="node listed"`, `class="nettick"`, "Witness network"} {
		if strings.Contains(body, absent) {
			t.Errorf("page with no network contains %q", absent)
		}
	}
	// Without a network, a record the config does not name is retired — the
	// behaviour before any of this existed.
	if g.RetiredCount != 3 {
		t.Errorf("RetiredCount = %d, want the 3 pushed records", g.RetiredCount)
	}
}

// Writes the fixture's page to $GRAPH_NETWORK_OUT, for a human to look at.
func TestRenderNetworkFixture(t *testing.T) {
	out := os.Getenv("GRAPH_NETWORK_OUT")
	if out == "" {
		t.Skip("set GRAPH_NETWORK_OUT to write the rendered page")
	}
	if err := os.WriteFile(out, []byte(render(t, networkFixture(t))), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestShortListName(t *testing.T) {
	for in, want := range map[string]string{
		"https://raw.githubusercontent.com/transparency-dev/witness-network/main/lists/staging/log-list-10qps-4klogs.1": testList10,
		"https://staging.witness-network.org/log-list-100qps-40klogs.1":                                                 testList100,
		"https://testing.witness-network.org/log-list.1":                                                                testListTest,
		"https://example.com/some/list.txt":                                                                             "list.txt",
	} {
		if got := ShortListName(in); got != want {
			t.Errorf("ShortListName(%q) = %q, want %q", in, got, want)
		}
	}
}
