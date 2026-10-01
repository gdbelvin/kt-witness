package server

// The ecosystem map.
//
// The index answers "is anything wrong" and the per-log page answers "what do
// we know about this one log". Neither answers the question a reader actually
// arrives with, which is "what does this witness *cover*, and is any of it
// rotting". Eighty rows in four tables cannot answer that: the shape of the
// coverage — nearly all CT by row count, nearly all the entries in a handful of
// giant logs, all of the construction auditing in the KT rows — is a property
// of the whole set, and a table only ever shows one row at a time.
//
// So this page is a picture of the set. The choices in it are deliberate, and
// two of them matter more than the rest:
//
//  1. RADIUS IS AGE, NOT DECORATION. A node's distance from the witness at the
//     centre is how long it has been since we last refreshed our cosignature of
//     it, on a log scale. Everything healthy sits in a tight band; a log the
//     witness has failed to refresh drifts outward and cannot be missed. This
//     is the one fact the existing pages hide: `tuscolo2026h1.sunlight.geomys.org`
//     has been stale for three days and it shows up today as a small STALE pill
//     in row sixty of a table nobody scrolls to. WitnessedAt is a fair axis to
//     spend the strongest visual channel on, because the witness re-cosigns on
//     a timer even when the tree has not moved (witness.go's `refresh` path) —
//     so an old timestamp genuinely means "we have not been able to look",
//     never merely "this log is quiet".
//
//  2. ANGLE CARRIES NO MEANING, SO IT IS SPENT ON LEGIBILITY. Each ecosystem
//     owns an angular sector, and within a sector a node's angle is chosen only
//     to keep it from colliding with its neighbours. That is the honest way to
//     draw eighty nodes: a force-directed layout would move nodes for reasons
//     the reader cannot decode, and would place a node differently on every
//     render, so a reader could not learn the picture. Here the picture is
//     stable — only a node's *radius* changes between renders, and when it does
//     it means something.
//
// Everything is computed here, in Go, and emitted as static SVG. No script, no
// CDN, no font fetch — the same rule the rest of the UI follows, for the same
// reason: a witness that has to load code from a third party to render itself
// has an extra thing to trust.

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Canvas geometry. The viewBox is wider than it is tall because the sector
// labels sit outside the outermost ring at the left and right extremes, which
// is where the horizontal headroom goes.
//
// It was widened from 1300 when the witness-network column arrived on the
// right. The ring sits in the middle of the wider canvas, the peer column stays
// pinned to the left edge, and the witness-network column is pinned to the
// right edge, so each margin column has clear air between it and the sector
// labels beside it.
const (
	graphW  = 1480.0
	graphH  = 940.0
	graphCX = 740.0
	graphCY = 476.0

	// The band radii between which every node lives. r0 is far enough out that
	// the fresh majority is not crushed against the centre node.
	graphR0   = 200.0
	graphRMax = 368.0

	// Node radii, from the sqrt of the log's size. Clamped hard at both ends:
	// CT logs run to 10^9 entries and KT logs to 10^6, so an unclamped sqrt
	// scale still gives a 30x radius ratio and the small nodes vanish. The
	// upper clamp is what keeps eighty nodes fitting on one ring at all: it was
	// chosen by drawing the real fleet's shape and taking the largest value at
	// which fitNodes does not have to shrink anything, so the shrink note under
	// the legend stays an exception rather than becoming boilerplate nobody
	// reads.
	graphNodeMin = 4.0
	graphNodeMax = 8.0

	// Angular gutter between sectors, in degrees. Wide enough to read as a
	// break in the ring rather than as a coincidence of spacing.
	graphGutter = 7.0

	// Ages, in minutes, at which a guide ring is drawn. graphAgeClamp is also
	// where the radial scale saturates: a log stale for thirty days must not be
	// allowed to fly off the canvas and take the scale with it, so everything
	// past two days sits on the outermost ring and is labelled with its real
	// age instead.
	graphAgeClamp = 48 * 60.0
)

// graphNode is one witnessed log as drawn.
//
// Coordinates are carried as float64 and formatted at render time rather than
// preformatted into strings, so the layout is testable as arithmetic — the
// overlap test in ui_graph_test.go reads these fields directly.
type graphNode struct {
	Origin string
	Label  string // shortened for drawing; the full origin is in the tooltip
	Kind   string
	Group  string // the ecosystem's full label, for the prose beneath the map
	Tier   string
	Code   string // A / A+ / B / B+ / ? — the tier reduced to its rank
	Rank   int
	Size   int64
	Age    string
	Href   string
	Title  string

	X, Y, R float64
	// Precomputed square geometry for the construction-audited tiers, and the
	// radius of the inner ring that marks a "+" tier. Worked out here rather
	// than with arithmetic in the template, because arithmetic in a template is
	// where SVG bugs go to hide.
	SX, SY, SD float64
	InnerR     float64
	// Square for the construction-audited tiers (B, B+), circle for the
	// append-only ones (A, A+); an inner ring marks the "+" of each pair. Tier
	// is therefore readable without colour, which matters both for the ~8% of
	// men with a colour vision deficiency and for anyone printing this.
	Square bool
	Ring   bool

	Stale  bool
	Forked bool

	// Corroborated: at least one peer witness has published a root for this
	// log, so a fork in it could actually be caught. Drawn as an outer halo,
	// because it is the difference between a log being watched and a log being
	// CHECKED — one witness's signature over a fetched checkpoint always agrees
	// with itself.
	Corroborated bool
	Peers        []string

	// Awaiting marks a log a witness-network list names that has never pushed
	// to us. It is drawn hollow, just past the outermost ring, and is not a
	// witnessed log in any sense: there is no measurement behind it, so it is
	// never stale, forked or corroborated, and it is left out of every count
	// of what this witness covers. It sits on the map only so the gap between
	// "listed" and "witnessed" is visible rather than merely stated.
	Awaiting bool

	// AlsoListed names the witness-network lists that also carry a log we
	// poll, drawn as a short notch on the node's spoke. Tick is its geometry.
	AlsoListed     string
	TickX1, TickY1 float64
	TickX2, TickY2 float64

	// Labelled nodes get their origin drawn beside them. Only a handful are:
	// eighty labels is not a map, it is a wall.
	Labelled             bool
	LabelX, LabelY       float64
	LabelAnchor          string
	FillOpacity          float64
	angle, orbit, lo, hi float64 // layout scratch: degrees, px, sector bounds
	sector               int
}

// graphPeer is another witness, placed outside the ring of logs.
//
// The edge drawn to it is not "these two witnesses talk to each other" — there
// is no evidence of that and this witness would not know. It is narrower and
// more useful: on N logs, both of us have published a root at the same size, so
// a disagreement between us would be detectable. That is the only relationship
// between witnesses that has teeth.
type graphPeer struct {
	Name       string
	Label      string
	X, Y, R    float64
	LabelX     float64
	LabelY     float64
	Comparable int
	Agreed     int
	Origins    int
	Divergent  bool
	Width      float64 // edge stroke width, by comparable logs
	Title      string
	// OnRight: this peer is also in the witness-network table, so it is drawn
	// once, in that column on the right, and not again on the left. It stays
	// in Peers so the peer table and count still include it.
	OnRight bool
}

// graphNetWitness is one entry of the witness-network table, drawn in the
// column on the right margin.
//
// The edge drawn to it is one of two very different things, and they are
// drawn differently so they cannot be confused. SOLID: we hold its key and on
// N logs we both published a root at the same size — the same evidence edge a
// peer on the left gets. DASHED, to the network wedge rather than to any log:
// it declares, in the network's table, that it follows these lists. That is
// somebody's statement of intent, and nothing this witness has checked.
type graphNetWitness struct {
	Operator string
	Env      string
	Name     string // key name; "" when no key is configured
	Lists    []string
	About    string // an https about page, used as the link; else ""

	X, Y, R        float64
	LabelX, LabelY float64
	Sub            string // second label line: key name, or "key not configured"

	Verified   bool // solid evidence edge
	Dashed     bool // declared edge drawn to the network wedge
	Divergent  bool
	Comparable int
	Width      float64
	EdgeX      float64 // end of the dashed declared edge, on the network wedge
	EdgeY      float64
	Title      string
}

// graphNetEnv is the heading over one environment's group in the column.
type graphNetEnv struct {
	Label string
	X, Y  float64
}

// graphSector is one ecosystem's wedge.
type graphSector struct {
	Kind    string
	Label   string
	Short   string
	Count   int
	Entries int64
	TopTier string
	Stale   int
	Forked  int
	// Awaiting counts listed logs drawn hollow in this wedge; only the
	// witness-network wedge has any. Not part of Count, which is logs
	// witnessed.
	Awaiting int

	Start, End  float64 // degrees, clockwise from twelve o'clock
	Wedge       string  // path data for the tinted background wedge
	Arc         string  // path data for the outer arc that names the group
	LabelX      float64
	LabelY      float64
	LabelAnchor string
}

// graphRing is one labelled guide circle: the age scale's tick marks.
type graphRing struct {
	R      float64
	Label  string
	LabelY float64
	Dashed bool // the two-hour ring, which is the threshold `Stale` uses
	Note   string
}

type graphView struct {
	WitnessName string
	Generated   string

	Sectors []graphSector
	Nodes   []graphNode
	Rings   []graphRing

	// Peers and the corroboration figures. Unobserved is the number this page
	// exists to make impossible to miss: logs this witness attests that no
	// other witness is publishing a root for, and which therefore no amount of
	// diligence here could catch a fork in.
	Peers        []graphPeer
	Corroborated int
	Unobserved   int
	PeerCount    int

	// The witness network, when this witness takes part in one. Network is
	// false, and everything else here zero, when it does not.
	Network       bool
	NetWitnesses  []graphNetWitness
	NetEnvs       []graphNetEnv
	NetStaging    int
	NetTesting    int
	NetVerified   int // network witnesses whose cosignature key we hold
	NetComparable int // of those, how many share a comparable root with us
	NetLogs       int // distinct logs named across the lists
	NetLists      int // lists this witness follows
	NetPushed     int // listed (not configured) logs that have pushed to us
	AwaitingCount int // listed logs that have not pushed yet
	NetMoved      []string

	// Flagged is the subset a reader must not have to hunt for in the picture:
	// anything stale or forked, listed in text with its real age.
	Flagged []graphNode

	TotalLogs    int
	TotalEntries int64
	StaleCount   int
	ForkedCount  int
	RetiredCount int
	Retired      []string

	// Scale is the factor the dot sizes were drawn at. It is 1 unless the fleet
	// was too dense for the canvas, in which case every dot shrank by the same
	// amount — see fitNodes — and the page says so rather than quietly
	// redefining what a dot's size means.
	Scale    float64
	ScalePct int

	CX, CY, W, H float64
	AriaLabel    string
}

// tierCode reduces a configured tier string ("A+ (root-chain continuity)") to
// the rank that is actually drawn. It goes through tierRank rather than doing
// its own prefix matching so that the ordering of tiers is defined in exactly
// one place: if a new tier is added to tierRank, this either handles it or
// visibly falls through to "?", which is the failure we want.
func tierCode(tier string) (string, int) {
	rank := tierRank(tier)
	switch rank {
	case 5:
		return "B+", rank
	case 4:
		return "B", rank
	case 3:
		return "A+", rank
	case 2:
		return "A", rank
	case 0:
		return "?", rank
	default:
		return "?", rank
	}
}

// tierFill is the intensity ladder the tiers are drawn with.
//
// Deliberately a single hue at four opacities rather than four colours. The
// obvious thing — green/amber/red across the tiers — would render tier A as a
// warning, and tier A is the honest ceiling for a certificate log: there is no
// mutable map to audit, so append-only IS the whole construction property. A
// page that draws two thirds of the ecosystem in warning amber for achieving
// everything it can achieve would be lying in exactly the direction this
// project spends the most effort not lying in. Intensity says "more was
// established" without saying "less is wrong".
func tierFill(rank int) float64 {
	switch rank {
	case 5: // B+
		return 1.0
	case 4: // B
		return 0.7
	case 3: // A+
		return 0.5
	case 2: // A
		return 0.3
	default:
		return 0.2
	}
}

// ageRadius maps age to distance from the centre, log-scaled.
//
// Log rather than linear because the interesting structure is at both ends at
// once: refreshes are hourly and staggered, so a healthy fleet is smeared over
// zero to sixty minutes and a linear scale would stack it all in the first
// centimetre, while a genuinely stuck log is days out and would compress
// everything else to nothing. The log scale gives the healthy spread about 40%
// of the band and still leaves the stale ones unmistakably outside it.
func ageRadius(minutes float64) float64 {
	if minutes < 0 {
		minutes = 0
	}
	if minutes > graphAgeClamp {
		minutes = graphAgeClamp
	}
	f := math.Log(1+minutes/5) / math.Log(1+graphAgeClamp/5)
	return graphR0 + (graphRMax-graphR0)*f
}

func polar(angleDeg, r float64) (float64, float64) {
	// -90 puts zero degrees at twelve o'clock and runs clockwise, which is how
	// a reader scans a dial.
	rad := (angleDeg - 90) * math.Pi / 180
	return graphCX + r*math.Cos(rad), graphCY + r*math.Sin(rad)
}

func arcPath(r, start, end float64) string {
	x0, y0 := polar(start, r)
	x1, y1 := polar(end, r)
	large := 0
	if end-start > 180 {
		large = 1
	}
	return fmt.Sprintf("M %.1f %.1f A %.1f %.1f 0 %d 1 %.1f %.1f", x0, y0, r, r, large, x1, y1)
}

func wedgePath(rInner, rOuter, start, end float64) string {
	x0, y0 := polar(start, rInner)
	x1, y1 := polar(start, rOuter)
	x2, y2 := polar(end, rOuter)
	x3, y3 := polar(end, rInner)
	large := 0
	if end-start > 180 {
		large = 1
	}
	return fmt.Sprintf("M %.1f %.1f L %.1f %.1f A %.1f %.1f 0 %d 1 %.1f %.1f L %.1f %.1f A %.1f %.1f 0 %d 0 %.1f %.1f Z",
		x0, y0, x1, y1, rOuter, rOuter, large, x2, y2, x3, y3, rInner, rInner, large, x0, y0)
}

// shortOrigin trims an origin down to something that can sit beside a 10px dot
// without colliding with its neighbour. The full origin is always in the node's
// tooltip and in the flagged table, so nothing is lost, only abbreviated.
func shortOrigin(origin string) string {
	s := origin
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	const max = 30
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// shortKind is the two-or-three letter code shown beside an ecosystem's name in
// the coverage table, where the full label is already present. It exists so the
// table and any future compact rendering agree on one abbreviation rather than
// each inventing its own.
func shortKind(kind, label string) string {
	switch kind {
	case "kt":
		return "KT"
	case "ct":
		return "CT"
	case "software":
		return "SW"
	case networkKind:
		return "WN"
	}
	if len(label) > 5 {
		return label[:5]
	}
	return label
}

// layoutGraph is the whole layout, as a pure function of the grouped logs and
// the current time. Kept free of the http and template machinery so it can be
// tested as arithmetic — in particular so the "does anything overlap at eighty
// nodes" question has an answer that is checked rather than eyeballed.
func layoutGraph(groups []logGroup, now time.Time) *graphView {
	return layoutGraphNet(groups, nil, now)
}

// awaitingOrbit is where a listed-but-never-pushed log is drawn: just past the
// 48h+ ring, inside the wedge. Past the ring rather than on it, because on it
// would read as "cosigned two days ago" — and there is no cosignature at all.
// The rim is still the right neighbourhood, for the reason layoutGraph gives
// for a record with no timestamp: an absent measurement must never render as
// a healthy one.
const awaitingOrbit = graphRMax + 8

// ringLabelHalfWidth is half the width of the widest age-ring label ("48h+ ·
// scale ends" at 10.5px mono), which the hollow nodes are kept clear of.
const ringLabelHalfWidth = 56.0

// placeNetworkGroup puts the witness-network wedge second in the dial, making
// one up if no listed log has pushed yet but some are waiting to.
//
// Second, because the dial starts at nine o'clock and runs clockwise: the
// first ecosystem takes the upper left and the second lands in the upper
// right, nearest the column of network witnesses whose declared edges run to
// it. Anywhere else those edges would have to cross the whole ring. The
// order is a legibility choice, like angle within a wedge, and carries no
// meaning.
func placeNetworkGroup(groups []logGroup, awaiting int) []logGroup {
	var net *logGroup
	rest := make([]logGroup, 0, len(groups)+1)
	for i := range groups {
		if groups[i].Kind == networkKind {
			c := groups[i]
			net = &c
			continue
		}
		rest = append(rest, groups[i])
	}
	if net == nil {
		if awaiting == 0 {
			return groups
		}
		net = &logGroup{Kind: networkKind, Label: kindLabel(networkKind)}
	}
	at := 1
	if len(rest) == 0 {
		at = 0
	}
	out := append([]logGroup{}, rest[:at]...)
	out = append(out, *net)
	return append(out, rest[at:]...)
}

func kindLabel(kind string) string {
	for _, k := range kindOrder {
		if k.kind == kind {
			return k.label
		}
	}
	return kind
}

// layoutGraphNet is layoutGraph plus the listed logs that have not pushed yet,
// which are laid out in the witness-network wedge by the same relaxation, so
// the no-overlap guarantee covers them too.
func layoutGraphNet(groups []logGroup, awaiting []NetworkLog, now time.Time) *graphView {
	g := &graphView{
		Scale: 1, ScalePct: 100,
		CX: graphCX, CY: graphCY, W: graphW, H: graphH,
		Generated: now.Format("2006-01-02 15:04:05 UTC"),
	}

	awaiting = append([]NetworkLog(nil), awaiting...)
	sort.Slice(awaiting, func(i, j int) bool { return awaiting[i].Origin < awaiting[j].Origin })
	groups = placeNetworkGroup(groups, len(awaiting))
	// A wedge's width follows how many dots it must hold, drawn or hollow:
	// sizing the network wedge by its pushed logs alone would pack every
	// hollow one onto a floor-width arc and shrink the whole fleet to fit.
	slots := func(grp logGroup) int {
		if grp.Kind == networkKind {
			return grp.Count + len(awaiting)
		}
		return grp.Count
	}

	total := 0
	for _, grp := range groups {
		total += slots(grp)
	}
	if total == 0 {
		return g
	}

	// Sector widths: by the square root of the log count, with a small floor.
	//
	// Neither extreme works. Strictly proportional allocation gives key
	// transparency — the ecosystem this project exists for, and the only one
	// where construction auditing is possible at all — a fifteen-degree
	// splinter, and hands nearly the whole dial to the ecosystem where every
	// row says the same thing. Equal wedges lie in the other direction, hiding
	// that CT is the overwhelming bulk of the coverage. A flat per-group floor
	// was tried and is worse than both: one unclassified log claimed fifty
	// degrees while seventy certificate logs fought over what was left.
	//
	// The square root is the usual compromise and it is the right one here: a
	// group with ten times the logs gets about three times the arc, so the
	// dominance is still visible while the small groups stay legible. The floor
	// only catches a group of one or two.
	n := float64(len(groups))
	available := 360 - n*graphGutter
	var weight float64
	for _, grp := range groups {
		weight += math.Sqrt(float64(slots(grp)))
	}
	floor := math.Min(16, available/n)
	spare := available - n*floor

	// Twelve o'clock is deliberately the middle of a gutter, so the ring labels
	// can run straight up from the centre without crossing any node.
	angle := -90 + graphGutter/2

	for _, grp := range groups {
		width := floor + spare*math.Sqrt(float64(slots(grp)))/weight
		s := graphSector{
			Kind: grp.Kind, Label: grp.Label, Short: shortKind(grp.Kind, grp.Label),
			Count: grp.Count, Entries: grp.Entries, TopTier: grp.TopTier,
			Stale: grp.Stale, Forked: grp.Forked,
			Start: angle, End: angle + width,
		}
		var hollow []NetworkLog
		if grp.Kind == networkKind {
			hollow = awaiting
			s.Awaiting = len(awaiting)
		}
		s.Wedge = wedgePath(graphR0-46, graphRMax+16, s.Start, s.End)
		s.Arc = arcPath(graphRMax+26, s.Start+1, s.End-1)

		mid := s.Start + width/2
		lx, ly := polar(mid, graphRMax+46)
		s.LabelX, s.LabelY = lx, ly
		switch {
		case lx < graphCX-24:
			s.LabelAnchor = "end"
		case lx > graphCX+24:
			s.LabelAnchor = "start"
		default:
			s.LabelAnchor = "middle"
		}
		g.Sectors = append(g.Sectors, s)
		angle = s.End + graphGutter

		// Slot assignment inside the sector: by size descending, then origin.
		// Sorting by size means the sector reads as a gradient rather than as
		// noise, and ordering by origin as a tiebreak means the arrangement is
		// deterministic — two renders a minute apart put every node in the same
		// place, so a reader can learn the map and then notice when something
		// moves. What moves is radius, and radius means staleness.
		rows := make([]logView, len(grp.Logs))
		copy(rows, grp.Logs)
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Size != rows[j].Size {
				return rows[i].Size > rows[j].Size
			}
			return rows[i].Origin < rows[j].Origin
		})

		sectorIdx := len(g.Sectors) - 1
		nslots := float64(len(rows) + len(hollow))
		for i, r := range rows {
			code, rank := tierCode(r.Tier)
			// A record with no timestamp is drawn at the outer rim, not at the
			// centre. An absent measurement must never render as the healthiest
			// possible one — that is the failure mode where a broken pipeline
			// looks like a perfect fleet.
			age := float64(graphAgeClamp)
			if !r.WitnessedAt.IsZero() {
				age = now.Sub(r.WitnessedAt).Minutes()
			}
			nr := nodeRadius(r.Size)
			nd := graphNode{
				Origin: r.Origin, Label: shortOrigin(r.Origin), Kind: grp.Kind, Group: grp.Label,
				Tier: r.Tier, Code: code, Rank: rank, Size: r.Size, Age: r.Age,
				Href:        "/log?origin=" + r.Origin,
				R:           nr,
				Square:      rank >= 4,
				Ring:        rank == 5 || rank == 3,
				Stale:       r.Stale,
				Forked:      r.Forked,
				FillOpacity: tierFill(rank),
				orbit:       ageRadius(age),
				sector:      sectorIdx,
			}
			slot := (float64(i) + 0.5) / nslots
			nd.angle = s.Start + width*slot
			// A node may be nudged sideways to avoid a collision but never out
			// of its own ecosystem's wedge: the grouping is data, the exact
			// angle is not.
			nd.lo, nd.hi = wedgeBounds(s, nr, nd.orbit)
			nd.Title = fmt.Sprintf("%s — %s · tier %s · %s entries · last cosigned %s",
				r.Origin, grp.Label, codeOrUnknown(code), humanCount(r.Size), r.Age)
			if r.Forked {
				nd.Title += " · FORKED"
			}
			g.Nodes = append(g.Nodes, nd)
		}
		// The hollow ones take the slots after the drawn ones, in origin order,
		// so the arrangement is as deterministic as the rest of the wedge.
		for i, nl := range hollow {
			nd := graphNode{
				Origin: nl.Origin, Label: shortOrigin(nl.Origin), Kind: grp.Kind, Group: grp.Label,
				Code: "?", R: graphNodeMin, Awaiting: true,
				orbit:  awaitingOrbit,
				sector: sectorIdx,
			}
			slot := (float64(len(rows)+i) + 0.5) / nslots
			nd.angle = s.Start + width*slot
			nd.lo, nd.hi = wedgeBounds(s, nd.R, nd.orbit)
			// The age rings are labelled straight up from the hub, and the
			// hollow run sits just past the outermost of them. If the wedge
			// spans twelve o'clock, keep each hollow node on its own side of
			// the labels rather than on top of "48h+ · scale ends".
			if nd.lo < 0 && nd.hi > 0 {
				clear := degFor(ringLabelHalfWidth+nd.R+2, nd.orbit)
				if nd.angle < 0 {
					nd.hi = math.Max(nd.lo, math.Min(nd.hi, -clear))
				} else {
					nd.lo = math.Min(nd.hi, math.Max(nd.lo, clear))
				}
				nd.angle = clampAngle(nd.angle, nd.lo, nd.hi)
			}
			lists := nl.List
			if len(nl.Lists) > 0 {
				lists = strings.Join(nl.Lists, ", ")
			}
			nd.Title = fmt.Sprintf("%s — listed on %s, awaiting first push · never cosigned here, "+
				"so not counted as witnessed, stale or corroborated", nl.Origin, lists)
			g.Nodes = append(g.Nodes, nd)
		}
	}

	// Relax, then shrink if relaxing was not enough, then relax again in the
	// room that freed up. See fitNodes for why shrinking is the concession the
	// layout is allowed to make and moving a node radially is not.
	for round := 0; round < 3; round++ {
		relaxAngles(g.Nodes)
		f := fitNodes(g.Nodes)
		g.Scale *= f
		if f == 1 {
			break
		}
	}
	// Quantised down to a 5% step. The exact factor a given fleet needs wobbles
	// with the ages of its logs, and a dot that is 3% smaller than it was an
	// hour ago for reasons the reader cannot see is a small lie told often.
	// Rounding to a coarse step means the scale changes rarely, visibly, and
	// with the note beside the legend to explain it.
	quantised := math.Floor(g.Scale*20) / 20
	if quantised < g.Scale {
		for i := range g.Nodes {
			g.Nodes[i].R *= quantised / g.Scale
		}
		g.Scale = quantised
	}
	g.ScalePct = int(math.Round(g.Scale * 100))

	for i := range g.Nodes {
		nd := &g.Nodes[i]
		nd.X, nd.Y = polar(nd.angle, nd.orbit)
		// A square of side sqrt(pi)*r has the same area as a circle of radius
		// r, so switching shape to encode tier does not accidentally also
		// encode a change in size — size is already spoken for.
		nd.SD = nd.R * 1.7725
		nd.SX, nd.SY = nd.X-nd.SD/2, nd.Y-nd.SD/2
		nd.InnerR = nd.R * 0.42
	}

	// Which nodes get a drawn label.
	//
	// Everything that is wrong (stale, forked) plus the two largest logs in
	// each ecosystem, which are the ones a reader recognises and uses to orient
	// themselves. That comes to roughly a dozen labels against eighty nodes,
	// which is the difference between a map and a wall of text.
	perSector := map[int]int{}
	for i := range g.Nodes {
		nd := &g.Nodes[i]
		if nd.Awaiting {
			// Hover-only. A drawn label would make a log that has never sent
			// us anything as prominent as the largest one we witness.
			continue
		}
		if nd.Stale || nd.Forked {
			nd.Labelled = true
			continue
		}
		if perSector[nd.sector] < 2 {
			nd.Labelled = true
			perSector[nd.sector]++
		}
	}
	// Every node gets label geometry, not only the labelled ones: the rest
	// carry the same text hidden, revealed on hover and on keyboard focus by a
	// CSS rule. That is the whole of the interactivity here — no script, and
	// nothing that a reader without a pointer loses, because the same text is
	// also in each node's <title> and in the tables below.
	for i := range g.Nodes {
		nd := &g.Nodes[i]
		lx, ly := polar(nd.angle, nd.orbit+nd.R+7)
		nd.LabelX, nd.LabelY = lx, ly+3.5
		switch {
		case lx < graphCX-10:
			nd.LabelAnchor = "end"
		case lx > graphCX+10:
			nd.LabelAnchor = "start"
		default:
			nd.LabelAnchor = "middle"
			nd.LabelY = ly
		}
	}
	unclashLabels(g.Nodes)

	for _, nd := range g.Nodes {
		if nd.Awaiting {
			g.AwaitingCount++
			continue
		}
		g.TotalLogs++
		g.TotalEntries += nd.Size
		if nd.Stale {
			g.StaleCount++
		}
		if nd.Forked {
			g.ForkedCount++
		}
		if nd.Stale || nd.Forked {
			g.Flagged = append(g.Flagged, nd)
		}
	}
	sort.Slice(g.Flagged, func(i, j int) bool { return g.Flagged[i].orbit > g.Flagged[j].orbit })

	// The guide rings are the scale. Without them the radial axis is a vibe;
	// with them it is a measurement a reader can read off. The two-hour ring is
	// drawn dashed and named because it is not an arbitrary tick — it is the
	// exact threshold `logView.Stale` uses, and the one the
	// kt_witness_log_staleness_seconds alert fires on.
	for _, r := range []struct {
		mins   float64
		label  string
		dashed bool
		note   string
	}{
		{60, "1h", false, ""},
		{120, "2h", true, "stale threshold"},
		{24 * 60, "24h", false, ""},
		{graphAgeClamp, "48h+", false, "scale ends"},
	} {
		rr := ageRadius(r.mins)
		g.Rings = append(g.Rings, graphRing{R: rr, Label: r.label, Dashed: r.dashed,
			Note: r.note, LabelY: graphCY - rr})
	}

	g.AriaLabel = fmt.Sprintf(
		"Radial map of %d witnessed logs around this witness. Distance from the centre is how long "+
			"ago each log was last cosigned, on a log scale from under an hour at the inner ring to "+
			"48 hours or more at the outer ring; logs past the dashed two-hour ring are stale. Each "+
			"ecosystem occupies its own wedge. Node area is the log's size in entries, and node "+
			"shape is its tier. %d of the %d logs are stale and %d are forked; every one of them is "+
			"listed in the table below this figure.",
		g.TotalLogs, g.StaleCount, g.TotalLogs, g.ForkedCount)
	if g.AwaitingCount > 0 {
		g.AriaLabel += fmt.Sprintf(" %d further logs are named on witness-network lists but have not "+
			"pushed a checkpoint yet; they are drawn hollow just outside the outer ring and are not "+
			"counted as witnessed.", g.AwaitingCount)
	}
	return g
}

// wedgeBounds is the range of angles a node of radius r at orbit may be slid
// across without any part of it leaving sector s.
func wedgeBounds(s graphSector, r, orbit float64) (lo, hi float64) {
	margin := degFor(r+1, orbit)
	lo, hi = s.Start+margin, s.End-margin
	if lo > hi {
		lo, hi = (s.Start+s.End)/2, (s.Start+s.End)/2
	}
	return lo, hi
}

func codeOrUnknown(code string) string {
	if code == "?" {
		return "unknown"
	}
	return code
}

// nodeRadius grows with the square root of the log's size — so a dot's area
// tracks entries — above a floor that keeps the smallest logs visible and
// clickable. The floor is doing real work at this fleet's spread: entries run
// from about 10^5 to 10^9, and a strictly proportional scale would draw the key
// transparency logs as specks a reader could neither see nor click. Size is
// therefore the weakest of the encodings on this page, which is the right
// ranking: it is the one fact already available in a sortable column on the
// index.
//
// Normalised against a fixed reference rather than against the largest log
// present, because a scale that renormalises to whatever happens to be in the
// set today would silently change every node's meaning when one log is added or
// removed, and a reader comparing this page to yesterday's would be comparing
// two different scales without being told.
func nodeRadius(size int64) float64 {
	if size <= 0 {
		return graphNodeMin
	}
	// 10^9 entries is about the size of the largest CT logs; it pins the top of
	// the scale so the clamp bites rarely rather than constantly.
	f := math.Sqrt(float64(size)) / math.Sqrt(1e9)
	r := graphNodeMin + (graphNodeMax-graphNodeMin)*f
	if r > graphNodeMax {
		return graphNodeMax
	}
	if r < graphNodeMin {
		return graphNodeMin
	}
	return r
}

// degFor converts a distance in pixels at a given orbit into an angle.
func degFor(px, orbit float64) float64 {
	if orbit <= 0 {
		return 0
	}
	return px / orbit * 180 / math.Pi
}

// relaxAngles resolves overlaps by moving nodes sideways only.
//
// The important constraint is what this function is NOT allowed to do: it may
// not move a node's radius, because radius is the age measurement and a layout
// that fudges it to make the picture tidier would be a picture that lies. It
// may not move a node out of its ecosystem's wedge either. Within those two
// constraints there is exactly one degree of freedom left, and this pushes
// pairs apart along it until they stop touching or until the passes run out.
//
// It is a fixed number of deterministic passes rather than a physics
// simulation, for the same reason the slot order is deterministic: the same
// data must always produce the same picture. With eighty nodes this is a few
// hundred thousand comparisons, which is nothing next to the store reads the
// page already does.
func relaxAngles(nodes []graphNode) {
	const passes = 900
	order, reach := byOrbit(nodes)
	for pass := 0; pass < passes; pass++ {
		moved := false
		for oi := range order {
			for oj := oi + 1; oj < len(order); oj++ {
				i, j := order[oi], order[oj]
				a, b := &nodes[i], &nodes[j]
				// Nodes are visited in radius order, so once the radial gap
				// alone exceeds what two dots could span there is nothing
				// further out that this one can touch. Without that break this
				// is 3,160 pairs times 600 passes on every page load, which is
				// real CPU spent on a public endpoint for no gain.
				if b.orbit-a.orbit > reach {
					break
				}
				ax, ay := polar(a.angle, a.orbit)
				bx, by := polar(b.angle, b.orbit)
				dx, dy := bx-ax, by-ay
				d := math.Hypot(dx, dy)
				need := a.R + b.R + graphPad
				if d >= need {
					continue
				}
				// Over-relaxed: pushing slightly harder than the overlap
				// strictly requires. A crowded wedge is a chain of sixty-odd
				// dots and an exactly-sufficient push propagates down it one
				// link per pass, which converges far too slowly to spend on a
				// page load. Overshooting settles the same arrangement in a
				// fraction of the passes.
				push := 1.8 * (need - d) / 2
				// Direction along the ring: whichever way they already differ.
				// Identical angles (possible when two logs share a slot after
				// earlier pushes) are separated by index so the result stays
				// deterministic rather than depending on floating-point noise.
				dir := 1.0
				if a.angle > b.angle || (a.angle == b.angle && i > j) {
					dir = -1
				}
				a.angle = clampAngle(a.angle-dir*degFor(push, a.orbit), a.lo, a.hi)
				b.angle = clampAngle(b.angle+dir*degFor(push, b.orbit), b.lo, b.hi)
				moved = true
			}
		}
		if !moved {
			break
		}
	}
	// Positions are materialised here so the overlap check that follows works
	// on the same coordinates the browser will draw.
	for i := range nodes {
		nodes[i].X, nodes[i].Y = polar(nodes[i].angle, nodes[i].orbit)
	}
}

// graphPad is the clear space kept between two drawn shapes. Small, but not
// zero: two dots that merely touch read as one lozenge.
const graphPad = 1.6

// byOrbit returns node indices ordered by distance from the centre, along with
// the radial distance beyond which two nodes cannot possibly touch. Both
// collision passes walk the nodes in this order so they can stop early.
func byOrbit(nodes []graphNode) ([]int, float64) {
	order := make([]int, len(nodes))
	maxR := 0.0
	for i := range nodes {
		order[i] = i
		if nodes[i].R > maxR {
			maxR = nodes[i].R
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return nodes[order[a]].orbit < nodes[order[b]].orbit })
	return order, 2*maxR + graphPad
}

// fitNodes guarantees that no two drawn shapes overlap, by shrinking every dot
// by the same factor when sliding them sideways was not enough.
//
// A wedge can be denser than its arc: sixty-five certificate logs all refreshed
// within the same few minutes have almost the same radius by definition, and if
// radius is a measurement then they genuinely all belong on the same ring
// whether or not that ring is long enough to hold them. Something has to give,
// and there are only three candidates. Moving a node radially is out — that is
// the measurement, and a picture that fudges it is a picture that lies about the
// one thing this page exists to show. Letting the dots overlap is out too: an
// unreadable pile is not a map. That leaves the size scale, which is the least
// load-bearing of the three, because shrinking every dot by one common factor
// preserves every comparison between dots exactly — only the absolute scale
// changes, and the page prints that factor so a reader is never comparing two
// renders at two scales without being told.
//
// It returns the factor applied, so the caller can relax again in the space it
// just created and accumulate the total.
func fitNodes(nodes []graphNode) float64 {
	worst := 1.0
	order, reach := byOrbit(nodes)
	for oi := range order {
		for oj := oi + 1; oj < len(order); oj++ {
			i, j := order[oi], order[oj]
			a, b := &nodes[i], &nodes[j]
			if b.orbit-a.orbit > reach {
				break
			}
			d := math.Hypot(b.X-a.X, b.Y-a.Y)
			if d <= 0 {
				continue
			}
			if need := a.R + b.R + graphPad; d < need {
				if f := d / need; f < worst {
					worst = f
				}
			}
		}
	}
	if worst >= 1 {
		return 1
	}
	for i := range nodes {
		nodes[i].R *= worst
	}
	return worst
}

// labelBox estimates a drawn label's bounding box. Labels are 10px monospace,
// so a character is about 6px wide and the box can be worked out from the
// text alone, without a font metric.
func labelBox(nd *graphNode) (x0, y0, x1, y1 float64) {
	w := 6.0 * float64(len([]rune(nd.Label)))
	switch nd.LabelAnchor {
	case "end":
		x0 = nd.LabelX - w
	case "middle":
		x0 = nd.LabelX - w/2
	default:
		x0 = nd.LabelX
	}
	return x0, nd.LabelY - 9, x0 + w, nd.LabelY + 3
}

// unclashLabels hides drawn labels that would overprint one another.
//
// Neighbouring nodes are kept apart by relaxAngles, but their labels are
// wider than the nodes, and two labelled logs a few degrees apart near twelve
// o'clock — where anchors switch from "end" to "start" — print on top of each
// other and become unreadable as both. Where two collide, the one a reader
// must not miss (stale or forked) keeps its label, then the larger log; the
// other falls back to hover, which every node already has.
func unclashLabels(nodes []graphNode) {
	var order []int
	for i := range nodes {
		if nodes[i].Labelled {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		na, nb := &nodes[order[a]], &nodes[order[b]]
		fa, fb := na.Stale || na.Forked, nb.Stale || nb.Forked
		if fa != fb {
			return fa
		}
		return na.Size > nb.Size
	})
	var kept [][4]float64
	for _, i := range order {
		x0, y0, x1, y1 := labelBox(&nodes[i])
		clash := false
		for _, k := range kept {
			if x0 < k[2] && k[0] < x1 && y0 < k[3] && k[1] < y1 {
				clash = true
				break
			}
		}
		if clash && !(nodes[i].Stale || nodes[i].Forked) {
			nodes[i].Labelled = false
			continue
		}
		kept = append(kept, [4]float64{x0, y0, x1, y1})
	}
}

func clampAngle(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// attachPeers places the other witnesses and marks which logs they corroborate.
//
// They sit on the left, outside the wedges, because they are not part of the
// fleet being measured — they are the only reason any of it can be checked. A
// witness's own signature over a checkpoint it fetched itself always agrees
// with itself; only a second party publishing a root at the same size can
// contradict a log. So the number this layout is built to make unmissable is
// not how many peers there are, it is how many logs have none.
func attachPeers(g *graphView, gs *gossipView, corr map[string][]string) {
	drawn := 0
	for i := range g.Nodes {
		if g.Nodes[i].Awaiting {
			// Nothing to corroborate: we hold no checkpoint for it.
			continue
		}
		drawn++
		if who, ok := corr[g.Nodes[i].Origin]; ok && len(who) > 0 {
			g.Nodes[i].Corroborated = true
			g.Nodes[i].Peers = who
			g.Corroborated++
		}
	}
	g.Unobserved = drawn - g.Corroborated
	g.PeerCount = len(gs.Peers)

	// Stacked down the left margin. One peer today; the spacing holds for a
	// handful without a layout pass, and if this ever needs more than that,
	// the ecosystem will have changed enough to warrant redrawing it.
	const px = 96.0
	top := graphCY - float64(len(gs.Peers)-1)*70.0/2
	for i, p := range gs.Peers {
		y := top + float64(i)*70.0
		width := 1.0 + math.Min(6.0, float64(p.Comparable)/2.0)
		gp := graphPeer{
			Name: p.Witness, Label: shortOrigin(p.Witness),
			X: px, Y: y, R: 13,
			LabelX: px, LabelY: y + 28,
			Comparable: p.Comparable, Agreed: p.Agreed, Origins: p.Origins,
			Divergent: p.Comparable > p.Agreed,
			Width:     width,
		}
		gp.Title = fmt.Sprintf("%s — %d logs comparable, %d agreed",
			p.Witness, p.Comparable, p.Agreed)
		if gp.Divergent {
			gp.Title += " — DISAGREEMENT"
		}
		g.Peers = append(g.Peers, gp)
	}
}

func (s *Server) graphPage(w http.ResponseWriter, r *http.Request) {
	g, err := s.buildGraph()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = graphTmpl.Execute(w, g)
}

// buildGraph is everything /graph draws, before it is rendered.
func (s *Server) buildGraph() (*graphView, error) {
	v, err := s.buildStatus()
	if err != nil {
		return nil, err
	}
	// Listed logs with no record here are the hollow ones. Logs a list names
	// that are also configured are polled, and already on the map as
	// themselves.
	nv := s.network()
	var awaiting []NetworkLog
	if nv != nil {
		have := make(map[string]bool, len(v.Logs))
		for _, lv := range v.Logs {
			have[lv.Origin] = true
		}
		for _, nl := range nv.Logs {
			if !nl.Static && !have[nl.Origin] {
				awaiting = append(awaiting, nl)
			}
		}
	}
	g := layoutGraphNet(v.Groups, awaiting, v.Now)
	g.WitnessName = v.WitnessName
	gs := s.peerSummary(v)
	attachPeers(g, gs, s.corroborated(v))
	attachNetwork(g, nv, gs)
	// A retired log is one with stored history that is no longer configured. It
	// is not drawn, because it is not being witnessed and putting it on a
	// liveness map would make the map claim something false — but it is counted
	// in words, because "we quietly stopped watching this" is exactly the kind
	// of change that should never be invisible.
	g.Retired, g.RetiredCount = v.Retired, len(v.Retired)
	return g, nil
}

var graphFuncs = template.FuncMap{
	"comma":  func(n int64) string { return humanCount(n) },
	"commai": func(n int) string { return humanCount(int64(n)) },
	// SVG coordinates: one decimal is plenty of precision for a 1200px canvas
	// and keeps the emitted markup readable by a human diffing two renders.
	"f": func(v float64) string { return fmt.Sprintf("%.1f", v) },
	// Alternating wedge tints: the sector boundaries have to be visible without
	// spending a colour on them, since colour is already carrying tier.
	"odd": func(i int) bool { return i%2 == 1 },
}

var graphTmpl = template.Must(template.New("graph").Funcs(graphFuncs).Parse(graphPageHTML))
