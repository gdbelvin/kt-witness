package server

import (
	"fmt"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

// A log that has gone stale must be visible on the map without a reader having
// to know it was already looking for it. This is the failure the page was built
// for: a log can sit in row sixty of a table with a small STALE pill for three
// days and nobody notices, so the test asserts the two things that make it
// impossible to miss here — it is named in the flagged table, and it is drawn
// outside the two-hour ring rather than merely coloured differently.
func TestGraphPageSurfacesAStaleLog(t *testing.T) {
	db, err := store.Open(t.TempDir() + "/g.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	now := time.Now().UTC()
	put := func(origin string, size int64, at time.Time) {
		var h tlog.Hash
		h[0] = byte(size)
		if err := db.CompareAndSet(nil, &store.Record{
			Origin: origin, Size: size, Hash: h,
			Cosigned: []byte(origin + "\n"), WitnessedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("fresh.example.com/ct", 900000000, now.Add(-9*time.Minute))
	put("kt.example.com/directory", 120000, now.Add(-20*time.Minute))
	put("tuscolo.example.com/sunlight", 4000000, now.Add(-72*time.Hour))

	s := &Server{
		Store:   db,
		VKey:    "witness.example.com+deadbeef+AAAA",
		Version: "test",
		Tiers: map[string]string{
			"fresh.example.com/ct":         "A (append-only)",
			"kt.example.com/directory":     "B+ (construction audited)",
			"tuscolo.example.com/sunlight": "A (append-only)",
		},
		// One log deliberately has no declared kind. groupByKind promises never
		// to drop such a log, and the map must keep that promise too — a log
		// that vanishes from a coverage picture because its config lacks a
		// field is exactly the kind of silent omission this project refuses.
		Kinds: map[string]string{
			"fresh.example.com/ct":     "ct",
			"kt.example.com/directory": "kt",
		},
	}

	rec := httptest.NewRecorder()
	s.graphPage(rec, httptest.NewRequest("GET", "/graph", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type %q, want text/html", ct)
	}
	body := rec.Body.String()

	for _, want := range []string{
		"<svg",                         // there is a picture
		"tuscolo.example.com/sunlight", // the stale log, named
		"STALE",                        // and flagged in words, not only in colour
		"3d ago",                       // with its real age
		"fresh.example.com/ct",
		"kt.example.com/directory",
		"Key transparency", // the ecosystem wedges are labelled
		"Other",            // including the one with no declared kind
		"stale threshold",  // the ring that makes the distance readable
		"Needs attention",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("graph page omits %q", want)
		}
	}

	// The no-dependencies rule is a security property, not a preference: this
	// page must render with the network unplugged. Asserted here because it is
	// the kind of thing that gets broken by a well-meaning "just pull in one
	// tiny library" edit years from now.
	for _, forbidden := range []string{"<script", "<link ", "http://", "cdn.", "@import"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("graph page contains %q — it must fetch and run nothing", forbidden)
		}
	}
}

// synthGroups builds a realistically-shaped fleet: a few large key transparency
// logs, a great many certificate logs, a couple of software ones. The shape
// matters — the layout's hard case is precisely CT's long tail of same-sized
// nodes all refreshed within the same hour, which is where a naive radial
// layout turns into a solid arc of overlapping dots.
func synthGroups(now time.Time, n int) []logGroup {
	var logs []logView
	for i := 0; i < n; i++ {
		kind, size, tier := "ct", int64(50_000_000+i*7_000_000), "A (append-only)"
		switch {
		case i%13 == 0:
			kind, size, tier = "kt", int64(200_000+i*1_000), "B+ (construction audited)"
		case i%17 == 0:
			kind, size, tier = "software", int64(9_000_000+i*3_000), "A+ (root-chain continuity)"
		}
		// Refreshes are hourly and staggered, so most of the fleet lands in a
		// narrow band of ages, with one log left far behind.
		age := time.Duration(i%55) * time.Minute
		if i == 3 {
			age = 72 * time.Hour
		}
		logs = append(logs, logView{
			Origin:      fmt.Sprintf("log%02d.example.com/x", i),
			Kind:        kind,
			Tier:        tier,
			Size:        size,
			WitnessedAt: now.Add(-age),
			Age:         age.String(),
			Stale:       age > 2*time.Hour,
		})
	}
	return groupByKind(logs)
}

// Eighty nodes is enough that "draw a dot per log" stops being a layout and
// starts being a pile. The map is only worth serving if every node is
// separately visible, so that is asserted rather than eyeballed: no two drawn
// shapes may overlap.
func TestGraphLayoutDoesNotOverlapAtFleetScale(t *testing.T) {
	now := time.Now().UTC()
	g := layoutGraph(synthGroups(now, 80), now)
	if len(g.Nodes) != 80 {
		t.Fatalf("laid out %d nodes, want 80", len(g.Nodes))
	}

	worst := math.Inf(1)
	var wa, wb string
	for i := range g.Nodes {
		for j := i + 1; j < len(g.Nodes); j++ {
			a, b := g.Nodes[i], g.Nodes[j]
			gap := math.Hypot(b.X-a.X, b.Y-a.Y) - (a.R + b.R)
			if gap < worst {
				worst, wa, wb = gap, a.Origin, b.Origin
			}
		}
	}
	if worst < 0 {
		t.Errorf("nodes overlap by %.2fpx (%s / %s); the map is unreadable at this density",
			-worst, wa, wb)
	}

	// Nothing may escape the canvas either, label margins included.
	for _, nd := range g.Nodes {
		if nd.X-nd.R < 0 || nd.X+nd.R > graphW || nd.Y-nd.R < 0 || nd.Y+nd.R > graphH {
			t.Errorf("%s drawn outside the viewBox at (%.1f, %.1f)", nd.Origin, nd.X, nd.Y)
		}
	}
}

// Distance from the centre is a measurement, and the relaxation pass that
// resolves overlaps is only allowed to move a node sideways. If it ever starts
// nudging radius to tidy the picture up, the picture stops being true — so the
// invariant is pinned here: age alone decides how far out a node sits.
func TestGraphRadiusIsAgeAndOnlyAge(t *testing.T) {
	now := time.Now().UTC()
	g := layoutGraph(synthGroups(now, 80), now)

	twoHour := ageRadius(120)
	for _, nd := range g.Nodes {
		r := math.Hypot(nd.X-graphCX, nd.Y-graphCY)
		if math.Abs(r-nd.orbit) > 0.01 {
			t.Fatalf("%s sits at radius %.2f but its age says %.2f", nd.Origin, r, nd.orbit)
		}
		if nd.Stale != (r > twoHour) {
			t.Errorf("%s: stale=%v but drawn at radius %.1f against a 2h ring at %.1f",
				nd.Origin, nd.Stale, r, twoHour)
		}
	}

	// And the stale one is not merely outside the ring, it is conspicuously
	// outside it: a reader must be able to spot it across the room.
	if len(g.Flagged) != 1 {
		t.Fatalf("flagged %d logs, want the single stale one", len(g.Flagged))
	}
	if got := g.Flagged[0].orbit; got < twoHour+40 {
		t.Errorf("the stale log is drawn at %.1f, only %.1fpx past the 2h ring at %.1f",
			got, got-twoHour, twoHour)
	}
	if !g.Flagged[0].Labelled {
		t.Error("the stale log is not labelled on the map; position would be its only clue")
	}
}

// Grouping is data; the exact angle a node is given is not. A node may be slid
// sideways to avoid a collision, but never out of its own ecosystem's wedge —
// otherwise the clustering that the whole layout is built on quietly stops
// being true at exactly the densities where it matters most.
func TestGraphNodesStayInsideTheirEcosystemWedge(t *testing.T) {
	now := time.Now().UTC()
	g := layoutGraph(synthGroups(now, 80), now)
	for _, nd := range g.Nodes {
		s := g.Sectors[nd.sector]
		if nd.angle < s.Start-0.001 || nd.angle > s.End+0.001 {
			t.Errorf("%s (%s) drifted to %.2f°, outside the %s wedge [%.2f°, %.2f°]",
				nd.Origin, nd.Kind, nd.angle, s.Label, s.Start, s.End)
		}
	}
}

// The tier ladder must come from tierRank, so that the map and the grouped
// tables can never disagree about which tier is stronger — and an unrecognised
// tier must degrade to a visible "?" rather than silently drawing as the
// weakest one, which would understate a log rather than merely fail to describe
// it.
func TestGraphTierCodesFollowTierRank(t *testing.T) {
	for _, c := range []struct {
		tier string
		code string
	}{
		{"A (append-only)", "A"},
		{"A+ (root-chain continuity)", "A+"},
		{"B (construction audit)", "B"},
		{"B+ (construction audited)", "B+"},
		{"", "?"},
		{"Z (from the future)", "?"},
	} {
		code, rank := tierCode(c.tier)
		if code != c.code {
			t.Errorf("tierCode(%q) = %q, want %q", c.tier, code, c.code)
		}
		if rank != tierRank(c.tier) {
			t.Errorf("tierCode(%q) rank %d disagrees with tierRank %d", c.tier, rank, tierRank(c.tier))
		}
	}
	if tierFill(5) <= tierFill(2) {
		t.Error("the tier intensity ladder is inverted: a stronger tier must not draw fainter")
	}
}
