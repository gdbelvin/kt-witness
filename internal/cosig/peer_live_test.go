package cosig

import (
	"context"
	"os"
	"testing"
)

// TestLivePollsAPeerWitness checks the parser against the real page, because a
// screen-scraper that has never met the page it scrapes is not a scraper.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLivePollsAPeerWitness(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	p := NewPeerPoller(map[string]string{
		"witness.stagemole.eu": "https://witness.stagemole.eu/",
	})
	views, err := p.Poll(context.Background(), "witness.stagemole.eu")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) == 0 {
		t.Fatal("parsed no logs from a page that lists dozens — the format has " +
			"probably changed, which is exactly what this test is for")
	}
	t.Logf("%s publishes %d logs", views[0].Witness, len(views))
	for _, v := range views[:min(4, len(views))] {
		t.Logf("  %s size %d root %s", v.Origin, v.Size, v.Root)
		if v.Origin == "" || v.Root == "" {
			t.Errorf("incomplete view: %+v", v)
		}
	}
}

// An unreachable or unparseable peer must be silent, not alarming. A witness
// that raises errors about its own screen-scraping is one whose alarms get
// ignored — and the alarms that matter here are the ones about logs.
func TestUnreachablePeerIsSilent(t *testing.T) {
	p := NewPeerPoller(map[string]string{"w": "https://127.0.0.1:1/"})
	views, err := p.Poll(context.Background(), "w")
	if err != nil || len(views) != 0 {
		t.Errorf("an unreachable peer should yield nothing quietly, got %v / %v", views, err)
	}
	// An unconfigured peer IS a configuration error, and should say so.
	if _, err := p.Poll(context.Background(), "unknown"); err == nil {
		t.Error("an unconfigured peer should be reported as a configuration error")
	}
}

// The parser must survive the page it was written against, and must not invent
// entries from text that merely looks similar.
func TestPeerPageParsing(t *testing.T) {
	page := `<div><pre># litewitness witness.example
## Logs
- sigsum.org/v1/tree/abc
  (size 39055, root /sIFqjEU42ZYuHevpOVgv2rqFzK6rX5sYsSN2RfY82k=)
- keyserver.geomys.org
  (size 79, root WQTa6sJ6jY2+mQU/cpFmtrkiHUIYpa6P/2z4ZL8jsUA=)
- broken.example/log
  (this line has no size)
</pre></div>`
	p := &PeerPoller{Peers: map[string]string{}}
	_ = p
	views := parsePeerPage("witness.example", page)
	if len(views) != 2 {
		t.Fatalf("expected 2 well-formed entries, got %d: %+v", len(views), views)
	}
	if views[1].Origin != "keyserver.geomys.org" || views[1].Size != 79 {
		t.Errorf("second entry parsed wrong: %+v", views[1])
	}
	if views[1].Root != "WQTa6sJ6jY2+mQU/cpFmtrkiHUIYpa6P/2z4ZL8jsUA=" {
		t.Errorf("root parsed wrong: %q", views[1].Root)
	}
}
