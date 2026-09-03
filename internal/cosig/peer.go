package cosig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Proactively fetching another witness's view.
//
// # Why this exists alongside reading cosignatures
//
// Cosignatures read off a checkpoint we fetched cannot detect a split view.
// Every signature on that document is over the same body, so they agree by
// construction; a log serving two histories would simply attach a different set
// of cosignatures to each. That channel gives corroboration, not detection.
//
// Detection requires the other witness's INDEPENDENTLY OBTAINED view, because
// only then can two accounts of the same size differ.
//
// # What would make this conclusive
//
// The convicting signature is the LOG'S OWN, not the witness's. If a peer
// served us the checkpoint it holds — body plus the log's signature over it —
// and that body named a different root at a size we also hold signed, the log
// would have signed two roots at one size. That is the log convicting itself,
// it needs nobody to be trusted, and it is reproducible by any third party.
//
// litewitness already holds exactly that artifact. It does not serve it: only
// POST /add-checkpoint exists, and every retrieval path returns 404. So the
// missing piece for real gossip is small and upstream — a witness endpoint that
// returns the signed checkpoint it is holding.
//
// # What this is worth today
//
// The status page it does publish is NOT SIGNED. A disagreement found here is
// therefore a LEAD: it could be stale, altered in transit, or simply wrong, and
// this project does not publish accusations on unsigned evidence. It is the
// signal to go and obtain the signed artifact — which today means asking a
// human to, since no endpoint serves it.
//
// # Fragility
//
// This parses a human-readable HTML page, because no witness implementation
// currently serves its view in a machine-readable, signed form. That is brittle
// by nature: an upstream layout change breaks it. So a parse failure is
// deliberately benign — zero observations, no error escalated — because the
// alternative is a witness that starts alarming about its own screen-scraping.
//
// The real fix is upstream. litewitness already HAS the signatures; it simply
// does not serve them for retrieval. A signed peer-view endpoint would make
// cross-witness gossip conclusive rather than advisory, and is worth asking for.

// PeerView is what another witness says it has seen for one log.
type PeerView struct {
	Witness string
	Origin  string
	Size    int64
	Root    string
}

// PeerPoller fetches other witnesses' published views.
type PeerPoller struct {
	Client *http.Client
	// Peers maps a witness name to its status page URL.
	Peers map[string]string
}

func NewPeerPoller(peers map[string]string) *PeerPoller {
	return &PeerPoller{
		Client: &http.Client{Timeout: 30 * time.Second},
		Peers:  peers,
	}
}

// litewitness renders each log as a name line followed by an indented
// "(size N, root R)". Anchored loosely on purpose: the surrounding markup is
// not our business and is the part most likely to change.
var peerLogRe = regexp.MustCompile(`(?m)^-\s+(\S+)\s*\n\s*\(size\s+(\d+),\s*root\s+(\S+?)\)`)

// Poll returns everything a peer says it has witnessed.
//
// An unreachable peer, a changed page format, or an unparseable body all return
// no observations and no error. None of those is evidence of anything, and a
// witness that alarms about its own scraping is a witness whose alarms get
// ignored.
func (p *PeerPoller) Poll(ctx context.Context, witness string) ([]PeerView, error) {
	url, ok := p.Peers[witness]
	if !ok {
		return nil, fmt.Errorf("cosig: no status URL configured for %q", witness)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, nil // unreachable is not evidence
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil
	}

	return parsePeerPage(witness, string(body)), nil
}

// parsePeerPage extracts the log listing from a witness status page.
//
// Split out from Poll so it can be tested without a network, which is the only
// way to keep a scraper honest about formats it has not met.
func parsePeerPage(witness, body string) []PeerView {
	text := stripTags(body)
	matches := peerLogRe.FindAllStringSubmatch(text, -1)
	out := make([]PeerView, 0, len(matches))
	for _, m := range matches {
		size, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, PeerView{
			Witness: witness, Origin: m[1], Size: size, Root: m[3],
		})
	}
	return out
}

// stripTags removes HTML markup so the log listing can be read as text.
var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string {
	return strings.ReplaceAll(tagRe.ReplaceAllString(s, ""), "\r\n", "\n")
}

// Divergence is a peer reporting a different root at a size we also witnessed.
//
// Named a divergence rather than a fork on purpose. It is a lead: the peer's
// page is unsigned, so this cannot support an accusation on its own, and the
// correct response is to go and obtain the signed artifact.
type Divergence struct {
	Origin    string
	Size      int64
	OurRoot   string
	Witness   string
	TheirRoot string
}

func (d *Divergence) String() string {
	return fmt.Sprintf(
		"%s at size %d: we witnessed root %s, %s publishes %s. "+
			"Their page is unsigned, so this is a LEAD, not evidence — obtain a "+
			"signed cosignature before treating it as a finding",
		d.Origin, d.Size, d.OurRoot, d.Witness, d.TheirRoot)
}
