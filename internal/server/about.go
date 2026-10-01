package server

// The /about page.
//
// witness-network.org asks every participating witness to publish, at a stable
// URL, four facts: its cosignature/v1 verifier key, its add-checkpoint URL, the
// lists it follows, and how often it re-reads them. This page states those and
// nothing else of substance — the status page already answers everything else,
// and a registration reviewer should not have to hunt for the key among the
// coverage figures.
//
// Same negotiation as "/": a browser gets HTML, anything else gets plain text,
// so the facts can be checked with curl.

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// AboutInfo is what the /about page states. witness-network.org requires a
// public page giving the cosignature/v1 vkey, the add-checkpoint URL, the
// lists followed, and how often they are re-read.
type AboutInfo struct {
	// PublicURL is the externally reachable base, e.g.
	// "https://witness.gdbsecurity.com". The add-checkpoint URL is derived
	// from it. Empty derives it from the request, which is right behind the
	// tunnel as long as the tunnel preserves Host.
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

// independenceNote is the one caveat the page must carry. docs/design.md
// argues that a witness which only sees what an operator chooses to send it is
// not independent; logs discovered from a list are exactly that case, and a
// reader deciding how much a cosignature from us is worth should be told.
const independenceNote = "Logs discovered from a witness-network list come with no monitoring URL, " +
	"so this witness cosigns them only when their operator pushes a checkpoint: for those logs it sees " +
	"only what the operator chooses to send it, and is not independent of that operator. " +
	"The C2SP logs it polls on its own schedule it also accepts pushes for, through the same checks."

const noListsNote = "This witness does not follow any witness-network list yet."

type aboutView struct {
	WitnessName   string
	VKey          string
	KeyType       string
	AddCheckpoint string
	PushEnabled   bool
	Lists         []string
	Refresh       string
	Operator      string
	Contact       string
	NoLists       string
	Independence  string
}

func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/about" {
		http.NotFound(w, r)
		return
	}
	v := &aboutView{
		VKey:          s.VKey,
		KeyType:       vkeyType(s.VKey),
		AddCheckpoint: s.publicURL(r) + "/add-checkpoint",
		PushEnabled:   s.AddCheckpoint != nil,
		Lists:         s.About.Lists,
		Refresh:       s.About.ListRefresh,
		Operator:      s.About.Operator,
		Contact:       s.About.Contact,
		NoLists:       noListsNote,
		Independence:  independenceNote,
	}
	if i := strings.Index(s.VKey, "+"); i > 0 {
		v.WitnessName = s.VKey[:i]
	}

	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		aboutTmpl.Execute(w, v)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s — witness-network participation\n\n", orUnknown(v.WitnessName))
	// Unset fields are left out rather than printed as placeholders: a page
	// saying "not stated" reads as a witness that is half configured.
	if v.Operator != "" {
		fmt.Fprintf(w, "operator:\n  %s\n\n", v.Operator)
	}
	if v.Contact != "" {
		fmt.Fprintf(w, "contact:\n  %s\n\n", v.Contact)
	}
	fmt.Fprintf(w, "witness verifier key (%s):\n  %s\n\n", v.KeyType, v.VKey)
	fmt.Fprintf(w, "add-checkpoint URL:\n  %s\n", v.AddCheckpoint)
	if !v.PushEnabled {
		fmt.Fprintf(w, "  (push is not enabled on this instance; the URL answers 404)\n")
	}
	fmt.Fprintf(w, "\nwitness-network lists followed:\n")
	if len(v.Lists) == 0 {
		fmt.Fprintf(w, "  none. %s\n", v.NoLists)
	} else {
		for _, l := range v.Lists {
			fmt.Fprintf(w, "  %s\n", l)
		}
	}
	if len(v.Lists) > 0 && v.Refresh != "" {
		fmt.Fprintf(w, "\nlist refresh interval:\n  %s\n", v.Refresh)
	}
	fmt.Fprintf(w, "\nindependence:\n  %s\n", v.Independence)
}

// publicURL is the configured base, or failing that the one the request was
// addressed to. The service sits behind a Cloudflare Tunnel, which terminates
// TLS and forwards plain HTTP, so the scheme comes from X-Forwarded-Proto
// before it comes from the connection.
func (s *Server) publicURL(r *http.Request) string {
	if u := strings.TrimRight(s.About.PublicURL, "/"); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		// A proxy chain may append; the first hop is the client's.
		scheme = strings.TrimSpace(strings.Split(p, ",")[0])
	}
	return scheme + "://" + r.Host
}

// vkeyType names the key type byte of a vkey, so the page states what the key
// actually is rather than what it is supposed to be. witness-network requires
// 0x04, cosignature/v1; a misconfigured key should be visible here, not
// discovered at registration.
func vkeyType(vkey string) string {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return "unparseable vkey"
	}
	b, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(b) == 0 {
		return "unparseable vkey"
	}
	if b[0] == 0x04 {
		return "vkey, key type 0x04, cosignature/v1"
	}
	return fmt.Sprintf("vkey, key type 0x%02x — NOT cosignature/v1", b[0])
}

var aboutTmpl = template.Must(template.New("about").Parse(aboutPageHTML))

const aboutPageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>About — {{.WitnessName}}</title>
<style>` + uiCSS + `
.fact{margin:0 0 1.4rem}
.fact .key{display:block}
</style></head><body><div class="wrap">

<header>
  <p class="sub"><a href="/">← {{.WitnessName}}</a></p>
  <h1>About this witness</h1>
  <p class="sub">What <a href="https://witness-network.org/">witness-network.org</a> asks every
  participating witness to state. Also served as plain text to a non-browser client.</p>
</header>

{{if or .Operator .Contact}}<h2>Operator</h2>
<div class="fact">
  {{if .Operator}}<div class="klabel">name</div><div>{{.Operator}}</div>{{end}}
  {{if .Contact}}<div class="klabel" style="margin-top:.5rem">contact</div><div>{{.Contact}}</div>{{end}}
</div>
{{end}}
<h2>Witness verifier key</h2>
<div class="fact">
  <div class="klabel">{{.KeyType}}</div>
  <code class="key">{{.VKey}}</code>
</div>

<h2>Add-checkpoint URL</h2>
<div class="fact">
  <code class="key">{{.AddCheckpoint}}</code>
  {{if not .PushEnabled}}<p class="note">Push is not enabled on this instance; the URL answers 404.</p>{{end}}
</div>

<h2>Witness-network lists followed</h2>
<div class="fact">
  {{if .Lists}}
  {{range .Lists}}<code class="key">{{.}}</code>{{end}}
  {{else}}
  <p>None. {{.NoLists}}</p>
  {{end}}
  {{if and .Lists .Refresh}}<div class="klabel" style="margin-top:.8rem">re-read every</div><div><code>{{.Refresh}}</code></div>{{end}}
</div>

<h2>Independence</h2>
<p class="note">{{.Independence}}</p>

</div></body></html>
`
