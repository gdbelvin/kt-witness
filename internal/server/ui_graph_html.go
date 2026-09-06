package server

// The ecosystem map's markup, kept beside the layout the way the gossip page
// keeps its own. Same rule as everywhere else in this UI: no CDN, no font
// fetch, no script tag. The only thing that moves on this page is a CSS :hover
// rule, and a reader with no pointer loses nothing by it — every label it
// reveals is also in the node's <title> and in the tables underneath.
//
// The stylesheet below appends to uiCSS rather than replacing it, so the SVG
// inherits --ok, --warn, --bad, --rule and the light-mode override for free.
// The nodes are styled by class for exactly that reason: a hard-coded fill
// would look correct in dark mode and wrong in a printout.

const graphPageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ecosystem map — {{.WitnessName}}</title>
<style>` + uiCSS + `
.map{border:1px solid var(--rule);border-radius:6px;background:var(--panel);padding:.4rem;margin:1rem 0}
.map svg{display:block;width:100%;height:auto}

.wedge{fill:var(--sunken);stroke:none}
.wedge.alt{opacity:.55}
.arc{fill:none;stroke:var(--rule2);stroke-width:1.6}
.ring{fill:none;stroke:var(--rule2);stroke-width:1;opacity:.85}
.ring.dash{stroke:var(--warn);stroke-dasharray:5 5;opacity:.85}
.ringlab{font-family:var(--mono);font-size:10.5px;fill:var(--faint)}
.ringlab.warn{fill:var(--warn)}
.slabel{font-size:12.5px;font-weight:600;letter-spacing:.04em;fill:var(--ink)}
.slabel tspan{font-weight:400;font-size:11px;fill:var(--muted)}

.spoke{stroke:var(--rule2);stroke-width:.7;opacity:.5}
.spoke.stale{stroke:var(--warn);stroke-width:1.2;stroke-dasharray:4 3;opacity:1}
.spoke.fork{stroke:var(--bad);stroke-width:1.4;opacity:1}

.node{fill:var(--ok);stroke:var(--ok);stroke-width:1.1}
.node.stale{stroke:var(--warn);stroke-width:1.6;stroke-dasharray:2.6 2}
.node.fork{stroke:var(--bad);stroke-width:2}
.inner{fill:none;stroke:var(--panel);stroke-width:1.4;opacity:.95}
.hub{fill:var(--panel);stroke:var(--ok);stroke-width:2}
.hublab{font-family:var(--mono);font-size:12px;fill:var(--ink);font-weight:600}
.hubsub{font-size:10.5px;letter-spacing:.1em;fill:var(--faint)}

.nlabel{font-family:var(--mono);font-size:10px;fill:var(--muted);paint-order:stroke;
        stroke:var(--panel);stroke-width:3px;stroke-linejoin:round}
.nlabel.stale{fill:var(--warn)}
.nlabel.fork{fill:var(--bad)}
.nlabel.hov{opacity:0}
.nd:hover .nlabel.hov,.nd:focus .nlabel.hov{opacity:1}
.nd:hover .node,.nd:focus .node{stroke:var(--ink);stroke-width:2}
.nd{cursor:pointer}

.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:1px;
        background:var(--rule);border:1px solid var(--rule);border-radius:5px;overflow:hidden}
.legend .cell{background:var(--panel);padding:.75rem .85rem}
.legend h4{margin:0 0 .45rem;font-size:.68rem;text-transform:uppercase;letter-spacing:.09em;
           color:var(--muted);font-weight:600}
.legend ul{list-style:none;margin:0;padding:0;font-size:.8rem}
.legend li{display:flex;align-items:center;gap:.5rem;padding:.12rem 0;color:var(--muted)}
.legend svg{flex:none}
.legend b{color:var(--ink);font-weight:600;font-family:var(--mono);font-size:.78rem}
</style></head><body><div class="wrap">

<header>
  <p class="sub"><a href="/">← {{.WitnessName}}</a></p>
  <h1>Ecosystem map</h1>
  <p class="sub">Every log this witness watches, one dot each, arranged by how long ago we last
  managed to cosign it. This is our own view and nothing else: it shows what <em>this</em> witness
  covers, not the wider witness ecosystem.</p>
</header>

{{if .StaleCount}}
<div class="banner bad">
  <strong>{{commai .StaleCount}} log(s) have not been refreshed in over two hours.</strong>
  They are the dots outside the dashed ring, and they are listed below the map. A stale cosignature
  is a failure of this witness — it does not mean the log is misbehaving, it means we have stopped
  being able to say anything current about it.
</div>
{{else}}
<div class="banner ok">
  Every log is inside the two-hour ring: the witness has a current cosignature for all
  {{commai .TotalLogs}} of them.
</div>
{{end}}

<h2>The map</h2>
<div class="map">
<svg viewBox="0 0 {{f .W}} {{f .H}}" role="img" aria-label="{{.AriaLabel}}">
  <g>
  {{range $i, $s := .Sectors}}<path class="wedge{{if odd $i}} alt{{end}}" d="{{$s.Wedge}}"/>{{end}}
  </g>

  <g>
  {{range .Rings}}<circle class="ring{{if .Dashed}} dash{{end}}" cx="{{f $.CX}}" cy="{{f $.CY}}" r="{{f .R}}"/>{{end}}
  </g>

  <g>
  {{range .Nodes}}<line class="spoke{{if .Forked}} fork{{else if .Stale}} stale{{end}}" x1="{{f $.CX}}" y1="{{f $.CY}}" x2="{{f .X}}" y2="{{f .Y}}"/>{{end}}
  </g>

  <g>
  {{range .Rings}}<text class="ringlab{{if .Dashed}} warn{{end}}" x="{{f $.CX}}" y="{{f .LabelY}}" dy="-4" text-anchor="middle">{{.Label}}{{if .Note}} · {{.Note}}{{end}}</text>{{end}}
  </g>

  <g>
  {{range .Sectors}}
    <path class="arc" d="{{.Arc}}"/>
    <text class="slabel" x="{{f .LabelX}}" y="{{f .LabelY}}" text-anchor="{{.LabelAnchor}}">{{.Label}}
      <tspan x="{{f .LabelX}}" dy="14">{{commai .Count}} log{{if ne .Count 1}}s{{end}}{{if .Stale}} · {{commai .Stale}} stale{{end}}{{if .Forked}} · {{commai .Forked}} forked{{end}}</tspan>
    </text>
  {{end}}
  </g>

  <g>
    <circle class="hub" cx="{{f .CX}}" cy="{{f .CY}}" r="27"/>
    <text class="hubsub" x="{{f .CX}}" y="{{f .CY}}" dy="-40" text-anchor="middle">THIS WITNESS</text>
    <text class="hublab" x="{{f .CX}}" y="{{f .CY}}" dy="48" text-anchor="middle">{{.WitnessName}}</text>
    <text class="hubsub" x="{{f .CX}}" y="{{f .CY}}" dy="66" text-anchor="middle">{{commai .TotalLogs}} LOGS · {{comma .TotalEntries}} ENTRIES</text>
  </g>

  <g>
  {{range .Nodes}}
    <a class="nd" href="{{.Href}}" tabindex="0">
      <title>{{.Title}}</title>
      {{if .Square}}<rect class="node{{if .Forked}} fork{{else if .Stale}} stale{{end}}" x="{{f .SX}}" y="{{f .SY}}" width="{{f .SD}}" height="{{f .SD}}" fill-opacity="{{f .FillOpacity}}"/>{{else}}<circle class="node{{if .Forked}} fork{{else if .Stale}} stale{{end}}" cx="{{f .X}}" cy="{{f .Y}}" r="{{f .R}}" fill-opacity="{{f .FillOpacity}}"/>{{end}}
      {{if .Ring}}<circle class="inner" cx="{{f .X}}" cy="{{f .Y}}" r="{{f .InnerR}}"/>{{end}}
      <text class="nlabel{{if .Forked}} fork{{else if .Stale}} stale{{end}}{{if not .Labelled}} hov{{end}}" x="{{f .LabelX}}" y="{{f .LabelY}}" text-anchor="{{.LabelAnchor}}">{{.Label}}{{if .Stale}} — {{.Age}}{{end}}</text>
    </a>
  {{end}}
  </g>
</svg>
</div>

<h2>How to read it</h2>
<div class="legend">
  <div class="cell">
    <h4>Distance = staleness</h4>
    <ul>
      <li>Rings mark 1h, 2h, 24h and 48h+ since we last cosigned.</li>
      <li>The dashed ring is the two-hour threshold that
          <code>kt_witness_log_staleness_seconds</code> alerts on.</li>
      <li>Anything outside it is drawn with a dashed edge and named, so the
          position is never the only clue.</li>
    </ul>
  </div>
  <div class="cell">
    <h4>Shape = tier</h4>
    <ul>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><circle class="node" cx="10" cy="10" r="7" fill-opacity=".32"/></svg><b>A</b> append-only</li>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><circle class="node" cx="10" cy="10" r="7" fill-opacity=".5"/><circle class="inner" cx="10" cy="10" r="3"/></svg><b>A+</b> whole published history</li>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><rect class="node" x="3.5" y="3.5" width="13" height="13" fill-opacity=".72"/></svg><b>B</b> construction audited</li>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><rect class="node" x="3.5" y="3.5" width="13" height="13" fill-opacity="1"/><circle class="inner" cx="10" cy="10" r="3"/></svg><b>B+</b> audited across all of it</li>
    </ul>
  </div>
  <div class="cell">
    <h4>Size &amp; wedge</h4>
    <ul>
      <li>A node's <em>area</em> grows with the log's size in entries, against a
          fixed 10<sup>9</sup>-entry scale — not rescaled to today's largest log,
          so two renders are comparable — above a floor that keeps the smallest
          logs clickable.{{if lt .ScalePct 100}} Every dot is drawn
          at {{.ScalePct}}% of that scale today, uniformly, because the fleet is
          too dense to draw them all full size without overlap.{{end}}</li>
      <li>Each wedge is one ecosystem. Angle within a wedge means nothing; it is
          spent entirely on keeping dots from overlapping.</li>
    </ul>
  </div>
  <div class="cell">
    <h4>Trouble</h4>
    <ul>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><circle class="node stale" cx="10" cy="10" r="7" fill-opacity=".32"/></svg><b>stale</b> dashed edge, outside the 2h ring</li>
      <li><svg width="20" height="20" viewBox="0 0 20 20"><circle class="node fork" cx="10" cy="10" r="7" fill-opacity=".32"/></svg><b>forked</b> heavy edge, evidence at <a href="/forks">/forks</a></li>
      <li>Hover or tab to any dot for its origin; click to open its page.</li>
    </ul>
  </div>
</div>
<p class="note">
  The one thing this map deliberately does not do is move a node's distance for aesthetic reasons.
  Distance is a measurement. Overlaps are resolved by sliding a dot sideways within its own wedge and
  never by pulling it in or out, so a dot that has drifted outward has drifted for exactly one reason.
</p>

<h2>Needs attention</h2>
{{if .Flagged}}
<div class="tablewrap"><table>
  <thead><tr><th>Origin</th><th>Ecosystem</th><th>Tier</th><th class="n">Size</th><th class="n">Last cosigned</th><th>State</th></tr></thead>
  <tbody>
  {{range .Flagged}}
  <tr>
    <td><a class="origin" href="{{.Href}}">{{.Origin}}</a></td>
    <td>{{.Group}}</td>
    <td>{{if .Tier}}<span class="pill ok">{{.Code}}</span>{{else}}<span class="pill warn">?</span>{{end}}</td>
    <td class="n">{{comma .Size}}</td>
    <td class="n">{{.Age}}</td>
    <td>
      {{if .Forked}}<span class="pill bad">FORKED</span>{{end}}
      {{if .Stale}}<span class="pill warn">STALE</span>{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table></div>
<p class="note">
  A stale row means the refresh loop has not produced a fresh cosignature for that origin — the
  source is failing, or the log has stopped serving a checkpoint we are willing to sign. Either way
  the cosignature we publish for it is old, and anyone relying on it should know that.
</p>
{{else}}
<p class="note">Nothing is stale and nothing is forked. Every dot on the map is inside the two-hour ring.</p>
{{end}}

<h2>Coverage by ecosystem</h2>
<div class="tablewrap"><table>
  <thead><tr><th>Ecosystem</th><th class="n">Logs</th><th class="n">Entries</th><th>Best tier</th><th class="n">Stale</th><th class="n">Forked</th></tr></thead>
  <tbody>
  {{range .Sectors}}
  <tr>
    <td>{{.Label}} <span class="root">{{.Short}}</span></td>
    <td class="n">{{commai .Count}}</td>
    <td class="n">{{comma .Entries}}</td>
    <td>{{if .TopTier}}<span class="pill ok">{{.TopTier}}</span>{{else}}—{{end}}</td>
    <td class="n">{{if .Stale}}<span class="pill warn">{{commai .Stale}}</span>{{else}}0{{end}}</td>
    <td class="n">{{if .Forked}}<span class="pill bad">{{commai .Forked}}</span>{{else}}0{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table></div>

{{if .RetiredCount}}
<p class="note">
  {{commai .RetiredCount}} origin(s) with stored history are no longer configured and are not drawn:
  they are not being witnessed, so putting them on a liveness map would make the map claim something
  false. They are not deleted either — that history is evidence. They are:
  {{range $i, $o := .Retired}}{{if $i}}, {{end}}<code>{{$o}}</code>{{end}}.
</p>
{{end}}

<footer>
  Generated {{.Generated}} · the same data, unrounded, is at <a href="/status.json">/status.json</a>;
  per-log detail is at <code>/log?origin=…</code>, reachable by clicking any dot.<br>
  Drawn entirely server-side as static SVG. No script runs on this page and it fetches nothing.
</footer>

</div></body></html>`
