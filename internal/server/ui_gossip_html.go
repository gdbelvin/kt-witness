package server

const gossipPageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gossip — {{.WitnessName}}</title>
<style>` + uiCSS + `
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1px;
      background:var(--rule);border:1px solid var(--rule);border-radius:6px;overflow:hidden}
.cell{background:var(--panel);padding:.7rem .85rem}
.cell .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.09em;color:var(--faint)}
.cell .v{font-family:var(--mono);font-size:1.15rem;margin-top:.15rem}
.cell.bad .v{color:var(--bad)} .cell.warn .v{color:var(--warn)} .cell.ok .v{color:var(--ok)}
.warnbox{border-left:3px solid var(--warn);background:var(--panel);padding:.9rem 1.1rem;
         border-radius:0 5px 5px 0;margin:1.2rem 0}
.warnbox strong{color:var(--ink)}
figure{margin:1.4rem 0}
figcaption{color:var(--muted);font-size:.86rem;margin-top:.5rem;max-width:66ch}
</style></head><body><div class="wrap">

<header>
  <p class="sub"><a href="/">← {{.WitnessName}}</a></p>
  <h1>Gossip</h1>
  <p class="sub">What other witnesses say, and why comparing views is the only thing
  that detects a fork.</p>
</header>

<h2>The state of it</h2>
<div class="grid">
  <div class="cell"><div class="k">logs witnessed</div><div class="v">{{.TotalLogs}}</div></div>
  <div class="cell"><div class="k">also seen by a peer</div><div class="v">{{.SharedLogs}}</div></div>
  <div class="cell ok"><div class="k">comparable &amp; agreed</div><div class="v">{{.Agreed}}/{{.Comparable}}</div></div>
  <div class="cell warn"><div class="k">size only, cannot compare</div><div class="v">{{.SizeOnly}}</div></div>
</div>

{{if .AnyDivergent}}
<div class="warnbox">
  <strong>A peer publishes a different root at a size we also hold.</strong>
  That is a lead, not a finding: peer status pages are unsigned, so this cannot
  support an accusation on its own. It is the signal to go and obtain the signed
  artefact.
</div>
{{end}}

<h2>Why a witness alone cannot catch a fork</h2>
<figure>
<svg viewBox="0 0 700 210" role="img" width="700" style="max-width:100%;height:auto"
     aria-label="A log serving two histories attaches a different set of cosignatures to each, so signatures read off a single fetched checkpoint always agree by construction.">
  <defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6"
    orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker></defs>
  <g fill="none" stroke="currentColor" stroke-width="1.4">
    <rect x="16" y="82" width="112" height="46" rx="6"/>
    <rect x="286" y="18" width="150" height="64" rx="6"/>
    <rect x="286" y="130" width="150" height="64" rx="6"/>
    <rect x="566" y="82" width="112" height="46" rx="6"/>
  </g>
  <g font-family="ui-monospace,monospace" font-size="12" fill="currentColor">
    <text x="72" y="102" text-anchor="middle">log</text>
    <text x="72" y="118" text-anchor="middle" font-size="10" opacity=".65">equivocating</text>
    <text x="361" y="42" text-anchor="middle">history A</text>
    <text x="361" y="62" text-anchor="middle" font-size="10" opacity=".65">+ cosigs over A</text>
    <text x="361" y="154" text-anchor="middle">history B</text>
    <text x="361" y="174" text-anchor="middle" font-size="10" opacity=".65">+ cosigs over B</text>
    <text x="622" y="102" text-anchor="middle">us</text>
    <text x="622" y="118" text-anchor="middle" font-size="10" opacity=".65">sees one</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.3" marker-end="url(#a)" opacity=".8">
    <path d="M128,98 C205,98 210,50 282,50"/>
    <path d="M128,114 C205,114 210,162 282,162"/>
    <path d="M436,50 C505,50 510,98 562,98"/>
  </g>
  <path d="M436,162 C480,162 500,172 528,172" fill="none" stroke="currentColor"
        stroke-width="1.3" stroke-dasharray="4 4" opacity=".4"/>
  <text x="470" y="190" font-family="system-ui,sans-serif" font-size="11"
        fill="currentColor" opacity=".65">never fetched</text>
</svg>
<figcaption>Every signature on a checkpoint we fetched sits over the same body, so they
agree by construction. A log serving two histories simply attaches a different cosignature
set to each. Reading cosignatures off our own fetch is corroboration; it is not detection.
Only a view obtained independently can differ.</figcaption>
</figure>

<h2>What this witness can and cannot do</h2>
<table>
  <thead><tr><th>attack</th><th>caught by us today</th></tr></thead>
  <tbody>
    <tr><td>rollback — an earlier root served as current</td><td><span style="color:var(--ok)">yes</span>, we retain history</td></tr>
    <tr><td>split view shown to different clients</td><td><span style="color:var(--warn)">only with signed peer views</span></td></tr>
    <tr><td>targeted fork aimed at one victim</td><td><span style="color:var(--warn)">only with signed peer views</span></td></tr>
    <tr><td>log and its auditors colluding</td><td><span style="color:var(--warn)">only with signed peer views</span></td></tr>
    <tr><td>entry rewritten at a published position</td><td><span style="color:var(--ok)">yes</span>, where we open entries</td></tr>
    <tr><td>a key substituted for a user who never checks</td><td><span style="color:var(--bad)">no — nobody but that user can</span></td></tr>
  </tbody>
</table>

<div class="warnbox">
  <strong>The missing piece is upstream, and it is small.</strong>
  A peer already holds the artefact that would settle this: the log's own signature
  over a body it obtained independently. If a witness served that, a body naming a
  different root at a size we also hold signed would be the log convicting itself —
  no witness would need to be trusted, and any third party could reproduce it.
  Today no witness implementation serves it; retrieval paths return 404, and the
  status pages that do exist are unsigned. So this page reports leads, never findings.
</div>

{{if .Seen}}
<h2>Seen cosigning, key not held</h2>
<p class="sub">
  Names on checkpoint signature lines this witness cannot verify. They are <strong>not</strong>
  corroboration — anyone can append a line claiming any name, and an unverified signature says nothing
  about who produced it. They are a list of keys worth going to find, because the witness protocol
  distributes keys out of band and a peer stays invisible until somebody fetches one by hand.
</p>
<div class="tablewrap">
<table>
  <thead><tr><th>Name</th><th class="n">Logs seen on</th><th>First seen</th></tr></thead>
  <tbody>
  {{range .Seen}}
    <tr>
      <td class="origin">{{.Name}}</td>
      <td class="n"><span class="pill warn">{{len .Origins}}</span></td>
      <td class="m">{{.First.Format "2006-01-02"}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
<p class="note">
  Until a key is added to <code>peer_witnesses</code>, these witnesses cosign the same checkpoints as
  this one and neither can contradict the other. That is not a gap in the ecosystem; it is a gap in
  this configuration, and it is the kind that reads from the inside exactly like an empty ecosystem.
</p>
{{end}}

{{if .Anonymous}}
<h2>Cosigning, and unidentifiable</h2>
<p class="sub">
  Cosignatures whose log publishes only a key hash, not a name. These are not keys we have failed to
  fetch — there is nowhere to fetch them from. Nobody outside the log operator can say who they are.
</p>
<div class="tablewrap">
<table>
  <thead><tr><th>Key hash</th><th class="n">Logs seen on</th><th>First seen</th></tr></thead>
  <tbody>
  {{range .Anonymous}}
    <tr>
      <td class="origin">{{.Name}}</td>
      <td class="n"><span class="pill warn">{{len .Origins}}</span></td>
      <td class="m">{{.First.Format "2006-01-02"}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>
<p class="note">
  This is worth separating from the list above, because the two are different problems wearing the
  same clothes. A named witness we cannot verify is an errand: go and find the key. An anonymous one
  cannot be resolved by any amount of diligence, and it means a log's witness set is unenumerable
  from outside — which looks like diversity while offering no way to check whether these signatures
  come from many independent parties or from one party holding many keys.
</p>
{{end}}

<h2>Peers polled</h2>
{{if .Peers}}
<table>
  <thead><tr><th>witness</th><th>logs in common</th><th>publishes roots</th><th>comparable</th><th>agreed</th></tr></thead>
  <tbody>
  {{range .Peers}}
    <tr>
      <td><code>{{.Witness}}</code></td>
      <td class="m">{{.Origins}}</td>
      <td class="m">{{.WithRoots}}</td>
      <td class="m">{{.Comparable}}</td>
      <td class="m">{{.Agreed}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
<p class="sub">A peer with roots can be contradicted; one publishing only sizes cannot.
Two witnesses agreeing on a size, with no roots to compare, have said nothing to
each other.</p>
{{else}}
<p class="sub">No peer views recorded yet.</p>
{{end}}

</div></body></html>
`
