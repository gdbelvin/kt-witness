package server

// The status page markup, kept in its own file so the Go logic beside it stays
// readable. Deliberately dependency-free: no CDN, no fonts, no JavaScript
// framework. A witness that cannot render its own status without fetching code
// from a third party is a witness with an extra thing to trust.

const uiHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.WitnessName}} — transparency log witness</title>
<style>` + uiCSS + `</style></head><body><div class="wrap">

<header>
  <h1>{{.WitnessName}}</h1>
  <p class="sub">An independently operated transparency&nbsp;log witness &amp; auditor · kt-witness {{.Version}}</p>
  <div class="klabel">Verifier key — this is what others pin</div>
  <div class="key">{{.VKey}}</div>
</header>

{{if .Forks}}
<div class="banner bad">
  <strong>{{commai .Forks}} fork(s) recorded.</strong> A log was caught contradicting itself and is
  permanently refused. Evidence at <a href="/forks">/forks</a>, including both conflicting views
  verbatim so the finding can be reproduced without trusting this witness.
</div>
{{else}}
<div class="banner ok">
  No contradictions observed. Every log below has been append-only for as long as this witness has
  been watching it. That is the whole claim — nothing here says a provider is trustworthy, only that
  it has not been caught showing two different histories.
</div>
{{end}}

<h2>At a glance</h2>
<div class="grid">
  <div class="cell"><span class="v">{{commai .TotalLogs}}</span><span class="k">logs witnessed</span></div>
  <div class="cell"><span class="v">{{comma .TotalEntries}}</span><span class="k">entries under attestation</span></div>
  <div class="cell"><span class="v">{{commai .TotalBackfilled}}</span><span class="k">epochs backfilled</span></div>
  <div class="cell"><span class="v">{{commai .TotalGaps}}</span><span class="k">gaps in published history</span></div>
  <div class="cell"><span class="v">{{commai .TotalVerified}}</span><span class="k">construction audits passed</span></div>
  <div class="cell"><span class="v">{{commai .Forks}}</span><span class="k">forks detected</span></div>
</div>
<p class="note">
  “Entries under attestation” is the sum of every witnessed log’s current size — the number of
  individual records this witness is currently vouching the append-only shape of.
</p>

<h2>Witnessed logs</h2>
<p class="note">
  Grouped by what each log makes transparent. A tier-A cosignature over a certificate log and a
  tier-A cosignature over a key directory are the same strength of claim about very different
  objects, and the tiers available differ by ecosystem — see below.
</p>

{{range .Groups}}
<h3 class="grouphead">{{.Label}}
  <span class="pill{{if .Forked}} bad{{else}} ok{{end}}">{{commai .Count}} log{{if ne .Count 1}}s{{end}}</span>
  {{if .TopTier}}<span class="pill ok">best: {{.TopTier}}{{if gt .AtTop 0}} ({{commai .AtTop}}){{end}}</span>{{end}}
  {{if .Forked}}<span class="pill bad">{{commai .Forked}} FORKED</span>{{end}}
  {{if .Stale}}<span class="pill warn">{{commai .Stale}} stale</span>{{end}}
</h3>
{{if .Blurb}}<p class="note">{{.Blurb}}</p>{{end}}
<div class="tablewrap">
<table>
  <thead><tr>
    <th>Origin</th><th>Tier</th><th class="n">Size</th><th>Root</th><th class="n">Last seen</th>
    <th class="n">Audited</th><th class="n">Sampled</th><th>Checkpoint</th>
  </tr></thead>
  <tbody>
  {{range .Logs}}
  <tr>
    <td>
      <a class="origin" href="/log?origin={{.Origin}}">{{.Origin}}</a>
      {{if .Forked}} <span class="pill bad">FORKED</span>{{end}}
      {{if .Stale}} <span class="pill warn">STALE</span>{{end}}
      {{if .History}}<div class="root">history {{comma .History.From}}–{{comma .History.To}} · {{commai .History.Epochs}} epochs · {{commai .History.Gaps}} gaps{{if .HistoryTotal}} · construction audited {{comma .HistoryAudited}}/{{comma .HistoryTotal}}{{if .Holes}} · <span class="pill warn">{{commai .Holes}} holes</span>{{end}}{{end}}</div>{{end}}
    </td>
    <td>{{if .Tier}}<span class="pill ok">{{.Tier}}</span>{{else}}<span class="pill warn">?</span>{{end}}</td>
    <td class="n">{{comma .Size}}</td>
    <td><span class="root">{{.RootShort}}…</span></td>
    <td class="n">{{.Age}}</td>
    <td class="n">{{if .Audited}}{{commai .Audited}}{{else}}—{{end}}</td>
    <td class="n">{{if .Audited}}{{commai .Sampled}}{{if .Unavailable}} <span class="pill warn">{{commai .Unavailable}} unavail</span>{{end}}{{else}}—{{end}}</td>
    <td><a href="{{.Path}}">fetch</a></td>
  </tr>
  {{end}}
  </tbody>
</table>
</div>
{{end}}

<p class="note">
  A <em>size</em> that never moves is normal for a quiet log; the cosignature is refreshed hourly so
  its timestamp stays a liveness signal. <strong>STALE</strong> means this witness has not refreshed
  that log in over two hours, which is a problem with the witness, not necessarily the log.
</p>

<h2>What the tiers mean</h2>
<div class="tablewrap"><table>
  <tbody>
  <tr><td><span class="pill ok">A</span></td><td><strong>Append-only.</strong> Every root this witness has seen is a prefix of the current one, proven by a consistency proof it verified itself. Catches equivocation and rollback. Says <em>nothing</em> about whether the log's contents are correct.</td></tr>
  <tr><td><span class="pill ok">A+</span></td><td>As A, and the root chain has been verified across the log's <em>entire published history</em>, not merely since this witness started watching.</td></tr>
  <tr><td><span class="pill ok">B+</span></td><td>Construction audited across the log's <em>entire published history</em>, not merely the epochs published since this witness started watching. Earned from the record, never configured: a log with 625,000 published epochs that we began witnessing yesterday has almost none of them checked, and a bare “B” would read as though it did.</td></tr>
  <tr><td><span class="pill ok">B</span></td><td><strong>Construction audit.</strong> As above, and the log's own proofs have been replayed to confirm the tree is correctly built. This is the only tier that can see an illegal mutation — a binding removed, or overwritten without its version advancing — because those leave the append-only chain perfectly intact.</td></tr>
  </tbody>
</table></div>
<p class="note">
  Conflating these is how a witness overpromises, so every assertion names its own tier and the
  distinction is enforced in the type system rather than by convention.
</p>

<h2>Construction auditing</h2>
<div class="grid">
  <div class="cell"><span class="v">{{commai .TotalAudits}}</span><span class="k">epochs considered</span></div>
  <div class="cell"><span class="v">{{commai .TotalSampled}}</span><span class="k">selected for audit</span></div>
  <div class="cell"><span class="v">{{pct .TotalSampled .TotalAudits}}</span><span class="k">effective sample rate</span></div>
  <div class="cell"><span class="v">{{commai .TotalVerified}}</span><span class="k">proofs replayed &amp; verified</span></div>
  <div class="cell"><span class="v">{{commai .TotalUnavailable}}</span><span class="k">could not be fetched</span></div>
</div>
<p class="note">
  Which epochs get audited is decided by the <a href="https://drand.love">drand</a> randomness beacon,
  drawn <em>after</em> each epoch is published — so an operator cannot know at publication time
  whether a given epoch will be checked. Declined epochs are recorded too, at
  <a href="/audits">/audits</a>, so coverage is auditable rather than asserted. An epoch that could
  not be fetched is recorded as unavailable, never as a failure: absence is not evidence.
</p>

<h2>Observed application heads</h2>
<p class="note">
  {{commai .Apps}} per-application heads read from the leaves of a log we witness, with
  {{commai .AppConflicts}} recorded contradiction(s). These are <strong>observations, not
  attestations</strong> — they are signed by keys the operator does not publish and are not bound to
  any root we verify, so they are never cosigned. See <a href="/applications">/applications</a>.
</p>

<h2>Endpoints</h2>
<div class="tablewrap"><table>
  <tbody>
  <tr><td><code>/</code></td><td>this page, or plain text to a non-browser client</td></tr>
  <tr><td><code>/status.json</code></td><td>everything on this page, as JSON</td></tr>
  <tr><td><code>/&lt;origin-hash&gt;/checkpoint</code></td><td>the cosigned checkpoint (C2SP <code>tlog-witness</code>)</td></tr>
  <tr><td><code>/.well-known/tlog-witness-key</code></td><td>the verifier key above</td></tr>
  <tr><td><code>/history</code></td><td>what backfill established about published history</td></tr>
  <tr><td><code>/audits</code></td><td>every sampling decision, with the beacon evidence to recompute it</td></tr>
  <tr><td><code>/applications</code></td><td>observed per-application heads (never cosigned)</td></tr>
  <tr><td><code>/gossip</code></td><td>what other witnesses say, and what comparison can and cannot prove</td></tr>
  <tr><td><code>/log?origin=…</code></td><td>per-log detail: coverage, traffic, audits, peer views</td></tr>
  <tr><td><code>/forks</code></td><td>misbehaviour evidence, verbatim</td></tr>
  </tbody>
</table></div>

<footer>
  Generated {{.Generated}} · oldest cosignature {{ts .OldestWitness}} · newest {{ts .NewestWitness}}<br>
  Largest log: <code>{{.LargestOrigin}}</code> at {{comma .LargestSize}} entries.<br>
  This witness attests only that the logs above have been append-only and, where a tier permits,
  correctly constructed. It makes no claim about any individual key, and it is not an endorsement of
  any operator.
</footer>

</div></body></html>`

// uiCSS is the single stylesheet every page shares.
//
// Extracted so the per-log and gossip pages look like the status page
// without carrying a copy of it. Still dependency-free: no CDN, no fonts,
// no framework. A witness that cannot render itself without fetching code
// from a third party is a witness with an extra thing to trust.
const uiCSS = `
:root{
  --bg:#0d1312; --panel:#141c1a; --sunken:#101817;
  --ink:#e7eeeb; --muted:#93a29e; --faint:#6f7d79;
  --rule:#243230; --rule2:#32433f;
  --ok:#4fbfa3; --warn:#d9a05b; --bad:#e2686b;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
@media (prefers-color-scheme:light){
  :root{--bg:#f6f8f7;--panel:#fff;--sunken:#eef2f0;--ink:#17211f;--muted:#5c6b67;
        --faint:#8a9995;--rule:#dce3e1;--rule2:#c3cecb;--ok:#0f6e5c;--warn:#8a5210;--bad:#a8322f;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
     font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:2rem 1.1rem 5rem}
a{color:var(--ok)}
h1{font-size:1.5rem;margin:0 0 .2rem;letter-spacing:-.01em}
h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.11em;color:var(--muted);
   margin:2.4rem 0 .7rem;font-weight:600}
.grouphead{font-size:1rem;font-weight:600;margin:1.8rem 0 .3rem;
   display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.grouphead .pill{font-weight:500;text-transform:none;letter-spacing:0}
.sub{color:var(--muted);margin:0 0 1.6rem;font-size:.92rem}
code,.m{font-family:var(--mono);font-variant-numeric:tabular-nums}

header{border-bottom:1px solid var(--rule);padding-bottom:1.2rem;margin-bottom:.4rem}
.key{display:inline-block;background:var(--sunken);border:1px solid var(--rule);
     padding:.42rem .6rem;border-radius:4px;font-family:var(--mono);font-size:.78rem;
     word-break:break-all;margin-top:.5rem}
.klabel{font-size:.7rem;color:var(--faint);text-transform:uppercase;letter-spacing:.09em}

.banner{border-radius:5px;padding:.85rem 1rem;margin:1.2rem 0;font-size:.92rem;
        border:1px solid var(--rule);background:var(--panel)}
.banner.bad{border-color:var(--bad);background:color-mix(in srgb,var(--bad) 12%,var(--panel))}
.banner.ok{border-left:3px solid var(--ok)}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;
      background:var(--rule);border:1px solid var(--rule);border-radius:5px;overflow:hidden}
.cell{background:var(--panel);padding:.85rem .9rem}
.cell .v{font-family:var(--mono);font-size:1.3rem;font-weight:600;color:var(--ok);
         display:block;line-height:1.15;letter-spacing:-.02em}
.cell .k{font-size:.72rem;color:var(--muted);margin-top:.28rem;display:block}

.tablewrap{overflow-x:auto;border:1px solid var(--rule);border-radius:5px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th{text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;
   color:var(--muted);font-weight:600;padding:.62rem .75rem;border-bottom:1px solid var(--rule2);
   white-space:nowrap}
td{padding:.58rem .75rem;border-bottom:1px solid var(--rule);vertical-align:top}
tr:last-child td{border-bottom:none}
td.n,th.n{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;white-space:nowrap}
.origin{font-family:var(--mono);font-size:.82rem;word-break:break-all}
.root{font-family:var(--mono);font-size:.74rem;color:var(--faint)}
.pill{display:inline-block;font-size:.66rem;padding:.1rem .38rem;border-radius:3px;
      font-family:var(--mono);letter-spacing:.03em}
.pill.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.pill.warn{background:color-mix(in srgb,var(--warn) 20%,transparent);color:var(--warn)}
.pill.bad{background:color-mix(in srgb,var(--bad) 20%,transparent);color:var(--bad)}
footer{margin-top:3rem;padding-top:1.1rem;border-top:1px solid var(--rule);
       color:var(--faint);font-size:.8rem}
.note{color:var(--muted);font-size:.85rem;margin:.5rem 0 0}
`
