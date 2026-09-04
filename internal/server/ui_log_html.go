package server

const logPageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Log.Origin}} — {{.WitnessName}}</title>
<style>` + uiCSS + `
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1px;
      background:var(--rule);border:1px solid var(--rule);border-radius:6px;overflow:hidden}
.cell{background:var(--panel);padding:.7rem .85rem}
.cell .k{font-size:.7rem;text-transform:uppercase;letter-spacing:.09em;color:var(--faint)}
.cell .v{font-family:var(--mono);font-size:1.05rem;margin-top:.15rem;word-break:break-all}
.bar{height:6px;background:var(--sunken);border-radius:3px;overflow:hidden;margin-top:.4rem}
.bar i{display:block;height:100%;background:var(--ok)}
.note{white-space:pre-wrap;font-family:var(--mono);font-size:.72rem;background:var(--sunken);
      border:1px solid var(--rule);border-radius:5px;padding:.7rem;overflow-x:auto}
.warnbox{border-left:3px solid var(--warn);background:var(--panel);padding:.8rem 1rem;
         border-radius:0 5px 5px 0;margin:1rem 0}
</style></head><body><div class="wrap">

<header>
  <p class="sub"><a href="/">← {{.WitnessName}}</a></p>
  <h1>{{.Log.Origin}}</h1>
  <p class="sub">{{.Log.Kind}} · {{.Log.Tier}}</p>
</header>

{{if .Retracted}}
<div class="warnbox">
  <strong>A fork finding against this log was withdrawn</strong> on {{since .Retracted.RetractedAt}}.
  <p class="sub" style="margin:.4rem 0 0">{{.Retracted.Reason}}</p>
  <p class="sub" style="margin:.4rem 0 0">The original evidence is kept at
  <a href="/forks">/forks</a> so the reversal can be checked as readily as the claim.</p>
</div>
{{end}}

<h2>Current head</h2>
<div class="grid">
  <div class="cell"><div class="k">size</div><div class="v">{{.Log.Size}}</div></div>
  <div class="cell"><div class="k">witnessed</div><div class="v">{{.Log.Age}} ago</div></div>
  <div class="cell"><div class="k">root</div><div class="v">{{.Log.RootShort}}</div></div>
  <div class="cell"><div class="k">assurance</div><div class="v">{{.Log.Tier}}</div></div>
</div>
{{if .CheckpointURL}}
<p class="sub" style="margin-top:.6rem">Our cosigned checkpoint:
<a href="{{.CheckpointURL}}"><code>{{.CheckpointURL}}</code></a></p>
{{end}}

{{if .Log.History}}
<h2>Published history</h2>
<div class="grid">
  <div class="cell"><div class="k">range</div><div class="v">{{.Log.History.From}}..{{.Log.History.To}}</div></div>
  <div class="cell"><div class="k">entries</div><div class="v">{{.Log.History.Epochs}}</div></div>
  <div class="cell"><div class="k">gaps</div><div class="v">{{.Log.History.Gaps}}</div></div>
  <div class="cell">
    <div class="k">construction audited</div>
    <div class="v">{{pct .CoveragePct}}%</div>
    <div class="bar"><i style="width:{{pct .CoveragePct}}%"></i></div>
  </div>
</div>
<p class="sub" style="margin-top:.6rem">{{.Coverage}}. Coverage counts settled decisions
inside the published range; work above that range is real but uncounted until the next
backfill widens it.</p>
{{end}}

{{if .HaveBytes}}
<h2>Traffic</h2>
<div class="grid">
  <div class="cell"><div class="k">downloaded</div><div class="v">{{.BytesIn}}</div></div>
  <div class="cell"><div class="k">uploaded</div><div class="v">{{.BytesOut}}</div></div>
  <div class="cell"><div class="k">requests</div><div class="v">{{.Requests}}</div></div>
</div>
<p class="sub" style="margin-top:.6rem">Counted as bytes actually read, not from
<code>Content-Length</code>. Construction-audit proofs dominate wherever they exist.</p>
{{end}}

{{if .HaveAudits}}
<h2>Construction audits</h2>
<div class="grid">
  <div class="cell"><div class="k">verified</div><div class="v">{{.VerifiedCount}}</div></div>
  <div class="cell"><div class="k">failed</div><div class="v">{{.FailedCount}}</div></div>
  <div class="cell"><div class="k">lowest seen</div><div class="v">{{.FirstAudited}}</div></div>
  <div class="cell"><div class="k">highest seen</div><div class="v">{{.LastAudited}}</div></div>
</div>
<p class="sub" style="margin-top:.6rem">Strategies in the last 40 decisions:
{{range $k, $n := .StrategyMix}}<code>{{$k}}</code>&nbsp;{{$n}}&nbsp; {{end}}
<br><code>live</code> follows the tip, <code>backlog</code> samples with log-decay,
<code>history</code> sweeps backwards, <code>rebuild</code> reconstructs the whole tree,
<code>entries</code> checks each published entry against the signed tree.</p>
<table>
  <thead><tr><th>epoch</th><th>strategy</th><th>rate</th><th>result</th><th>decided</th></tr></thead>
  <tbody>
  {{range .AuditRows}}
    <tr>
      <td class="m">{{.Epoch}}</td>
      <td><code>{{.Strategy}}</code></td>
      <td class="m">{{.Rate}}</td>
      <td>{{if .Verified}}<span style="color:var(--ok)">verified</span>{{else}}<span style="color:var(--bad)">failed</span>{{end}}</td>
      <td class="m">{{.When}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<h2>What other witnesses say</h2>
{{if .HavePeers}}
<table>
  <thead><tr><th>witness</th><th>size</th><th>root</th><th>comparable</th></tr></thead>
  <tbody>
  {{range .Peers}}
    <tr>
      <td><code>{{.Witness}}</code></td>
      <td class="m">{{.Size}}</td>
      <td class="m">{{if .Root}}{{.Root}}{{else}}<span style="color:var(--faint)">not published</span>{{end}}</td>
      <td>{{if .Comparable}}{{if .Agrees}}<span style="color:var(--ok)">agrees</span>{{else}}yes{{end}}{{else}}<span style="color:var(--warn)">size only</span>{{end}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
<p class="sub">A witness publishing a size but no root has said nothing that can be
contradicted. See <a href="/gossip">the gossip page</a> for why that matters.</p>
{{else}}
<p class="sub">No other witness we poll publishes a view of this log. That is the normal
case: see <a href="/gossip">/gossip</a>.</p>
{{end}}

<h2>Our cosigned checkpoint, verbatim</h2>
<div class="note">{{.SignedNote}}</div>

</div></body></html>
`
