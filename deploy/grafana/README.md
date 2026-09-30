# Dashboard as code

`kt-witness.json` is the Grafana dashboard, exported so it is reproducible like
everything else here. Until now it existed only inside Grafana, which meant the
answer to "what is being measured, and is the measurement right" lived somewhere
that could not be reviewed or restored.

That mattered more than it sounds. Several faults this dashboard has carried were
in the *queries*, not the service: a rate taken from a gauge that stepped whenever
backfill widened its range, rate windows shorter than the scrape interval, and
every series in nine panels named `_value {_start=...}` because Flux's internal
columns were never dropped. None of those were visible from the metrics endpoint —
only from looking at the rendered page.

## Restoring or updating

```sh
# import (creates or overwrites the kt-witness dashboard)
jq '{dashboard: ., overwrite: true}' deploy/grafana/kt-witness.json \
  | curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
      -X POST https://grafana.${KT_TAILNET}.ts.net/api/dashboards/db \
      -H 'Content-Type: application/json' --data-binary @-

# export after editing in the UI, so the file stays the source of truth
curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
  https://grafana.${KT_TAILNET}.ts.net/api/dashboards/uid/kt-witness \
  | jq '.dashboard | del(.id, .version)' > deploy/grafana/kt-witness.json
```

`id` and `version` are stripped: Grafana assigns them per instance, and keeping
them makes the file look like it belongs to one particular server.

## The endpoints dashboard: is anyone relying on this?

`kt-witness-endpoints.json` (uid `kt-witness-endpoints`) answers a different
question from the performance dashboard: not "is the witness keeping up" but
"does anybody use what it signs". A witness can cosign every log on time and
still be worth nothing, if nobody fetches its cosignatures or pushes to it.

It reads the per-endpoint metrics from `internal/server/httpmetrics.go`:

| metric | labels | what it says |
|---|---|---|
| `kt_witness_http_requests_total` | route, method, code, via | every request |
| `kt_witness_http_request_duration_seconds_{bucket,sum,count}` | route, via, le | latency, as served by the witness |
| `kt_witness_http_distinct_clients` | route | distinct outside clients, trailing 24h |
| `kt_witness_checkpoint_fetches_total` | origin, via | whose cosignatures people read |
| `kt_witness_push_requests_total` | status | push outcomes (`internal/push`) |

**`via="tunnel"` is the whole trick.** Telegraf scrapes `/metrics` over the LAN
every 15s and Docker probes `/healthz`; counted together with real traffic, they
make an unused witness look busy. Requests that came through the Cloudflare
Tunnel carry `Cf-Ray`, and only those are outside parties. The reliance panels
filter to `via="tunnel"` and drop `/metrics` and `/healthz`. `route` is a fixed
set (unknown paths are `other`), so scanners cannot grow the series count.

Import it the same way as the main dashboard:

```sh
jq '{dashboard: ., overwrite: true}' deploy/grafana/kt-witness-endpoints.json \
  | curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
      -X POST https://grafana.${KT_TAILNET}.ts.net/api/dashboards/db \
      -H 'Content-Type: application/json' --data-binary @-
```

## Endpoint alerts

`alerts/kt-witness-endpoints.json` adds four rules to the existing `kt-witness`
group in the "Server Alerts" folder, so they route to the same contact point as
the rest:

| rule | fires when | severity |
|---|---|---|
| public endpoint down | the outside `/healthz` probe is not 200 for 5m, or has no result | critical |
| endpoints returning 5xx | > 5 server errors to outside clients in 10m | warning |
| endpoints slow (p95 > 2s) | checkpoint reads + pushes, for 15m | warning |
| pushes withheld | > 10 pushes answered 5xx in 15m | warning |

The existing "kt-witness: no metrics" already covers the process being down.
What it cannot see is the process up on the LAN while the tunnel, DNS or
Cloudflare is broken — to every client that is an outage. "public endpoint
down" covers that, and needs Telegraf to probe the public URL. Add to
`/home/<user>/monitoring/telegraf.conf` and restart Telegraf:

```toml
[[inputs.http_response]]
  urls = ["https://witness.gdbsecurity.com/healthz"]
  method = "GET"
  response_timeout = "10s"
  interval = "60s"
  follow_redirects = false
```

Until that probe exists the rule is in NoData, which is deliberately Alerting.

```sh
jq -c '.[]' deploy/grafana/alerts/kt-witness-endpoints.json | while read -r rule; do
  uid=$(jq -r .uid <<<"$rule")
  # PUT updates an existing rule; POST creates it the first time.
  curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" -H 'Content-Type: application/json' \
    -H 'X-Disable-Provenance: true' \
    -X PUT "https://grafana.${KT_TAILNET}.ts.net/api/v1/provisioning/alert-rules/$uid" \
    --data-binary "$rule" | grep -q '"uid"' \
  || curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" -H 'Content-Type: application/json' \
    -H 'X-Disable-Provenance: true' \
    -X POST "https://grafana.${KT_TAILNET}.ts.net/api/v1/provisioning/alert-rules" \
    --data-binary "$rule"
done
```

`X-Disable-Provenance` keeps the rules editable in the UI, like the existing
ones. The folder uid (`afvyr68dobym8a`) and datasource uid are this Grafana's;
rewrite both if the rules are ever moved.

Every query in both files was run against this InfluxDB (`influx query` inside
the `influxdb` container) before being committed, and the histogram-quantile
pipeline was checked against hand-computed values on synthetic buckets.

## The datasource

Panels reference the InfluxDB datasource by uid `efq9ck8t93vnke`. On a different
Grafana that uid will differ and every panel will render empty — which looks
exactly like a broken exporter. Rewrite the uid on import if the dashboard is
ever moved.

## Two conventions the queries follow

**Rates come from counters, never gauges.** A gauge that is recomputed rather
than accumulated can step for reasons unrelated to the work, and a derivative
turns that step into a spike that never happened.

**Rate windows are floored at four scrape intervals** — 1m against the current
15s. Below that the delta is taken across whatever gap happens to fall out, and
the graph reports sampling rather than behaviour. If the scrape interval in
`telegraf.conf` changes, change the floor with it.

## The Loki datasource

`loki-datasource.json` adds the log store from `deploy/loki` to this Grafana.
Grafana on docker-services now mounts `/home/<user>/grafana/provisioning`, but
only a dashboards provider and an empty `datasources/` are in it, and provisioned
objects become read-only in the UI. The HTTP API does the same job without a
restart, in the same style as the dashboard import above:

```sh
curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
  -X POST http://127.0.0.1:3001/api/datasources \
  -H 'Content-Type: application/json' \
  --data-binary @deploy/grafana/loki-datasource.json

# to update an existing one, PUT to /api/datasources/uid/loki instead
```

The uid is pinned to `loki` rather than left for Grafana to generate, so a panel
committed here referencing it works on import — the Influx datasource's
generated uid is exactly the trap described above.

The url is `http://loki:3100`, resolved over the `grafana_default` docker
network that the Loki stack joins from its own side. Loki itself is published
only on 127.0.0.1: it runs with `auth_enabled: false`, so anything that can
reach the port can read and delete logs.
