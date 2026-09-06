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
      -X POST https://grafana.example-tailnet.ts.net/api/dashboards/db \
      -H 'Content-Type: application/json' --data-binary @-

# export after editing in the UI, so the file stays the source of truth
curl -sS -u "$GRAFANA_USER:$GRAFANA_PASS" \
  https://grafana.example-tailnet.ts.net/api/dashboards/uid/kt-witness \
  | jq '.dashboard | del(.id, .version)' > deploy/grafana/kt-witness.json
```

`id` and `version` are stripped: Grafana assigns them per instance, and keeping
them makes the file look like it belongs to one particular server.

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
Grafana on docker-services has no provisioning directory mounted — its compose
file mounts only `./data` — so a file under `provisioning/datasources` would
require restarting Grafana with a new mount. The HTTP API does the same job
without a restart, in the same style as the dashboard import above:

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
