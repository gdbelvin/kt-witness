# Centralised logs

Diagnosing this witness used to mean `ssh docker-services` and
`docker compose logs`, and that had a failure mode worse than the
inconvenience: `docker compose up -d` recreates the container, and a recreated
container's json-file logs are deleted with the old container. The record of
what the witness was doing before a fix was destroyed *by* the fix. This
directory keeps the lines somewhere the container lifetime cannot reach.

- **Loki** stores and indexes the lines.
- **Alloy** reads them off the Docker socket and pushes them. It replaces
  Promtail, which Grafana deprecated and has since stopped supporting.
- Everything is local. This is an independently operated transparency witness;
  routing its operational record through someone else's log service would make
  a third party a silent participant in what it can say about itself.

The witness needs no code change and no restart for any of this: it keeps
writing to stdout under the json-file driver, and Alloy tails what Docker
already wrote.

## Deploying

Copy this directory to the host and bring it up **as its own project**:

```sh
rsync -a deploy/loki/ docker-services:~/kt-witness/deploy/loki/
ssh docker-services 'cd ~/kt-witness/deploy/loki && docker compose -f compose.yaml up -d'
```

The compose file sets `name: kt-witness-logs`. This is deliberately unlike
`deploy/cloudflared`, whose snippet is appended to the witness's own stack:
cloudflared belongs to the witness and should die with it, whereas logging must
*outlive* the witness container by definition. Keeping it a separate project
also means no compose command aimed at logging can recreate the witness — which
matters, because a rebuild of the Proton tree in flight is hours of work that a
restart throws away.

A config change to a bind-mounted file does not make compose recreate anything;
`docker compose -f compose.yaml restart loki` (or `alloy`) after editing.

## Retention and disk

30 days (`retention_period: 720h`), enforced by the compactor — retention
without `compactor.retention_enabled` silently keeps everything forever, and
Loki 3.x will not even start with retention on and no `delete_request_store`.

The budget: all containers on the box together write about **11 MB of log per
day** (measured with `docker logs --since 24h` across everything running;
kt-witness itself is ~1.2 MB/day, Grafana and Telegraf are louder). Thirty days
is ~330 MB raw and rather less compressed, against 570 GB free. So the 30 days
is chosen for how far back an investigation needs to see — a backfill that has
been wrong since last month is the kind of fault the old setup could not look
at — and not to fit a disk. Ingestion is capped at 16 MB/s so a service stuck
in a log loop cannot turn that budget into a full root filesystem, and both
containers carry `mem_limit` (2g Loki, 512m Alloy) because the box's memory is
an explicit budget the witness already claims 44g of.

## Labels, and the line we do not cross

Stream labels are the index. Loki's cost is roughly the number of distinct label
combinations, so a label whose values are unbounded degrades the whole store,
not just the queries that use it.

Labels: `container`, `compose_project`, `compose_service`, `image_title`,
`host`, and `level`. One stream per container, times four log levels.

Everything the witness logs as a field — `origin`, `epoch`, `strategy`,
`proton_replay`, `tier`, `msg`, `err` — is attached as **structured metadata**
(Loki 3.x, schema v13) instead. It is still queryable and still aggregatable:

```logql
{compose_project="kt-witness"} | origin=`whatsapp.kt/v2`
{compose_project="kt-witness", level="WARN"}
topk(6, sum by (origin) (count_over_time({compose_project="kt-witness"} | origin=~`.+` [4h])))
```

`epoch` is the hard no as a label: it increments forever, and one stream per
epoch per origin is an index that grows without bound until the store is
unusable. `origin` at 80-odd values would have been affordable, but it appears
on only some lines, and a label present on some lines of a stream and absent on
others splits that stream in two for no benefit. Structured metadata answers the
same questions without either problem.

## The logs are logfmt, not JSON

`slog`'s default `TextHandler` writes logfmt:

```
time=2026-09-06T18:44:35.931Z level=INFO msg="epoch verified" origin=whatsapp.kt/v2 epoch=1206745 ms=9131 strategy=history
```

so `config.alloy` uses `stage.logfmt`. This is worth stating because the failure
is invisible: `stage.json` against these lines extracts nothing, every field
comes back absent, and "the witness never logged an origin" looks identical to
"the parser was pointed at the wrong format". If the witness ever switches to
`slog.NewJSONHandler`, that stage has to change with it.

`stage.timestamp` takes the witness's own `time=` field rather than the moment
Alloy read the line, so a replayed backlog lands where it belongs on the time
axis instead of arriving as a spike at restart.

## Verifying

```sh
curl -s http://127.0.0.1:3100/ready
curl -s http://127.0.0.1:3100/loki/api/v1/labels
curl -sG http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={compose_project="kt-witness"}' \
  --data-urlencode "start=$(( $(date +%s) - 900 ))000000000" \
  --data-urlencode "end=$(date +%s)000000000" --data-urlencode 'limit=5'
```

Rejected pushes appear in **Alloy's** log as `status=400`, not in Loki's — check
`docker logs alloy` first when lines are missing.

Alloy's pipeline UI is on 127.0.0.1:12345 and Loki's API on 127.0.0.1:3100, both
loopback-only: Loki runs with `auth_enabled: false`, so exposing either on the
LAN would be unauthenticated read and delete over the log store. Reach them by
`ssh -L` or from the host. Grafana reaches Loki over the `grafana_default`
docker network instead — see `../grafana/README.md`.

## First start is noisy

On first start Alloy ships each container's *retained* json-file history, and
containers that have been up for months hand Loki interleaved lines from weeks
ago. Loki rejects an entry more than `ingester.max_chunk_age` behind the newest
entry in its stream, so `docker logs loki` shows a burst of "entry too far
behind" for the long-lived unrelated services. It settles within a minute and no
kt-witness line was affected. `max_chunk_age` is raised to 24h so a restart's
worth of replay is accepted without holding chunks open for a week.

That replay also means day one does not look like the 11 MB/day budget above:
the store landed at ~100 MB of chunks immediately, because it swallowed every
container's entire retained json-file history at once. That is a one-off, and it
ages out under the 30-day retention like anything else. The write-ahead log is
the other thing not to panic at — it reached 900 MB during the replay and fell
to about 1 MB at the first checkpoint five minutes later. WAL segments are only
truncated once a checkpoint has been written, so a fresh install or a restart
looks alarming on `du` for exactly one checkpoint interval.
