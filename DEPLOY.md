# Running kt-witness

## Build

```sh
docker build --platform linux/amd64 -t kt-witness .
```

Two builders: Go for the witness core, Rust for AKD proof verification (tier B).
The Rust stage builds `facebook/akd` and is slow the first time; dependency
caching means source-only changes rebuild in seconds.

## First run

State lives in a volume at `/data` and holds two things that must survive
restarts:

- **`witness.key`** — the signing key. It *is* our published identity. Losing it
  means coming back as a different party, and anyone who listed the old key in
  their trust policy stops seeing us. Back it up before anything else.
- **`witness.db`** — every head we have attested. Losing it means starting again
  from trust-on-first-use, discarding the history we have witnessed.

```sh
mkdir -p data && cp witness.example.json data/witness.json
$EDITOR data/witness.json          # set "name" to your witness identity

docker compose run --rm kt-witness -config /data/witness.json -genkey
# prints the verifier key to publish — record it
```

`name` appears in every cosignature and cannot change without changing identity,
so choose it as carefully as a hostname.

## Backfill

Trust-on-first-use leaves everything before we showed up unattested. `-backfill`
verifies published history first:

- **Meta** — the whole root chain, from listing metadata only. No proof blobs are
  downloaded, so ~625 requests cover ~625,000 epochs.
- **Proton** — its full retained history (~500 epochs, ~90 days). About a minute.
- **Signal** — not possible. Anchoring would need a historical signed root, and
  the API only offers proofs from a size we already witnessed.

```sh
docker compose run --rm kt-witness -config /data/witness.json -backfill
```

Results are recorded and served at `/` and `/history`. A backfill that hits a
contradiction poisons the log exactly as a live one would; a *gap* is recorded
but not treated as evidence, since retention limits produce gaps too.

## Overnight run

```sh
docker compose up -d
docker compose logs -f
```

Watch for:

| Log line | Meaning |
|---|---|
| `cosigned` | Normal. A new head was verified and signed. |
| `withheld cosignature` | We could not verify something. Expected occasionally; a *persistent* one for the same origin deserves a look. |
| `FORK DETECTED` | Conclusive misbehaviour. The log is permanently refused, and evidence is at `/forks`. |
| `signal auditor` | Per-auditor tree sizes and lag. |
| `epoch verified` | A tier-B construction audit passed. |

## Resource notes, measured not guessed

- **Tier B bandwidth** scales with `audit.sample_rate`. Meta publishes an epoch
  every 120 s at ~284 MB, so rate 0.1 is ~20 GB/day and rate 1.0 is ~204 GB/day.
  Check this against any ISP cap before raising it.
- **Memory**: one AKD verification peaks around 3.7 GB RSS. `mem_limit: 6g`
  leaves headroom without letting the host swap.
- **CPU**: ~24 s wall for one epoch, but ~144 s of CPU — it parallelises about
  6x. On a single core it would take ~144 s and miss the 120 s epoch cadence, so
  tier B needs real cores.
- **Disk**: `/tmp` needs ~1 GB for one proof in flight. The compose file mounts
  a tmpfs; on a memory-tight host use a disk-backed mount instead.

## Operational bar

This is what the witness ecosystem expects, and what the config targets:

- Poll at least once a minute; refuse to cosign a stale view.
- Publish the verifier key so consumers can list it in their trust policy.
- Hold the signing key in hardware (TKey or Armored-Witness class). The file
  key here is the development path — acceptable for a first unattended run,
  not for a witness others rely on.
- Uptime is the product.
