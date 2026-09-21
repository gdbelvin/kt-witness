# Running kt-witness

> For the prepared `witness.gdbsecurity.com` deployment, follow
> [deploy/RUNBOOK.md](deploy/RUNBOOK.md) — it has the exact commands in order.
> This file is the general reference.

## Build

```sh
docker build --platform linux/amd64 -t kt-witness .
```

One builder: Go, cross-compiled to the run platform, into
`gcr.io/distroless/static-debian12`. It was two — a Rust stage building
`facebook/akd` for tier B proof verification, slow the first time, on a
`distroless/cc` base because that binary needed `libgcc_s.so.1` — until
`internal/akdtree` moved the arithmetic into the witness binary. Nothing in the
image is dynamically linked now.

## First run

State lives in a volume at `/data` and holds two things that must survive
restarts:

- **`witness.key`** — the signing key. It *is* our published identity. Losing it
  means coming back as a different party, and anyone who listed the old key in
  their trust policy stops seeing us. Back it up before anything else.
- **`witness.db`** — every head we have attested. Losing it means starting again
  from trust-on-first-use, discarding the history we have witnessed.

The container runs as uid 65532 (distroless nonroot), so the state directory
must be writable by it.

```sh
mkdir -p data && cp witness.example.json data/witness.json
sudo chown -R 65532:65532 data
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
- **Memory**: one AKD verification peaked around 3.7 GB RSS in the Rust sidecar,
  which is what made the pool size a memory question; the in-process verifier
  uses a fraction of that. The compose file's `mem_limit` is the host's budget,
  not the verifier's.
- **CPU**: ~24 s wall and ~144 s of CPU for one Meta epoch, measured against the
  Rust verifier — the Go one costs about an eighth. Either way it parallelises,
  and on a single core it would miss the 120 s epoch cadence, so tier B needs
  real cores.
- **Disk**: no writable `/tmp`. A verification holds the proof in memory and
  writes nothing on the way; the only proofs that touch disk are the ones
  `audit.prefetch_dir` deliberately caches under `/data` ahead of time, bounded
  by `prefetch_bytes`.

## Building on arm64

Go cross-compiles, so building on an arm64 Mac for `linux/amd64` is native and
quick. This used to be the slow step: the Rust stage had to target the *run*
platform, so the same build ran the akd tree under emulation for tens of
minutes. There is still no apt-get in the image, and that is still deliberate —
apt's GPG verification fails under emulation.

To check a built image really targets amd64:

```sh
docker run --rm --platform linux/amd64 --entrypoint /usr/local/bin/kt-witness \
  kt-witness:latest -version
```

The failure this used to guard against is gone. A wrong-architecture sidecar let
the witness start normally with tiers A/A+ working and only tier B dead, quietly;
verification is in the witness binary now, so an image that runs at all has it.
The check is still worth a second rather than an assumption.

## Operational bar

This is what the witness ecosystem expects, and what the config targets:

- Poll at least once a minute; refuse to cosign a stale view.
- Publish the verifier key so consumers can list it in their trust policy.
- Hold the signing key in hardware (TKey or Armored-Witness class). The file
  key here is the development path — acceptable for a first unattended run,
  not for a witness others rely on.
- Uptime is the product.
