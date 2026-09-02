# Deploying witness.kt.gdbsecurity.com

Prepared, not deployed. Run these on the server. It is amd64, so the Rust stage
builds natively and quickly.

## 1. Build

```sh
git clone <this repo> kt-witness && cd kt-witness
docker build -t kt-witness:latest .
```

Confirm the sidecar actually runs — a wrong-architecture or missing-library build
still starts the witness and fails only tier B, quietly:

```sh
echo '{"log_directory":"http://127.0.0.1:1","epoch":1,"prev_root":"aa","curr_root":"bb"}' \
  | docker run --rm -i --entrypoint /usr/local/bin/kt-akd-verify kt-witness:latest
```

Expect JSON with `"kind":"fetch"`. Anything else — especially a library error —
means tier B would be silently dead.

## 2. State directory

```sh
mkdir -p data && cp deploy/witness.json data/witness.json
sudo chown -R 65532:65532 data      # the image runs as distroless nonroot
```

## 3. Generate the signing key, on this machine

The key is the witness's published identity. Generating it here means the
private key never leaves the server.

```sh
docker run --rm -v "$PWD/data:/data" kt-witness:latest \
  -config /data/witness.json -genkey
```

It prints the verifier key — **record it**, that is what others pin:

```
witness.kt.gdbsecurity.com+<keyid>+<base64>
```

Then back up `data/witness.key`. Losing it means coming back as a different
witness, and anyone who pinned the old key stops seeing you. Losing the database
only costs history.

## 4. Backfill

Verifies published history before witnessing starts, so everything before today
is attested rather than trusted-on-first-use. Takes about three minutes.

```sh
docker run --rm -v "$PWD/data:/data" kt-witness:latest \
  -config /data/witness.json -backfill -once
```

Expect roughly:

```
backfill complete origin=meta.messenger.kt/v1 from=89395 to=624784 epochs=535390 gaps=0
backfill complete origin=proton.me/kt/v1     from=6206  to=6707   epochs=501    gaps=0
```

Signal and Apple cannot be backfilled: both need a historical signed root to
anchor from, and neither serves proofs from a size we have not already witnessed.

## 5. Run

```sh
docker compose up -d
docker compose logs -f
```

## What healthy looks like

Five logs cosigned on the first round:

| Origin | Tier |
|---|---|
| `thelemail.com/keys` | A |
| `meta.messenger.kt/v1` | A+ |
| `proton.me/kt/v1` | A+ |
| `signal.org/kt` | A |
| `apple.com/kt/top-level-tree` | A |

Then mostly quiet: Signal advances every round, Meta every ~2 min, Apple
steadily, Proton every ~4 h, thelemail rarely (it re-cosigns hourly to keep its
timestamp a liveness signal).

| Log line | Meaning |
|---|---|
| `cosigned` | Normal. |
| `withheld cosignature` | Could not verify something. Occasional is fine; persistent for one origin deserves a look. |
| `FORK DETECTED` | Conclusive misbehaviour. That log is permanently refused; evidence at `/forks`. |
| `epoch verified` | A tier-B construction audit passed (~277 MB, ~30 s native). |
| `signal auditor` | Per-auditor sizes and lag. |
| `CONTRADICTION IN OBSERVED APPLICATION HEAD` | An Apple per-application head (possibly iMessage) contradicted itself. Not signature-verified, so it is for a human to judge, not grounds to refuse. |

## Endpoints

| Path | |
|---|---|
| `/` | Human-readable status |
| `/<origin-hash>/checkpoint` | Cosigned checkpoint (C2SP `tlog-witness`) |
| `/.well-known/tlog-witness-key` | The verifier key to publish |
| `/history` | Backfilled history |
| `/audits?origin=` | Tier-B sampling decisions |
| `/applications` | Apple per-application heads — observations, never cosigned |
| `/forks` | Misbehaviour evidence |

## Expected load

- **Bandwidth**: ~20 GB/day, essentially all tier B at `sample_rate` 0.1. Raising
  it to 1.0 means ~204 GB/day — check any cap first.
- **Memory**: one AKD verification peaks ~3.7 GB RSS; the compose limit is 6 GB.
- **CPU**: ~24 s wall per epoch but ~144 s of CPU — it parallelises ~6x, so tier B
  needs real cores. On one core it would miss the 120 s epoch cadence.
- **Disk**: the database grows ~300 KB/day. `/tmp` needs ~1 GB for one proof in
  flight (compose mounts a tmpfs).

## Before anyone relies on this

The signing key is a file on disk. That is fine for a first run, and not fine
once others list the key in a trust policy — the ecosystem norm is hardware
(TKey or Armored-Witness class). Publishing the verifier key is what invites
people to depend on it, so do that step deliberately.
