# Deploying witness.kt.gdbsecurity.com

Run these on the server. It is amd64, so the Rust stage builds natively and
quickly — a cross-build from an arm64 laptop works but goes through QEMU and is
much slower.

## 1. Get the source onto the server

There is no git remote configured, so clone over SSH from the machine holding
the repository:

```sh
# on the server
git clone ssh://<you>@<laptop>/Users/<user>/dev/kt-witness kt-witness && cd kt-witness
```

or push from the laptop into a bare repo on the server:

```sh
# on the server
git init --bare ~/kt-witness.git
# on the laptop
git remote add server ssh://<server>/~/kt-witness.git && git push server master
# on the server
git clone ~/kt-witness.git kt-witness && cd kt-witness
```

## 2. Build

```sh
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

## 3. State directory

```sh
mkdir -p data
sudo chown -R 65532:65532 data      # the image runs as distroless nonroot
```


## Publishing the witness over HTTPS

The identity `witness.kt.gdbsecurity.com` is inside every cosignature already
issued, so serving it publicly invites reliance. That is a decision, not a
deployment step — and the false fork finding against the Go checksum database
argues for more operating record first.

The site's address is residential and moves, which rules out a plain A record:
one that goes stale leaves the witness looking, from outside, exactly like a
witness that has stopped working. Tailscale Funnel cannot help either — it
presents a certificate valid only for `*.ts.net`, so a CNAME from a custom name
fails the TLS handshake.

So: **Cloudflare Tunnel**. It dials outward, survives an address change, needs no
inbound ports, and keeps the home address out of public DNS.

### What only you can do

1. **Delegate only `kt.gdbsecurity.com` to Cloudflare.** The parent zone does
   not move: the website, email and everything else stay on Squarespace DNS.

   Cloudflare subdomain zones work on the Free plan, and Squarespace supports NS
   records, so the delegated subtree can be exactly the namespace the witness
   already lives in and nothing else.

   - In Cloudflare, add **`kt.gdbsecurity.com`** as a new zone — not
     `gdbsecurity.com`. It is issued its own nameservers, which are *not* the
     parent zone's.
   - At Squarespace → DNS Settings → Custom Records, add **NS** records for host
     `kt` pointing at them.

   Squarespace issues **four** nameserver values and every one needs its own
   record. A delegation with one missing looks complete in their interface and
   does not resolve, which is a tedious thing to debug from the symptom.

   Confirm the delegation before going further, since everything after this
   depends on it:

   ```sh
   dig +short NS kt.gdbsecurity.com          # expect the Cloudflare nameservers
   ```

2. **Authenticate and create the tunnel** — interactive, once:

   ```sh
   # on docker-services
   cloudflared tunnel login                    # opens a browser
   cloudflared tunnel create kt-witness        # prints the tunnel UUID
   cloudflared tunnel route dns kt-witness witness.kt.gdbsecurity.com
   ```

3. **Put the pieces where the config expects them**:

   ```sh
   mkdir -p ~/kt-witness/secrets/cloudflared
   cp ~/.cloudflared/<UUID>.json ~/kt-witness/secrets/cloudflared/
   sed -i "s/TUNNEL_UUID/<UUID>/g" ~/kt-witness/deploy/cloudflared/config.yml
   ```

   The credentials file authenticates the tunnel to Cloudflare. `.gitignore`
   covers it; keep it that way.

### Then

Append `deploy/cloudflared/compose.snippet.yaml` to `compose.yaml` and:

```sh
docker compose up -d cloudflared
docker compose logs -f cloudflared      # expect "Registered tunnel connection"
```

Verify from **outside** the tailnet and the LAN, because a check from inside can
succeed for the wrong reason:

```sh
curl -sS -o /dev/null -w '%{http_code} verify=%{ssl_verify_result}\n' \
  https://witness.kt.gdbsecurity.com/
curl -sS https://witness.kt.gdbsecurity.com/ | head -5
```

`verify=0` means the chain verified. Then fetch a cosigned checkpoint the way a
consumer would, since that is the endpoint that matters rather than the pages:

```sh
curl -sS https://witness.kt.gdbsecurity.com/<origin-hash>/checkpoint
```

### The alternative

`deploy/caddy/witness.caddy` serves the same site from the Caddy already running
on this host, with a Let's Encrypt certificate via HTTP-01 and nobody in the
delivery path. It needs a stable address and inbound 80/443, so it is the right
answer only if those change. HTTP-01 rather than DNS-01 because Squarespace has
no DNS API, and a certificate that renews only when someone remembers is a
certificate that expires.

### If it goes wrong

A tunnel that outlives the witness serves 502s under the witness's own name,
which is worse than being unreachable — hence `depends_on` in the snippet.
`docker compose stop cloudflared` withdraws it immediately; DNS keeps pointing
at a tunnel that is simply not running, and nothing is served rather than
something wrong being served.



## Shipping the source without git

The server is not a git checkout, so the source arrives by tar over ssh. There
is no rsync on it.

```sh
# from the laptop
tar czf - --exclude='.git' --exclude='data' --exclude='*.key' . \
  | ssh <server> 'cd ~/kt-witness && tar xzf -'

# ALWAYS copy the config explicitly afterwards
scp deploy/witness.json <server>:~/kt-witness/deploy/witness.json
```

**Why the config gets its own line.** An earlier version of this used
`--exclude='./witness.json'` to skip the gitignored root config. bsdtar matched
that pattern against `deploy/witness.json` as well, so the push shipped every
new adapter with the *previous* config. The container would have started clean,
reported healthy, logged no errors, and cosigned none of the new logs — because
it would not have known they existed.

That is the same failure as the `.gitignore` incident below, wearing a different
hat, and it is the second time this specific file has been silently dropped by a
pattern meant for another one. Treat any exclude pattern containing
`witness.json` as a bug.

**Verify the transfer by asking the server what it now believes**, never by
trusting that the copy succeeded:

```sh
ssh <server> 'cd ~/kt-witness && python3 -c "
import json; print(len(json.load(open(\"deploy/witness.json\"))[\"logs\"]))"'
```

That number must match the laptop. A config that is merely *present* proves
nothing; a stale one is indistinguishable from a correct one from the outside.

**Do not copy the config into `data/`.** compose mounts `deploy/witness.json`
read-only at `/config/witness.json`, so the file the container reads is the file
in the repository. An earlier version of this runbook said to copy it, and the
copy drifted: the repository grew to 77 logs while the container kept reading a
stale 10-log copy and reported no errors, because it never knew the other logs
existed.

## 4. Generate the signing key, on this machine

The key is the witness's published identity. Generating it here means the
private key never leaves the server.

```sh
docker run --rm -v "$PWD/data:/data" -v "$PWD/deploy/witness.json:/config/witness.json:ro" \
  kt-witness:latest -config /config/witness.json -genkey
```

It prints the verifier key — **record it**, that is what others pin:

```
witness.kt.gdbsecurity.com+<keyid>+<base64>
```

Then back up `data/witness.key`. Losing it means coming back as a different
witness, and anyone who pinned the old key stops seeing you. Losing the database
only costs history.

## 5. Backfill

Verifies published history before witnessing starts, so everything before today
is attested rather than trusted-on-first-use. Takes about three minutes.

```sh
docker run --rm -v "$PWD/data:/data" -v "$PWD/deploy/witness.json:/config/witness.json:ro" \
  kt-witness:latest -config /config/witness.json -backfill -once
```

Expect roughly:

```
backfill complete origin=meta.messenger.kt/v1 from=89395 to=624784 epochs=535390 gaps=0
backfill complete origin=proton.me/kt/v1     from=6206  to=6707   epochs=501    gaps=0
```

Signal and Apple cannot be backfilled: both need a historical signed root to
anchor from, and neither serves proofs from a size we have not already witnessed.

## 6. Run

```sh
# 8080 is often taken. Pick a free host port; the container port is unchanged.
echo "KT_WITNESS_PORT=8088" > .env
docker compose up -d
docker compose logs -f
```

## What healthy looks like

**Ten logs** cosigned on the first round:

| Origin | Tier | Advances |
|---|---|---|
| `thelemail.com/keys` | B | rarely |
| `meta.messenger.kt/v1` | A+ | every ~2 min |
| `whatsapp.kt/v2` | A+ | every ~30 s |
| `proton.me/kt/v1` | A+ | every ~4 h |
| `signal.org/kt` | A | every round |
| `apple.com/kt/top-level-tree` | A | steadily |
| `apple.com/at/pcc` | A | slowly |
| `parcelyard2026h2.prod.certificate.transparency.goog` | A | constantly |
| `log.twig.ct.letsencrypt.org/2026h1` | A | constantly |
| `tuscolo2026h1.sunlight.geomys.org` | A | constantly |

Unchanged logs are re-cosigned hourly, so their timestamp stays a liveness
signal.

| Log line | Meaning |
|---|---|
| `cosigned` | Normal. |
| `withheld cosignature` | Could not verify something. Occasional is fine; persistent for one origin deserves a look. |
| `FORK DETECTED` | Conclusive misbehaviour. That log is permanently refused; evidence at `/forks`. |
| `epoch verified` | A tier-B construction audit passed (~277 MB, ~30 s native). |
| `signal auditor` | Per-auditor sizes and lag. |
| `signal search proof verified` | The `distinguished` key was opened and checked end to end — VRF, prefix tree, inclusion, commitment. |
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

Measured; the full model is in [docs/cost.md](../docs/cost.md).

- **Bandwidth**: **~40 GB/day** (~1.2 TB/month), essentially all tier B at
  `sample_rate` 0.1 — ~20 GB Meta, ~17 GB WhatsApp. Raising the rate to 1.0
  means ~372 GB/day; check any cap first. Almost all of it is *ingress*.
- **CPU**: ~0.27 cores sustained, but bursty. One Meta epoch is ~24 s wall and
  ~144 s CPU (it parallelises ~6×), so tier B needs real cores; on a single core
  it would miss the 120 s cadence.
- **Memory**: one AKD verification peaks ~3.7 GB RSS; the compose limit is 6 GB.
- **Disk**: **~45 GB**, of which ~40 GB is Proton's retained tree once the
  incremental audit is wired (not yet — see TODO). Without it, a few GB. There
  is no tile cache, so the 80 CT logs need no disk. Audit proofs are verified
  and discarded, never retained. `/tmp` needs ~1 GB for one proof in flight
  (compose mounts a tmpfs).

## Before anyone relies on this

The signing key is a file on disk. That is fine for a first run, and not fine
once others list the key in a trust policy — the ecosystem norm is hardware
(TKey or Armored-Witness class). Publishing the verifier key is what invites
people to depend on it, so do that step deliberately.
