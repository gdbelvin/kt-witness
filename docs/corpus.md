# The validation corpus

`cmd/kt-corpus` keeps a bounded set of real proofs on disk so the verification
code can be re-run over them, offline and deterministically, as often as we
like.

## What this is not

It is not evidence retention, and it does not change what
[cost.md](cost.md) says about production: **audit proofs are still verified and
discarded.** Retaining Meta's and WhatsApp's proofs at full rate would be ~136
TB/year and would buy nothing, because the evidence worth keeping — checkpoints,
audit decisions, fork evidence — is kilobytes.

This is a **regression corpus**, and it exists for two reasons:

- While the verification code is still being validated, every change needs to be
  re-checked against real proofs, not synthetic ones. Doing that by
  re-downloading is slow, non-deterministic, and hammers providers who owe us
  nothing.
- A provider can change or withdraw data we already checked. A proof we cannot
  re-fetch is a regression test we cannot run.

## The limits, which are not advisory

The witness host's volumes sit on an **over-provisioned thin LVM pool** — about
1.62 TiB of volumes against a 1.71 TB pool, with roughly 691 GB free. Filling a
thin pool does not merely fail one write; it can freeze every guest on the pool.
So:

| | Default | Behaviour |
|---|---|---|
| `-cap` | 200 GB **total**, across all ecosystems | checked before every download and again mid-stream; reaching it stops the run |
| `-floor` | 100 GB free | checked before every download; reaching it stops the run |

The cap is a total rather than per ecosystem on purpose: the pool does not care
which log filled it. `Content-Length` is treated as a claim, so the real
enforcement is a byte budget applied to the download as it streams — a response
that overruns is aborted and deleted, never stored and reconciled afterwards.

On a platform where free space cannot be measured, fetching refuses outright.
Guessing is not an option for a safety limit.

## Layout

The on-disk layout **is** the providers' URL layout, and that is the whole
design. Neither verifier can be handed a slice of bytes: the AKD verifier fetches
its own proof over HTTP, and Signal's response verification is an unexported step
inside `Source.Fetch`. Rather than fork either — at which point a passing replay
would prove nothing about production — replay starts a loopback HTTP server over
the corpus and points the real, unmodified code at it.

```
<corpus>/
  akd/<origin>/blobs/<epoch>/<prev_root>/<curr_root>   the proof, as CloudFront serves it
  akd/<origin>/manifests/<epoch>.json
  signal/<origin>/blobs/<tree_size>.json               the response envelope, verbatim
  signal/<origin>/manifests/<tree_size>.json
```

`<origin>` is the origin with `/` and `:` replaced by `_`, so it stays readable
in `ls`.

### The manifest

One JSON file per artifact, recording what it is and **what it must verify to**:

```json
{
  "kind": "akd",
  "origin": "meta.messenger.kt/v1",
  "seq": 625510,
  "blob": "akd/meta.messenger.kt_v1/blobs/625510/0112…/7362…",
  "bytes": 156263255,
  "sha256": "…",
  "prev_root": "0112…",
  "curr_root": "7362…",
  "captured_at": "2026-09-03T00:44:11Z"
}
```

The recorded expectation is the point. A replay that only asked "did this
parse?" would pass on a proof that verifies to a completely different root,
which is the one outcome we most need to catch. For AKD the expectation is the
epoch and the two roots, taken from the object key the log itself published — so
a replay checks the proof against the provider's own claim, never against
anything we derived. For Signal it is the verified tree size and root.

Nothing is admitted unverified. An artifact whose expectation was never
established would make every future replay a tautology.

## What is kept, and why that shape

**Diversity beats volume.** A contiguous run of epochs from one afternoon
exercises the verifier with nearly identical trees. So AKD epoch selection walks
back from the tip in doubling steps — tip, tip−1, tip−2, tip−4, tip−8 … — which
is deterministic, needs no state, and gives dense coverage of recent behaviour
with a long tail into history.

**Signal first, always.** A Signal response is ~490 KB and carries the VRF, the
prefix tree, a batch inclusion proof and a commitment opening — the newest and
least settled code in the project. Per byte it is worth orders of magnitude more
than an AKD proof, so it is captured before anything else and a run that hits a
limit still ends with the most valuable artifacts stored. Use `-signal-interval`
to space captures out; two taken a second apart describe the same tree.

**`-gc` erodes density, not coverage.** Each round drops the artifact from the
largest-consuming ecosystem whose sequence number sits closest to its surviving
neighbours — the most redundant one — and never an endpoint of an origin's
range, so the span the corpus covers does not shrink from the ends. If only
endpoints remain and the corpus is still over cap, it falls back to dropping the
largest artifact rather than failing to converge.

## Usage

```
kt-corpus -status
kt-corpus -fetch -akd-epochs 4 -signal-captures 8
kt-corpus -verify                              # -replay is an alias
kt-corpus -gc
```

`-verify` replays every artifact and prints pass/fail per artifact plus a total,
exiting non-zero if anything failed. It does not stop at the first failure: the
useful output of a regression run is *which* artifacts broke.

AKD capture and replay need no external binary. Replay used to take the path to
the Rust sidecar and did nothing without one, reporting AKD artifacts as skipped;
the verifier is in this process now, so replay always works — which is what a
corpus is for: an artifact that can only be checked when an external binary
happens to be present is one nobody checks.

## What a full run costs

Measured on this host, 2026-09-03, against the 374 Mbps connection in
[cost.md](cost.md):

| | Size | Verify |
|---|---|---|
| Meta epoch | ~150 MB (proofs have shrunk from the ~284 MB in cost.md) | ~8 s |
| WhatsApp epoch | ~30 MB | ~1.7 s |
| Signal response | ~450 KB | ~7 ms |

A 200 GB corpus split evenly between the two AKD logs — say 100 GB of Meta
(~680 epochs), 95 GB of WhatsApp (~3,200 epochs) and a few thousand Signal
responses — is roughly **75 minutes of downloading** at the measured link speed
and about **3 hours of CPU** to replay end to end. Both numbers are small enough
that a full replay is a thing you can run before every release, which is the
property that makes the corpus worth its disk.
