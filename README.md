# kt-witness

A multi-log Key Transparency witness and auditor.

There is currently one publicly-operating third-party KT auditor of consequence
(Cloudflare's, for Meta), and the mature witness ecosystem — C2SP `tlog-witness`,
Sunlight, sigsum, transparency-dev — cannot consume CONIKS/AKD-family KT epochs
at all. `kt-witness` is a protocol-agnostic verify → cosign → publish core with
per-ecosystem adapters, intended to be *operated*, not just published.

## Assurance tiers

Every published assertion names its tier. Conflating them is how a witness
overpromises, so the distinction is enforced in the type system
(`source.Tier`).

| Tier | Attests | Cost |
|---|---|---|
| **A** — checkpoint witness | The sequence of signed roots is append-only (split-view detection) | Negligible |
| **A+** — root-chain continuity | Additionally, continuity across the log's *entire* published history, where layout permits it from metadata alone | Negligible |
| **B** — construction audit | Additionally, the tree is correctly built, by replaying the log's own proofs | Large (see below) |
| **S** — signed head | Weaker than A: heads are authentic and equivocation at a given size is detectable, but append-only between observations is *not* proven because the deployment exposes no usable consistency proof. Apple sits here | Negligible |

## Status

- **Tier A, C2SP logs — working.** Witnesses any `tlog-checkpoint` +
  `tlog-tiles` log. Verified end to end against `thelemail.com/keys`: our
  cosignature is accepted alongside `witness.navigli.sunlight.geomys.org` and
  `witness.stagemole.eu`, and validates under an independent verifier.
- **Meta (AKD), tier A+ — working.** Witnesses `messenger.key-transparency.v1`
  live by walking Meta's published root chain. Verified against the real log at
  epoch 624,730.
- **Meta tier B** — feasibility established by spike (see below); not yet wired.
- **Proton, tier A+ — working.** Walks the epoch chain and verifies the WebPKI
  certificate that commits to each chain hash. No account, no coordination.
- **Signal, tier A — working.** Signal's KT client endpoints are unauthenticated
  *by design* (sending credentials is an error). Signal never serves its tree
  root, so we **derive** it: each auditor's signed root plus its consistency
  proof yields the service root, all three must agree, and Signal's own
  signature must verify over the result. Append-only across observations then
  follows from the `lastTreeHeadSize` consistency proof. Verified live at tree
  size 852,163,309.
- **Apple, tier S — working.** Apple's promised public auditing was never
  announced, but the infrastructure is live: `at_researcher/log_head` serves
  ECDSA-signed tree heads to anyone. This witnesses the shared **Top-Level Tree**
  that iMessage commits into — not iMessage's own tree, which is not publicly
  listed. Append-only is unproven because `consistency_proof` rejects
  size-to-size ranges.
- **Google KT** — archived since 2024-10-11, no live deployment.
- **IETF keytrans** — the draft deliberately specifies no transport, and no
  public deployment speaks it, so there is nothing to be conformant to on the
  wire yet. Deliberately skipped; see NOTES.md.

## How consistency is verified

We never accept a proof the log hands us. For `tlog-tiles` logs we fetch tiles
for the *new* tree, let `tlog.TileHashReader` bind every tile to the new signed
root, then compute the consistency proof locally from our previously witnessed
size. A log cannot fabricate a proof it does not have the tile data to back.

Failures are separated into two kinds, which is the distinction that matters
operationally:

- **Fork** (`source.ForkError`) — positive evidence of append-only violation.
  Never retried, persisted as evidence with both conflicting views verbatim,
  published at `/forks` so a disclosure is reproducible by third parties.
- **Unproven** — we could not obtain or check a proof. Not evidence of
  misbehaviour, but equally not grounds to sign. The cosignature is withheld and
  the round retried.

Withholding *is* the enforcement mechanism. There is no alerting protocol.

## Backfill

Trust-on-first-use leaves everything before we showed up unattested. `-backfill`
verifies published history first, and against production it covers a great deal:

| Log | Range verified | Cost |
|---|---|---|
| Meta Messenger | **535,390 epochs** (89,395..624,784), zero gaps | ~625 requests, under 2 min |
| Proton | 501 epochs — its entire ~90-day retention | ~500 requests, ~64 s |
| Signal | not possible | — |

Meta's is affordable because the bulk object listing turns ~625,000 requests into
~625, and no proof blob is downloaded at all — the root chain is entirely in the
key names. Signal cannot be backfilled: anchoring would need a historical signed
root, and the API only offers proofs from a size we already witnessed.

A contradiction found in history poisons the log exactly as a live one does. A
*gap* does not: retention limits and partial writes both produce holes, and
linkage cannot be checked across one. Results are served at `/history`.

## Deployment

See [DEPLOY.md](DEPLOY.md). Two builders (Go core, Rust sidecar) into a
distroless image; state lives in a `/data` volume that must persist, because the
signing key is the published identity.

## Usage

```sh
go build ./cmd/kt-witness
cp witness.example.json witness.json   # edit: set "name" to your witness identity
./kt-witness -genkey                   # prints the verifier key to publish
./kt-witness
```

Endpoints:

| Path | Purpose |
|---|---|
| `GET /<origin-hash>/checkpoint` | Latest cosigned checkpoint (C2SP `tlog-witness` monitoring endpoint) |
| `GET /.well-known/tlog-witness-key` | Our published cosignature verifier key |
| `GET /forks` | Recorded misbehaviour evidence |
| `GET /history` | Verified published history, from a backfill pass |
| `GET /audits?origin=` | Tier-B sampling decisions and results |
| `GET /` | Human-readable status |

## What the Meta adapter attests — and what it does not

Meta's proof objects are keyed `<epoch>/<prev_root>/<curr_root>`, so the root
chain is self-linking in listing metadata. Walking it proves the published
history is continuous — no rollback, no gap, no fork — without downloading a
single 284 MB blob. That is tier A+, and no other public verifier publishes it.

It does **not** verify a signature by Meta. Meta's epoch signing key is not
published anywhere we could find; the signatures on Cloudflare's plexi
`/reports` are reporters' own, and that endpoint takes open submissions (it
currently carries digests like `deadbeef…` and `cafebabe…`). So a cosignature
here attests *"kt-witness observed this root chain and it was continuous"*, not
*"Meta signed this"*. That distinction must survive into anything published.

As partial compensation, every fetch cross-checks Cloudflare's independently
published anchor root against Meta's own store, and refuses to sign if the two
disagree. Two unrelated parties having to agree is stronger than either alone.

Because the head is *derived* rather than signed, the core treats it with less
evidential weight (`Source.DerivedHead`): a head that appears to regress, or to
change at the same epoch, is withheld-and-retried rather than recorded as a
fork. A transient bad read looks identical to a rollback, and an accusation is
permanent and public. Real equivocation is still caught conclusively — as a
broken hash link during the chain walk, which no read error can fabricate.

Catch-up steps forward at most `max_epochs_per_round` (default 200) per round,
so recovering from downtime converges instead of repeatedly attempting one
enormous walk that cannot finish before the head goes stale.

Three practical notes discovered against the live service:

- CloudFront serves **stale negative listings** (`x-cache: Hit`, `age: 180`,
  zero keys for an epoch that had since been published), and a
  `Cache-Control: no-cache` request header does not bypass it. Every listing is
  therefore cache-busted with a nonce. Left unhandled, this produces a false
  fork accusation.

- plexi's `root` field lags far behind (epoch 89,527 while `last_verified_epoch`
  was 624,707), so it is a historical anchor, not the tip. The tip is found in
  Meta's store by exponential probe plus binary search — O(log n) requests.
- Object keys sort lexicographically, not numerically (`"99999" > "624700"`), so
  the chain is walked by hash linkage rather than by listing order.

`whatsapp.key-transparency.v1` is **not** a config copy-paste away: it currently
reports status `Disabled` with inconsistent epochs. Check `v2` before adding it.

## How Signal's service root is recovered

Signal never serves the service tree's root; libsignal reconstructs it from the
combined-tree search proof, which is a large piece of machinery. There is a much
shorter path, and it is the core of this adapter.

Because Signal deploys in third-party-auditing mode, each response carries one
`FullAuditorTreeHead` per auditor: the auditor's Ed25519-signed root at its own
(smaller) tree size, plus a consistency proof up to the service's size. A
consistency proof does not merely *check* a root — run forwards, it *determines*
one. So every auditor independently yields the service root, and three things
must line up:

1. each auditor's signature over its own root verifies;
2. all auditors derive the **same** service root, from different sizes with
   different proofs;
3. Signal's own signature verifies over the derived root.

Against production this holds: three auditors at different sizes with 21- and
23-hash proofs all derive the identical root, and all three of Signal's
signatures verify over it. That agreement is also the test — if the log-tree
reimplementation were wrong, none of it would line up.

Signal's log tree is reimplemented in `logtree.go`: left-balanced with RFC 9420
node numbering (not RFC 6962), nodes hashed as `H(marshal(l) || marshal(r))` over
a 33-byte encoding whose leading byte distinguishes leaves from interior nodes.
It is tested against a tree built independently from leaves, for every `(m, n)`
pair up to 40.

What is still **not** verified is the prefix tree — that individual
identifier-to-key bindings are correctly placed. That needs VRF evaluation and
the search-proof machinery, and is the Signal analogue of tier B.

## Operating notes

The ecosystem's established bar, which this project targets:

- Poll each log at least once per minute; refuse to cosign a stale view
  (`max_sign_delay`).
- Persist atomically with a compare-and-set on the previous head — the
  `tlog-witness` spec calls out a race where two conflicting checkpoints of the
  same size are both accepted. See `store.CompareAndSet`.
- Hold the Ed25519 signing key in hardware (TKey or Armored-Witness class). The
  file-based key here is the development path only.
- Publish the verifier key so consumers can list it in their trust policy.
  Uptime is the product.

## Measured facts about the Meta target

Established by direct measurement, not inference:

- Audit proofs are **publicly downloadable without credentials or operator
  coordination**, keyed `<epoch>/<prev_root>/<curr_root>`.
- New epoch every **120 s**; **~284 MB** per proof; download at ~58 MB/s (~5 s).
- Verification with `akd` 0.13 (`WhatsAppV1Configuration`) takes **~24 s**
  wall-clock (~144 s CPU, parallelising ~6x) and **~3.7 GB** peak RSS for one
  epoch. Against a 120 s budget that is ~5x headroom — **but it depends on
  multicore**; single-threaded it would miss the budget.
- Sustained real-time tier B is therefore ~**204 GB/day** of ingest for one
  namespace.

### Interop gotcha: the epoch is off by one

Meta names objects by the **target** epoch; `akd`'s own `generate_audit_blobs`
names by the **source** epoch. An auditor must pass `epochs = vec![key_epoch - 1]`
to `audit_verify`, or the end-hash check fails while the start hash still
passes. The failure is a useful negative control: a one-epoch shift breaks
verification, which confirms the check is genuinely cryptographic.

## Tier B: construction auditing

Enabled by setting `audit.sidecar_path`. AKD proof verification lives in Rust
(`rust/kt-akd-verify`) because that is where `facebook/akd` is; the Go side
drives it as a long-running subprocess over one-JSON-per-line.

The sidecar's `kind` field is load-bearing and mirrors the same standard used
everywhere else here: only `kind: "verify"` — the proof provably fails to
reconstruct the published root — is treated as misbehaviour and poisons the log.
`fetch` and `decode` mean *we* could not check, and are retried. That failure is
arithmetic, not observation, which is why it can be conclusive where a missing
object cannot.

Auditing runs on its own goroutine and deliberately does **not** gate cosigning:
one verification takes ~24 s, and the witness must stay responsive enough to
detect equivocation.

Results are published at `GET /audits?origin=<origin>`, including the epochs we
*declined* — a coverage claim nobody can recompute is not a claim.

## Probabilistic auditing

Full construction audit of every epoch is expensive, and a Merkle root cannot be
recomputed from a subset of an epoch's changed nodes — so sampling must happen at
epoch granularity, not within an epoch.

That is sufficient, because a KT attack only accomplishes something if the forged
binding **persists** long enough to be served to a victim. Detection over `k`
consecutive bad epochs is `1-(1-p)^k`; at `p = 0.1` an attack persisting one hour
is caught with ~96% probability, at ~20 GB/day.

The sample must be **unpredictable to the log operator**, or they simply cheat on
the epochs we skip. Selection is therefore driven by drand's quicknet beacon,
drawn *after* each epoch has been published and observed:

```
selected  <=>  first 8 bytes of SHA-256(randomness || ":" || big-endian uint64 epoch)
               interpreted big-endian  <  rate * 2^64
```

Every decision is recorded with the beacon round, its signature, and the derived
randomness, so a third party can refetch the round, verify it against quicknet's
public key, and recompute exactly which epochs we should have audited — then
check `/audits` to confirm we did. Sampling that nobody can check is not a
security property.

A sampled assertion must say so: *chain continuity verified for 100% of epochs;
construction verified for a disclosed p fraction.* The `/audits` response states
this in its `note` field rather than leaving it to be inferred.

An epoch that is selected but repeatedly unfetchable is recorded as
`kind: "unavailable"` after a bounded number of attempts and skipped, rather than
retried forever. Retrying without bound looks safer but is not: progress would
never advance, and one dead proof blob would silently stall tier B for the whole
log. A declared skip is auditable; a stalled auditor is not.

### Known gap: the canonical beacon round is not yet pinned

Selection currently uses whichever quicknet round was latest when the decision
was made, and records it. A third party can verify that round's signature and
recompute the selection — but nothing yet specifies *which* round is the
legitimate one for a given epoch. Since rounds are 3 s apart, a dishonest witness
could in principle redraw until an epoch it wished to skip deselects (~10 draws
at p=0.1).

One fix is to pin the canonical round as a pure function of the epoch. A likely
better one is **gossip between witnesses**: independent witnesses draw
independent rounds, so a witness that consistently declines what others verify is
detectable statistically without anyone agreeing on a canonical round — and union
coverage composes (ten witnesses at p=0.1 give ~65% per epoch, not 10%). See
[NOTES.md](NOTES.md).

Until then, treat published coverage as an honest-witness claim rather than a
cryptographically enforced one.
