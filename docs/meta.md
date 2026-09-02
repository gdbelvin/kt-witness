# Meta / Messenger

`meta.messenger.kt/v1` — **tier A+**, and **tier B** by beacon-driven sampling.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to Meta.

## What is peculiar

Meta is the deployment that can be audited **without the operator's
cooperation** — or the existing auditor's. Its AKD audit proofs sit in an
openly listable object store, which converts the highest-value target here from
"tier A only" into a genuine independent construction audit.

It is also the only **derived-head** source: nothing Meta serves to us carries
Meta's signature, so the head is something we assemble by reading storage.
That single fact shapes the whole adapter.

## The self-linking listing

Audit proof objects are keyed:

```
<epoch>/<prev_root>/<curr_root>
```

The root chain is therefore **in the listing metadata itself**. Continuity —
`curr[n] == prev[n+1]` — can be verified across the log's entire published
history by paging XML, without downloading a single 284 MB proof.

That is tier A+, and it is the best value-per-byte assertion anywhere in this
project: **624,000+ epochs** for the cost of a few hundred listing requests.
Backfill established 535,390 epochs (89,395 → 624,784) with zero gaps in under
two minutes.

**Object keys sort lexicographically, not numerically** (`"99999" > "624700"`),
so the chain must be walked by hash linkage and never by listing order.

## Finding the tip

Cloudflare's `plexi` service publishes a namespace list with a `root` field.
That field lags badly — epoch 89,527 while `last_verified_epoch` was 624,707. It
is a **historical anchor to cross-check, not the tip**.

The tip is found in Meta's own store by exponential probe plus binary search:
O(log n) requests.

`plexi`'s `/reports` endpoint is a mixed feed containing obvious placeholder
digests (`deadbeef…`, `cafebabe…`, `aaaa…`) alongside real ones, which strongly
suggests it is an *open submission* endpoint for third-party observations. It
must never be treated as authoritative: verify signatures, never trust listed
digests.

## The CDN trap

This is the most important operational lesson in the project, and it nearly
produced a false, permanent, public accusation that Meta had forked.

**CloudFront serves stale *negative* listings.** A listing request for an epoch
that had since been published returned zero keys with `x-cache: Hit`,
`age: 180`. A `Cache-Control: no-cache` request header does **not** bypass it.

A cached "absent" in the middle of a chain walk looks exactly like a hole in
Meta's history.

Two fixes, in order of importance:

1. **Absence was reclassified as retryable.** Only a *positive* contradiction —
   broken linkage, two objects for one epoch, the tip disagreeing with the walk
   — can now be a fork. This is where the project's governing rule came from.
2. A per-request cache-busting nonce, so a fresh listing is genuinely fresh.

The same bug then turned out to exist one layer up, in the generic core: a size
regression was still treated as conclusive, and Meta's size comes from a chain
of *absence* observations. That produced `DerivedHead()`, which is now part of
the `Source` interface and applies to any future adapter with the same shape.

## Derived heads

`DerivedHead()` is `true` for Meta. A head that appears to have gone backwards,
or a same-size-different-root contradiction, only **withholds** — because the
disagreement is between two of *our* readings, not two of Meta's signatures.

If a Meta signing key ever becomes pinnable, this flips and the stronger
treatment returns. Until then, the honest description of the assertion is "the
chain of roots I derived from Meta's published proof objects is continuous",
which is what the tier says.

## Tier B: the AKD sidecar

Proof verification is `facebook/akd` 0.13 (`WhatsAppV1Configuration`,
`public_auditing` feature), which is Rust. The witness core is Go, so tier B
runs as a long-lived subprocess with a narrow JSON contract.

Results are classified `fetch` / `decode` / `verify`. **Only `verify` can
accuse** — a failed download or an unparseable blob is absence, not evidence.

### The off-by-one

> Meta names objects by the **target** epoch. `akd`'s `generate_audit_blobs`
> names by the **source** epoch.

`audit_verify` must be passed `epochs = vec![key_epoch - 1]`. Get it wrong and
the *start* hash check passes while the *end* hash check fails — which doubles
as a negative control confirming the verification is genuinely cryptographic.

### Cost

| | |
|---|---|
| new epoch | exactly every 120 s |
| proof blob | ~284 MB |
| decode + verify | ~24 s wall, ~144 s CPU (parallelises ~6×) |
| peak RSS | ~3.7 GB |
| sustained ingest for continuous audit | ~204 GB/day, ~6 TB/month |
| full replay from genesis | ~175 TB — off the table |

Continuous full audit is affordable on real infrastructure and not on a hobby
VPS. Sampling at 0.1 gives ~20 GB/day. Feasibility depends on multicore: single
threaded, verification misses the 120-second budget.

Sampling is beacon-driven so Meta cannot predict which epochs will be checked;
see [design.md](design.md). Note that verification must start from a **pinned
recent epoch**, never genesis.

## Cross-checking against an independent auditor

Cloudflare's plexi is currently the only publicly operating third-party KT
auditor of consequence — and its output is itself a single point of trust.
Agreement between an independently derived root and plexi's published root for
the same epoch is the strongest available correctness signal for this adapter,
and disagreement would be interesting to everyone.

## Unresolved

`/namespaces/<ns>/audits` returns 405 to GET. The path to Cloudflare's *signed*
auditor output is not established, so cross-checking currently uses the
namespace `root` field rather than a signed statement.

## WhatsApp

`whatsapp.key-transparency.v1` reports status `Disabled` with inconsistent
epochs, so it is not a config copy-paste from Messenger. Check `v2` first.

## Sources

`facebook/akd`; Cloudflare's plexi namespace API; and Meta's log directory at
`d2e61astky5m6k.cloudfront.net`, all confirmed by probing. Everything about the
CDN's behaviour came from observing it, not from documentation.
