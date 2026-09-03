# AKD epochs as signed-note checkpoints

A specification for canonicalising an AKD-family Key Transparency epoch into a
`c2sp.org/tlog-checkpoint` signed note, so that existing transparency-log
witness infrastructure can cosign a KT log.

This is the reusable part of this project. The implementation lives in
`internal/source/akd`, but the mapping is what other people need, and a mapping
that exists only as code is not a mapping anyone else can implement. Everything
below describes what that code actually does; where the implementation and an
ideal spec diverge, the implementation is described and the divergence noted.

## 1. Scope and motivation

Witness infrastructure — C2SP `tlog-witness`, Sunlight, sigsum,
transparency-dev — is mature, deployed, and built around one shape: an
RFC 6962-style append-only log that publishes a signed checkpoint of
`(origin, size, root)` and serves Merkle consistency proofs between sizes.

CONIKS/AKD-family Key Transparency deployments do not have that shape. They
publish a sequence of *epochs*, each committing to the current state of a
mutable directory, and they link epochs to one another by hash rather than by
Merkle consistency proof. None of them publishes a signed note. The result is
that the entire existing witness ecosystem cannot consume a KT log at all — not
because the cryptography is incompatible, but because nothing translates.

This document is that translation. It specifies how an `(epoch, root)` pair
from an AKD deployment becomes a checkpoint body that any signed-note
implementation can parse, cosign, and serve, and — more importantly — exactly
what a cosignature on that checkpoint is and is not permitted to mean.

It is written against Meta's Messenger and WhatsApp deployments, which are the
two publicly reachable AKD logs. Nothing in the canonicalisation is specific to
Meta; anything with the same published layout can use it.

## 2. The source data

An AKD deployment of this shape publishes audit proof objects into a listable
object store (Meta's is fronted by CloudFront, speaking the S3
`ListObjectsV2` API). Each object is keyed:

```
<epoch>/<prev_root>/<curr_root>
```

| field | meaning |
|---|---|
| `epoch` | the **target** epoch of the transition, in base-10 with no leading zeros |
| `prev_root` | the AKD root hash *before* the transition, lowercase hex, 32 bytes / 64 characters |
| `curr_root` | the AKD root hash *after* the transition, lowercase hex, 32 bytes / 64 characters |

The object *body* is the construction proof for that transition — for Meta,
roughly 284 MB. The canonicalisation never reads it. Everything this spec needs
is in the key.

That is the property the whole thing rests on: **the root chain is self-linking
in the listing metadata**. For consecutive epochs `n` and `n+1`, the published
history is continuous exactly when

```
curr_root(n) == prev_root(n+1)
```

and that can be checked across the log's entire published history by paging
XML. Meta has 624,000+ epochs; verifying the chain across all of them costs a
few hundred listing requests and no proof downloads.

Two properties of the store that an implementer will otherwise discover the
hard way:

- **Object keys sort lexicographically, not numerically.** `"99999"` sorts
  after `"624700"`. A bulk listing therefore arrives in an order that is not
  epoch order, and a chain walk MUST be driven by epoch number and hash
  linkage, never by listing position.
- **There is no "latest epoch" endpoint.** The tip has to be located by probing
  (the implementation uses an exponential probe upward from a hint followed by
  a binary search on the present/absent boundary: `O(log n)` requests).

Meta publishes no signature over any of this. There is no epoch signing key we
have been able to find, and the signatures on Cloudflare's plexi `/reports`
endpoint are reporters' own, on an endpoint that accepts open submissions and
currently carries obviously synthetic digests (`deadbeef…`, `cafebabe…`). This
fact drives section 4.

## 3. The canonicalisation

A link `(epoch, prev_root, curr_root)` recovered from one object key becomes a
`c2sp.org/tlog-checkpoint` body as follows.

### Body

The checkpoint body is exactly three lines, each terminated by a single `\n`
(U+000A), with no other content, no leading or trailing whitespace, and no
extension lines:

```
<origin>\n
<epoch>\n
<base64(curr_root)>\n
```

- **Line 1 — origin.** The witness-minted origin string for this log
  (section 3.1).
- **Line 2 — size.** The `epoch` from the object key, formatted as a base-10
  signed 64-bit integer with no leading zeros, no sign, and no separators.
- **Line 3 — root hash.** `curr_root` from the object key, decoded from its
  64 hex characters to 32 raw bytes and re-encoded with **standard base64
  (RFC 4648 §4, with padding)**. For a 32-byte hash this is always 44
  characters ending in a single `=`. It is *not* base64url and *not*
  unpadded — this is what `tlog-checkpoint` requires and what
  `torchwood.Checkpoint.String()` emits.

The implementation constructs this via `torchwood.Checkpoint{Origin, Tree:
tlog.Tree{N: epoch, Hash: curr_root}}.String()` with an empty `Extension`
field. An independent implementer producing the three lines above by string
concatenation gets byte-identical output.

Worked example, with an illustrative hash. Given the object key

```
624784/<64 hex>/3f0a9c1d4e7b2856a1c09fd3b6e45102778bd4a90c3e5f61829d47ba0e5c3311
```

and origin `meta.messenger.kt/v1`, the body is these 73 bytes:

```
meta.messenger.kt/v1
624784
PwqcHU57KFahwJ/TtuRRAneL1KkMPl9hgp1Hug5cMxE=
```

(with a trailing newline after the base64 line).

### 3.1 Origin

The origin is a **convention minted by the witness**, not anything the operator
publishes. AKD deployments publish no checkpoints and therefore no origin
strings; one has to be chosen, and the whole point of an origin is that
everybody chooses the same one, so it is fixed here rather than left to
configuration in practice.

The convention is a schema-less URL-like identifier naming the operator, the
service, and a version:

| log | origin |
|---|---|
| Meta / Messenger | `meta.messenger.kt/v1` |
| WhatsApp | `whatsapp.kt/v2` |

Implementations MUST treat the origin as an opaque, exact-match string: it is
the witness's primary key for the log, and it is what a `tlog-witness` client
hashes to address the checkpoint endpoint. Two witnesses that pick different
origins for the same log produce cosignatures that cannot be aggregated, which
defeats the purpose.

The version suffix tracks the *deployment's* namespace version, not this
spec's: WhatsApp is `v2` because Meta's `whatsapp.key-transparency.v1`
namespace reports status `Disabled` with inconsistent epochs and `v2` is the
live one.

Because the origin is minted rather than derived, it carries no authority. It
identifies which log is being talked about and nothing more.

### 3.2 The size field is an epoch number

This is the single most important thing for an implementer coming from
RFC 6962 to internalise, and it is the one place where the canonicalisation
deliberately reuses a field for a different meaning.

In a `tlog-checkpoint` for an RFC 6962-style log, line 2 is a **leaf count**,
and the relationship between two checkpoints is proven by a Merkle consistency
proof between those two sizes. Here, line 2 is an **epoch number**. It counts
directory revisions, not entries. It says nothing about how many bindings the
directory contains, and it does not grow by one per binding added.

Consequences, all normative:

- A verifier MUST NOT attempt an RFC 6962 consistency proof between two
  checkpoints for an AKD origin. No such proof exists, and none is served.
- Consistency between sizes `m` and `n` for these origins means, and only
  means, the `prev_root`/`curr_root` chain walk of section 5.
- A verifier MUST NOT attempt an RFC 6962 inclusion proof against the root on
  line 3. It is an AKD root, committing to a directory state, not a Merkle tree
  head over a leaf sequence.
- The monotonicity property a witness enforces — size never decreases, and the
  same size never carries two different roots — does still hold and is still
  meaningful, because epochs are strictly increasing.

The reuse is justified by the fact that every generic property a witness cares
about (ordering, uniqueness per size, non-regression) holds for epoch numbers
as well as for leaf counts. The property that does *not* transfer is the one
proof format, and the spec is explicit about that rather than letting an
implementer assume.

### 3.3 Signatures

As minted, the note has **no signatures at all**. This is abnormal for a
checkpoint — normally the log signs it — and it follows directly from the fact
that the operator publishes no signature over anything. The witness constructs
an unsigned note body and then adds its own `cosignature/v1` Ed25519
cosignature (via `torchwood.CosignatureSigner`) when, and only when, the
verification of section 5 succeeds.

So a served checkpoint for an AKD origin carries witness cosignatures and
nothing else. A consumer that expects to find and verify a log signature will
find none, and MUST NOT interpret its absence as an error in the note — it is a
true statement about the deployment.

### 3.4 Extension lines

None are defined. The extension field is empty and the body is exactly three
lines. An implementation MUST NOT add extension lines without defining them
here first, because they are covered by the cosignature and a consumer that
does not understand them cannot tell what it just relied on.

A `prev_root` extension line was considered and rejected: it would make each
checkpoint self-describing as a chain step, but a witness that has verified the
chain already knows it, and one that has not must not be handed something that
looks like proof.

## 4. What the checkpoint asserts — and does not

This is the section to read if you read only one.

A witness cosignature on an AKD checkpoint produced under this spec asserts,
precisely:

> At this time, I observed this log's published objects to name this root at
> this epoch, and the chain of `prev_root`/`curr_root` links from the last
> epoch I witnessed to this one was continuous.

That is **tier A+** in the vocabulary of [design.md](design.md): append-only
between observations, plus root-chain continuity across published history.

It does **not** assert any of the following, and anyone adopting this mapping
must not let it be read as though it does.

**It does not assert that the operator signed anything.** No signature by Meta
is verified, because none is published. The claim is about *our reading of a
public object store*. Every downstream description must preserve the
difference between "kt-witness observed this root chain" and "Meta signed this
root". This is why `DerivedHead()` is true for these sources.

**It does not assert the directory is correctly constructed.** A KT directory
is a mutable map, not an append-only list. A perfectly continuous chain of
epoch roots is compatible with a binding removed without authorisation, a
binding overwritten in place without its version counter advancing, or a
version skipped so that a key the user never published appears legitimate.
Each of those changes what the map contains, not the order in which its
commitments were published. Seeing them requires replaying the construction
proofs — tier B — which is a separate and much more expensive path. Tier A+ is
about the *shape* of the log and holds just as well if its contents are
nonsense.

**It does not assert anything about any particular user's key.**

**It is not an endorsement of the operator.** A witness cosigns logs precisely
because it does not trust them. The value of the assertion comes from being
narrow: it makes equivocation expensive, because an operator showing different
histories to different people must either exclude the witness from one of them
— visible as a stalled cosignature — or produce two contradictory statements
the witness has published.

**It says nothing about epochs before the first one witnessed**, unless a
backfill pass established them, and a backfill establishes chain continuity
only — the same tier A+ claim, extended backwards.

Any publication of these cosignatures MUST name the tier alongside them. A
cosignature that implies more checking than was done is worse than no
cosignature, because people rely on it.

## 5. Verification procedure

An implementer verifying that checkpoint `next` extends previously witnessed
checkpoint `prev`, both for the same origin, proceeds as follows.

**Step 0 — first observation.** If there is no `prev`, this is
trust-on-first-use. Pin `next` and attest continuity only from this epoch
forward. Do not attempt to reach genesis: full replay is not affordable, and a
chain walk over hundreds of thousands of epochs will not finish inside any
reasonable signing deadline. (Backfill is a separate, non-blocking pass; see
below.)

**Step 1 — listing, per epoch.** For each `epoch` from `prev.size + 1` through
`next.size` inclusive, issue a listing request scoped by prefix:

```
GET <log_directory>/?list-type=2&prefix=<epoch>/&max-keys=2&cb=<nonce>
```

The `cb` parameter is a per-request random cache-busting nonce (the
implementation uses 8 random bytes, hex-encoded). It is **required for
correctness, not an optimisation**: CloudFront serves stale *negative*
listings, and a `Cache-Control: no-cache` request header does not bypass it.
See section 6.

`max-keys=2` is deliberate — it is the smallest value that can still reveal a
second object for the same epoch.

**Step 2 — interpret the listing.**

- *Zero keys.* The epoch is absent. **Withhold and retry.** Do not accuse. A
  hole in the middle of published history is tempting to call a rollback, but
  absence is the one observation that cannot be trusted: an edge cache, a
  partially completed write, or an out-of-order upload all produce it
  transiently.
- *Two or more keys.* Two published histories at the same point. Report as an
  ordinary error and **withhold**. Confirming this as equivocation means
  deliberately fetching both keys and comparing them, not acting on a single
  listing response.
- *Exactly one key.* Split it on `/` into exactly three parts. Reject the
  object if it does not split into three, if part 0 does not parse as an
  integer equal to the requested epoch, or if either hash is not exactly 64 hex
  characters. All of these are withhold, not accuse.

**Step 3 — walk the chain.** Maintain `expected`, initialised to `prev.hash`.
For each epoch in ascending order:

- If `link.prev_root != expected`, this is a **positive contradiction**: the
  object for epoch `n` declares a previous root that epoch `n-1` did not
  publish. Both objects exist and their names disagree; no cache or transient
  read produces this. Raise a fork.
- Otherwise set `expected = link.curr_root` and continue.

**Step 4 — close the loop.** After the walk, `expected` MUST equal
`next.hash`. If it does not, the tip disagrees with the chain that leads to it,
which is also a positive contradiction and a fork.

**Step 5 — cosign.** Only now. Any error at any earlier step withholds.

### Ordering

The chain MUST be walked by ascending epoch number, resolving each epoch by its
own prefixed listing or by an epoch-keyed index built from a bulk listing.
Object keys sort lexicographically (`"99999"` sorts after `"624700"`), so a
bulk listing's natural order is not epoch order. An implementation that walks
in listing order will produce linkage failures on honest data — the worst
possible failure mode, since a linkage failure is the one thing this spec
treats as conclusive.

The bulk path (used for backfill) is: page the whole listing with
`max-keys=1000`, parse every key into an epoch-indexed map — **silently
skipping** keys that do not parse, since the store may hold unrelated objects —
sort the epoch numbers numerically, then check linkage between numerically
adjacent entries. Non-consecutive epoch numbers are a *gap*, reported and
skipped, never a fork: linkage cannot be checked across a hole, and retention
limits produce holes legitimately.

### The derived-head caveat

The head verified here was assembled from listing metadata. Nobody signed it.
So a verifier MUST apply the weaker of the two contradiction rules to it:

- A **broken hash linkage** (steps 3 and 4) is conclusive. It is a
  contradiction between two objects the operator published.
- A head that appears to have **gone backwards**, or the same size carrying two
  different roots, only **withholds**. That contradiction is between two of
  *our* readings, not two of the operator's signatures, and a bad read is by
  far the more likely explanation.

This is the `DerivedHead()` flag in the `Source` interface, and it exists
because the generic core originally applied the conclusive rule to a size
derived from a chain of *absence* observations.

### Intermediate heads (non-normative)

Because proving consistency means walking every intervening epoch, a source
that is far behind cannot catch up in one step inside a signing deadline. The
implementation bounds a round to 200 epochs and reports an intermediate head
instead of the true tip, so catch-up converges over several rounds. This is
permitted — the checkpoint for an intermediate epoch is a valid checkpoint —
and is a scheduling choice, not part of the canonicalisation.

## 6. Security considerations

**Derived heads.** The heads canonicalised here carry no operator signature.
Everything downstream inherits that. A consumer aggregating cosignatures across
logs MUST NOT assume that a cosigned checkpoint implies a log signature it can
fall back on; for these origins there is none.

**Absence is not evidence.** The governing rule of this project is that
accusation requires positive contradiction, never absence. A missing object, a
failed download, an unparseable proof, a server that times out — all mean *we
could not check*, which is evidence of nothing. Withholding is the enforcement
mechanism: it costs an honest operator nothing and denies a dishonest one the
cosignature they wanted, so there is never a need to reach for an accusation to
have an effect. A fork determination is permanent and public; a log that
equivocates and then reverts does not quietly regain a cosignature.

**CDN caching of negative listings.** This rule exists because it was nearly
violated. Meta's audit proofs are served through CloudFront, which caches
*negative* listings — a listing for an epoch that had since been published
returned zero keys with `x-cache: Hit` and `age: 180` — and a `Cache-Control:
no-cache` request header does not bypass it. A cached "absent" in the middle of
a chain walk looks exactly like a hole in Meta's history, and the first version
of this adapter would have published a false, permanent, public accusation that
Meta had forked. Two fixes, in order of importance: absence was reclassified as
retryable, and a per-request cache-busting nonce was added. An implementer who
omits the nonce and treats absence as conclusive will eventually make the same
false accusation. See [meta.md](meta.md).

**A cosignature is not an endorsement.** Restating section 4 because it is the
claim most likely to be lost in summary: a witness cosigning an AKD checkpoint
is not vouching for the operator, the directory, or any key. It is recording
what it saw, so that showing two different things to two different people
becomes detectable.

**Cross-checks are not signatures.** The implementation cross-checks
Cloudflare's plexi anchor root against Meta's own store and refuses to sign
when they disagree, on the reasoning that two unrelated parties having to agree
is stronger than either alone. That is a useful independent signal, and it is
not a signature verification. plexi's namespace `root` field also lags badly
(observed at epoch 89,527 while `last_verified_epoch` was 624,707), so it is a
historical anchor to cross-check, never the tip.

**plexi `/reports` is open submission.** It carries obvious placeholder digests
alongside real ones. Listed digests MUST NOT be treated as authoritative; only
verified signatures count, and the signatures there are reporters' own.

**Tier B has its own trap.** If an implementation goes on to verify
construction proofs, note that Meta names objects by the **target** epoch while
`akd`'s `generate_audit_blobs` names by the **source** epoch, so `audit_verify`
must be passed `epochs = vec![key_epoch - 1]`. Getting it wrong makes the start
hash check pass and the end hash check fail. Tier-B results must also be
classified: only a genuine *verify* failure can accuse, while a failed fetch or
an undecodable blob is absence.

## 7. Open questions and what is not specified

**Incorporating an operator signature.** If Meta ever publishes a pinnable
epoch signing key — or Cloudflare publishes its auditor key in a verifiable
form — the right thing is to verify that signature, flip `DerivedHead()` to
false for the source, and restore the conclusive treatment of head regressions.
What is *not* settled is how the operator's signature would ride on the
checkpoint. The note format has room for it, but the operator would be signing
a body this spec invented, which they have no reason to produce. The likely
answer is an extension line carrying the operator's own signed artifact
verbatim, so a verifier checks the native signature rather than a re-encoding —
but that line is not defined here, and defining it speculatively would be
worse than leaving it open.

**Cloudflare's signed auditor output.** `/namespaces/<ns>/audits` returns 405
to GET. The path to plexi's *signed* output is not established, so the
cross-check currently uses the unsigned namespace `root` field.

**A tier line in the checkpoint.** Consumers currently learn the tier
out of band, from this project's published status. Putting it in the note would
make each cosignature self-describing, but it would also be a claim about the
witness inside a note about the log, and it is not obvious that belongs there.
Unresolved.

**Genesis.** Nothing here establishes the first epoch. Backfill can walk the
published history back as far as the operator retains objects; before that
there is no chain to check, and trust-on-first-use is doing the work.

**Cross-witness agreement.** Two witnesses independently deriving the same
checkpoint body for the same epoch is a much stronger signal than either alone,
and this spec makes it possible by fixing the encoding. Nothing yet specifies
how those observations are gossiped or compared.

## Sources

`internal/source/akd/akd.go` and `internal/source/source.go` in this
repository; `filippo.io/torchwood` for the checkpoint encoding;
`c2sp.org/tlog-checkpoint` and `c2sp.org/tlog-witness`; `facebook/akd` 0.13;
Cloudflare's plexi namespace API; and Meta's log directory at
`d2e61astky5m6k.cloudfront.net`. Everything about the CDN's behaviour came from
observing it, not from documentation.
