# Design

How the witness works, independently of any particular Key Transparency
deployment. One file per ecosystem sits beside this one and covers only what is
unique to that deployment:

| | |
|---|---|
| [c2sp.md](c2sp.md) | Native signed-note logs — thelemail, any Sunlight-family log |
| [meta.md](meta.md) | Meta / Messenger, via AKD audit proofs on a public bucket |
| [proton.md](proton.md) | Proton Mail, the one directory published in full |
| [signal.md](signal.md) | Signal, the one with no published root |
| [apple.md](apple.md) | Apple, the one with no published directory |
| [akd-checkpoint.md](akd-checkpoint.md) | The AKD → signed-note canonicalisation, specified so anyone can implement it |
| [landscape.md](landscape.md) | The whole transparency-log world: what exists, what is covered, what is deliberately excluded |
| [cost.md](cost.md) | What it costs to run, measured per log, and what that means for funding |

## The problem

A Key Transparency log asks users to believe that the key it hands you for a
contact is the same key it hands everyone else. Nothing in a signed root
establishes that on its own: an operator can sign two perfectly well-formed
histories and show a different one to each victim. Detecting that requires
somebody outside the operator to record what they were shown and compare.

That role — the witness — is well developed for RFC 6962-style transparency
logs and almost absent for KT. There are more KT operators than KT witnesses.
This project is one witness that covers several of them.

## What a witness actually asserts

The witness's product is a **cosignature**: a statement, under a stable
identity, of the form *"at this time I saw this log at this size with this
root, and it extended everything I had seen before."*

That is a narrow claim, and its value comes from being narrow. It is not an
endorsement of the operator, it says nothing about whether any particular
user's key is correct, and it cannot be issued retroactively. What it does is
make equivocation expensive: an operator who shows different histories to
different people must either exclude the witness from one of them — visible as
a stalled cosignature — or produce two contradictory signed statements the
witness has published.

Every assertion also names the **tier** it was verified at, which is the
subject of the next section. Overpromising here is the single largest
reputational risk a witness has: a cosignature that implies more checking than
was done is worse than no cosignature, because people rely on it.

## Assurance tiers

Tiers are ordered weakest to strongest and live in the type system
(`internal/source.Tier`), so a numeric comparison means what it says.

### Tier S — signed head

*"The operator signed this root at this size."*

No relationship between successive observations is proven. This is the floor: a
signature relays the operator's claim without checking it. Nothing in the
project ships at tier S; it exists so an adapter under development cannot
silently imply more.

### Tier A — append-only

*"…and every root I have witnessed is a prefix of this one."*

Adds a consistency proof between the previously witnessed size and the current
one, verified locally. This is what catches equivocation and rollback, and it
is the classic witness assertion.

### Tier A+ — root-chain continuity

*"…and I have verified that chain across the log's entire published history,
not just since I started watching."*

Available where a log's published layout links each epoch's root to its
predecessor, so the whole chain can be checked from metadata. For Meta that
covers 624,000+ epochs for the cost of paging XML. Best value per byte
available anywhere in this project.

### Tier B — construction audit

*"…and I have replayed the log's own proofs and confirmed the tree is
correctly built."*

The only tier that can see an **illegal mutation**. Everything above is about
the *shape* of the log and holds just as well if its contents are nonsense.

## Why append-only is not enough

This is the point the rest of the design turns on, so it is worth stating
plainly.

A KT directory is a **mutable map**, not an append-only list. Bindings are
added, replaced when a user rotates a key, and removed when an account closes.
The log records a sequence of commitments to that map's state.

A chain of consistent epoch hashes proves the *sequence of commitments* was not
rewritten. It cannot see:

- a binding **removed** without authorisation
- a binding **overwritten in place** without its version counter advancing
- a version **skipped**, so a key the user never published appears legitimate

Every one of those can be done while keeping the log perfectly consistent,
because they change what the map *contains*, not the order in which its
commitments were published.

This is not hypothetical. Replaying Proton's epoch 6708 → 6709 shows 36,520
additions and **9,337 removals** — and none of those removals are visible from
the chain of signed epoch hashes. Whether they are legitimate is a separate
question (Proton permits deletion inside a retention window). The point is that
only construction auditing can see them at all.

```
        what the epoch chain proves              what it cannot see
    ┌─────────────────────────────────┐   ┌─────────────────────────────┐
    │  E₅ ─→ E₆ ─→ E₇ ─→ E₈           │   │  inside E₇:                 │
    │  each hash commits to the last  │   │    alice@… removed          │
    │  nobody rewrote the sequence    │   │    bob@…   overwritten      │
    └─────────────────────────────────┘   │  chain stays perfect        │
                                          └─────────────────────────────┘
```

## The governing rule

> **Accusation requires positive contradiction, never absence.**

A missing object, a failed download, a proof that will not parse, a server that
times out — all of these mean *we could not check*, which is not evidence of
anything. They withhold the cosignature and retry.

Only a positive contradiction — two different roots at the same size, a broken
hash linkage, a consistency proof that refutes itself — marks a log as forked.
That decision is **permanent**: a log that equivocates and then reverts does not
quietly regain a cosignature.

The rule exists because it was nearly violated. Meta's audit proofs are served
through CloudFront, which caches *negative* listings, and a `Cache-Control:
no-cache` request header does not bypass it. A cached "absent" mid-walk looks
exactly like a hole in Meta's history, and the first version of the adapter
would have published a false, permanent, public accusation that Meta had
forked. See [meta.md](meta.md).

**Withholding is the enforcement mechanism.** It costs an honest operator
nothing and denies a dishonest one the cosignature they wanted. There is no
need to reach for an accusation to have an effect.

### Derived heads

The same trap has a second layer. Some sources do not receive a signed head at
all — they *derive* one by reading storage. For those, a head that appears to
have gone backwards is far more likely to be a bad read than a rollback.

Sources therefore declare `DerivedHead()`. When it is true, even a
size-with-different-root contradiction only withholds, because the "contradiction"
is between two of *our* readings rather than two of the operator's signatures.
Meta and WhatsApp are the derived-head sources: both are read out of object
listings rather than handed to us signed.

## Architecture

```
                    ┌────────────────────────────────────────┐
   operators        │            per-ecosystem adapters      │
   ──────────       │  (all KT-specific cryptography lives   │
                    │             only in here)              │
  thelemail  ──────▶│  c2sp    tier A / B                    │
  static CT  ──────▶│  c2sp  + staticct    tier A            │
  Meta       ──────▶│  akd     tier A+ / B   derived head    │
  WhatsApp   ──────▶│  akd     tier A+ / B   derived head    │
  Proton     ──────▶│  proton  tier A+ / B                   │
  Signal     ──────▶│  signal  tier A + per-label spot check │
  Apple KT   ──────▶│  apple   tier A                        │
  Apple AT   ──────▶│  apple   tier A                        │
                    └───────────────────┬────────────────────┘
                                        │  Source interface
                                        │  Origin() Tier() DerivedHead()
                                        │  Fetch() VerifyConsistency()
                                        ▼
                    ┌────────────────────────────────────────┐
                    │          witness core (generic)        │
                    │  1. is this log poisoned?  → refuse    │
                    │  2. does it extend what I saw? → check │
                    │  3. is it fresh enough?    → gate      │
                    └───────────────────┬────────────────────┘
                                        ▼
                    ┌────────────────────────────────────────┐
                    │  sign   cosignature/v1, Ed25519        │
                    └───────────────────┬────────────────────┘
                          ┌─────────────┴──────────────┐
                          ▼                            ▼
              ┌───────────────────────┐   ┌────────────────────────┐
              │  store  (bbolt)       │   │  serve                 │
              │  authoritative        │   │  GET /<hash>/checkpoint│
              │  compare-and-set      │   │  POST /add-checkpoint  │
              └───────────┬───────────┘   └────────────────────────┘
                          ▼
              ┌───────────────────────┐
              │  export  plain files  │   status.json, checkpoints/*.txt,
              │  derived, disposable  │   audits/*.jsonl, forks/*.json
              └───────────────────────┘
```

The core is protocol-agnostic. It knows about tiers, contradiction, poisoning
and freshness; it knows nothing about AKD, prefix trees or sparse Merkle trees.
Every adapter reduces its ecosystem to the same `Source` interface:

```go
type Source interface {
	Origin() string
	Tier() Tier
	DerivedHead() bool
	Fetch(ctx context.Context, prev *Head) (*Head, error)
	VerifyConsistency(ctx context.Context, prev, next *Head) error
}
```

### The bridge

The reusable contribution is smaller than the code and more useful: the
**canonicalisation** of a KT epoch into a `tlog-checkpoint` signed note.

Existing witness infrastructure — C2SP `tlog-witness`, Sunlight, sigsum — is
mature and cannot consume CONIKS/AKD-family KT epochs at all. Mapping
`(epoch, root)` onto an origin and a signed note is what lets that network
cosign a KT log for the first time. That mapping wants to be a written spec, not
only an implementation.

## Polling and re-signing

The witness polls rather than waiting to be pushed, because a witness that only
sees what an operator chooses to send it is not independent. Push is also
accepted, for native C2SP logs whose operators expect it.

Unchanged logs are re-cosigned hourly. A cosignature carries a timestamp, so
re-signing an unchanged head turns that timestamp into a liveness signal: a
consumer can tell "this log has not moved" apart from "this witness stopped
looking". The consistency proof is skipped on a refresh, since nothing moved.

Freshness is gated in the other direction too — the witness refuses to cosign a
head older than a configured bound, so a stale checkpoint cannot be laundered
into a fresh-looking cosignature.

## Storage

Two layers, with a deliberate split of responsibility.

**bbolt is authoritative.** A single file, one writer, with buckets for heads,
forks, poisoned logs, audits, backfilled history, and observed application
heads. It exists for one property the spec demands: `tlog-witness` calls out a
race where two conflicting checkpoints of the same size are both accepted, and
the fix is a compare-and-set inside a single transaction.

**Plain files are the product.** Evidence locked inside a B+tree that needs our
binary to read is evidence with a dependency on us. Somebody reproducing a fork
claim should be able to use `cat` and `jq`. So a derived mirror is written
beside the database:

```
<dir>/
  status.json                  everything at a glance
  checkpoints/<log>.txt        the cosigned note, byte for byte
  history.json                 what backfill established
  applications.json            observed heads (never cosigned)
  audits/<log>.jsonl           tier-B decisions, one JSON object per line
  forks/<log>-<unix>.json      misbehaviour evidence, one file each
```

Nothing there is a source of truth. Deleting the whole directory loses nothing
and it is rebuilt on the next round. Writes are atomic (write-then-rename) so the
directory can be served while the witness runs, and fork evidence is written
**once and never rewritten** — an accusation that changes shape after
publication is not evidence.

## Probabilistic auditing

Tier B is expensive. Meta publishes a ~284 MB audit proof every 120 seconds:
about 204 GB/day for one namespace, and replaying from genesis would be ~175 TB.
Continuous full audit is not on the table.

Sampling is, provided the operator cannot predict which epochs will be checked.
Selection is driven by the drand *quicknet* beacon, drawn **after** each epoch
is published:

```
select(epoch) ⟺ first 8 bytes of SHA-256(randomness ‖ ":" ‖ uint64be(epoch)) < rate · 2⁶⁴
```

Because the randomness postdates the epoch, an operator cannot know at
publication time whether a given epoch will be audited — so cheating anywhere
carries a `rate` chance of detection per epoch, and cheating repeatedly is
caught quickly. Declined epochs are recorded too, so coverage is auditable
rather than asserted.

Two honest limits. The sampling rate is disclosed in the published assertion,
because a sampled audit is not a full one. And the beacon round is not yet
canonicalised — rounds are 3 seconds apart, so a dishonest witness could redraw
until an epoch deselects. Gossip between witnesses fixes that and makes coverage
compose; see [TODO.md](../TODO.md).

Note the argument does not transfer to Signal, whose proofs are per-*label*
rather than per-epoch. See [signal.md](signal.md).

## Incident model

There is no standardised alerting protocol for this, so:

- **Fail closed.** Never sign speculatively. Any verification error withholds.
- **Poison permanently.** A confirmed fork is recorded write-once and the log is
  refused from then on.
- **Publish reproducible evidence.** Both conflicting views are written
  verbatim, so a disclosure can be checked independently of this witness — and
  of whether anyone trusts it.
- **Disclose out of band.** A confirmed fork is a human decision to publish, not
  an automated one.

## Verification approach

The recurring problem in this project is that a proof implementation which is
subtly wrong tends to *pass its own tests*. Two things guard against that.

**Self-validating acceptance tests.** Prefer checks where several independent
mechanisms must agree, so passing by accident is implausible:

- Signal's log tree was accepted because three auditors, at different sizes with
  different proofs, independently derived the *same* service root, and three of
  Signal's signatures verified over it.
- Signal's search path was accepted because a chain of VRF → prefix tree → batch
  inclusion → commitment produced a root equal to the one those auditors had
  already agreed on, by an entirely separate route.
- Apple's hashing was established by running a production proof through an
  existing RFC 6962 implementation.
- Proton's tree was accepted by rebuilding all 200,714,006 published leaves and
  matching the signed hash exactly.

**Negative controls everywhere.** A check that still passes on mutated input is
not checking anything. Every proof path has a test that corrupts one byte and
requires failure.

Where a reference implementation exists, its own test vectors are used, so the
code is checked against the reference rather than against itself.
