# Proton

`proton.me/kt/v1` — **tier A+**, and **tier B** via the construction audit.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to Proton.

## What is peculiar

Proton is the deployment that **publishes its entire directory**. Every epoch's
complete leaf set is downloadable, and so is the diff between consecutive
epochs. That makes it the only ecosystem here where a third party can rebuild
the whole tree and check it against the signed root — and consequently the one
that demonstrates, concretely, why append-only is not enough.

Proton is also peculiar in what it signs with: **there is no Ed25519 root
signature**. Equivocation is meant to be caught through Certificate
Transparency.

## The chain hash

Each epoch commits to its predecessor:

```
chain_hash(t) = SHA-256( chain_hash(t-1) ‖ tree_hash(t) )
```

Verifying that chain across the retention window is tier A+, and it is cheap.

One wire-format trap: the JSON field is `PrevChainHash`. Proton's *own* Go
client struct calls it `PreviousChainHash` — the two do not match, and a decoder
written from their client silently gets a zero value.

## Certificates instead of signatures

Instead of signing roots, Proton issues a WebPKI certificate per epoch whose
Subject Alternative Name encodes the chain hash:

```
<chainhash[0:32]>.<chainhash[32:64]>.<certificateTime>.<epochID>.1.<domain>
```

The certificate is verified against WebPKI. Because certificates expire after
about 90 days, this is checked for the tip only; older epochs rely on the chain.

The design intent is that a fork requires *two certificates* for the same epoch,
both logged in CT — making equivocation publicly visible through infrastructure
Proton does not control. That is a genuinely elegant use of CT.

The loop is closed. Given the CT logs this witness already watches, it rebuilds
the precertificate's RFC 6962 Merkle leaf and matches it against the hash the
log's own signed checkpoint carries at the index the SCT names — verifying
inclusion locally from tiles rather than trusting the SCT's promise or asking
the log for a proof.

Confirmed live: epoch 6712's certificate is entry 593,786,554 of
`tuscolo2026h2.sunlight.geomys.org`. Negative controls in the same test reject
the certificate at index+1 and a bit-flipped TBS at the right index.

The whole configured CT set is supplied rather than one pinned log, because CT
shards are temporal and rotate underneath Proton's ~90-day certificates.

## The tree

A **256-level sparse Merkle tree**, recovered from Proton's C verifier:

```
label   32 bytes
value   36 bytes
leaf    68 bytes, records sorted by label
depth   256, bit read MSB-first: bitAt(label, level) = label[(level-1)/8] >> (7-((level-1)%8)) & 1
```

The critical rule, and the one that would have been missed:

```go
func join(left, right []byte) []byte {
    if isEmpty(left) && isEmpty(right) { return emptyNode }   // zeros ‖ zeros stays zeros
    return sha256(left ‖ right)
}
```

An all-zero node combined with another all-zero node stays all-zero rather than
being hashed. Getting this wrong is only reachable through the sharded code
path, so it would have surfaced for the first time at full scale, after a
20-minute run.

## Rebuilding 200 million leaves

The full dump is **~13.6 GB for ~200.7 million leaves**. Two properties make the
rebuild affordable:

- the dump is **sorted by label**, so the tree can be built by recursive range
  splitting — every subtree is a contiguous byte range;
- that runs in **constant memory** over a memory-mapped file, sharded across
  cores at a configurable depth.

```
$ kt-proton-audit -epoch 6709
  200714006 leaves
  recomputed  b18dc51c789386cf34fa7fd497128260986aee8ea6e9082074a602f93352db8c
  MATCH: the signed tree hash is exactly what these leaves build.
```

## Between snapshots: replaying the step

The full rebuild proves the operator's leaves build the root they signed. It
says nothing about whether the change from one epoch to the next was
*legitimate*.

Proton publishes a diff per epoch — 69-byte records (`1 op ‖ 32 label ‖ 36
value`), against 68-byte tree records. Applying it and rebuilding is the
between-snapshot audit:

```
$ kt-proton-audit -from 6708 -epoch 6709
  downloading base tree                    13.65 GB in 8m28s
  diff 3.16 MB (45857 records)
  merged in 37s
  mutations: 36520 added, 9337 removed, 0 overwritten in place, 0 removals of absent labels
  NOTE: this epoch mutated existing entries. None of that is
        visible from the chain of signed epoch hashes.
  rebuilding 200714006 leaves
  recomputed  b18dc51c789386cf34fa7fd497128260986aee8ea6e9082074a602f93352db8c
  took        18m45s

  MATCH: epoch 6708 plus its published diff is exactly epoch 6709.
```

**9,337 removals in a single epoch.** Every one invisible from the chain of
signed epoch hashes, and every one confirmed by this audit. This is the concrete
demonstration behind the mutable-map argument in [design.md](design.md).

Mutations are **reported, never silently folded into a new root**. Removals and
in-place overwrites are the entire point of running the audit.

They are also not accusations, and each removal is now judged rather than
merely counted. The 36-byte leaf value ends in the epoch that revision entered
the directory, and every epoch publishes the oldest epoch it still retains, so a
removal is explained exactly when the entry predates the window:

	explained  ⟺  minEpochID < StartEpochID(removing epoch)

Across five sampled epochs and 45,816 removals, every one was explained — and
the largest removed `minEpochID` in each epoch lands exactly on the window
boundary rather than merely inside it, which is what a retention policy looks
like when it is actually being applied.

The rule is inferred from Proton's behaviour, not promised by anything Proton
signs. So a removal that fails it withholds and is published; it is never an
accusation.

## Cost, and what it means for the witness loop

| | |
|---|---|
| full dump | 13.6 GB |
| download | ~8m30s |
| diff apply | ~37s |
| rebuild | ~19m |
| epoch cadence | ~4 hours |

Comfortably inside the cadence, so continuous tier B is genuinely affordable —
no sampling needed, unlike Meta.

It does not yet run inside the witness process. It needs the 13.6 GB tree kept
on disk between epochs (so only the 3 MB diff is fetched) and a scheduler that
tolerates a 19-minute job. That is plumbing, not cryptography, and it is the
nearest available increase in assurance for this witness.

## Sources

Tree structure and the empty-node rule recovered from Proton's C verifier;
epoch and diff formats from `proton.me/kt/` and `api.protonmail.ch/kt/v1/`,
confirmed by rebuilding.

## Why Proton reported A+ while doing tier-B work

Until now the incremental auditor rebuilt the entire tree, compared it against
Proton's signed root, and told nobody. Coverage is computed from stored audit
records — `AuditCoverage` counts them across the backfilled range — and nothing
was writing any, so the strongest construction evidence in the project was
invisible to the thing that decides what tier to claim.

Each successful rebuild now records an audit with strategy `rebuild` and rate 1:
every epoch is checked outright rather than sampled, so recording it as drawn
would misdescribe it. Only successes are recorded. A failed rebuild is already
logged loudly and does not poison the log here, and recording it as a settled
negative would let a transient I/O failure masquerade as a construction fault.

### What this does and does not reach

It gives Proton **forward** coverage from the bootstrap point. The auditor steps
one epoch at a time toward the tip; it never walks backwards, because going back
would mean bootstrapping a full ~13.6 GB tree per epoch rather than applying a
3 MB diff.

So epochs published before the witness bootstrapped stay unaudited, and Proton
cannot honestly claim B+ across its whole published range on this mechanism
alone. Tier B — construction audited, growing — is what it earns, and the
coverage number says exactly how much. Claiming otherwise would be the
overpromise this project exists not to make.
