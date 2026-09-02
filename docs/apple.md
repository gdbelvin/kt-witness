# Apple

`apple.com/kt/top-level-tree` — **tier A**.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to Apple.

## What is peculiar

Apple is the deployment with **no published directory**. There is no way to
enumerate what it contains, and — uniquely among the five — no per-application
surface for the tree anyone actually cares about.

It is also the one where this project's own documentation was wrong. A previous
note recorded Apple inclusion proofs as *blocked on a capability Apple has not
deployed*. Half of that was false, and the correction came from a discovery
document nobody had looked at.

## The init bag

Apple publishes an unauthenticated, unsigned discovery document listing every
researcher endpoint:

```
https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch     (plain)
https://init-kt-prod.ess.apple.com/init/getBag?ix=3&p=atresearch     (signed)
```

Live contents:

| field | endpoint |
|---|---|
| `at-researcher-public-keys` | `https://kttcc-prod.ess.apple.com/at_researcher/public_keys` |
| `at-researcher-list-trees` | `…/at_researcher/list_trees` |
| `at-researcher-log-leaves` | `…/at_researcher/log_leaves` |
| `at-researcher-log-head` | `…/at_researcher/log_head` |
| `at-researcher-consistency-proof` | `…/at_researcher/consistency_proof` |
| **`at-researcher-log-inclusion-proof`** | **`…/at_researcher/log_inclusion_proof`** |

Two findings in one document.

**`log_inclusion_proof` exists and had never been tried.** It works; see below.

**`at-researcher-log-leaves-for-revision` is absent.** It is declared in Apple's
own `AuditorApi.proto`, and its response carries leaves *with* inclusion proofs
— exactly the thing that would bind iMessage heads to a verified root. It is in
the schema and not in the deployment. That absence is the explanation for the
404s this project had been recording as an unexplained symptom.

The lesson generalises: **Apple's protos describe a superset of what is
deployed.** Read the bag, not the schema, to know what exists.

## The trees

`at_researcher/list_trees` returns the same three trees for **every**
`application` value:

| treeId | logType | application | signing key |
|---|---|---|---|
| 7618469013902052 | `PER_APPLICATION_TREE` | `PRIVATE_CLOUD_COMPUTE` | `…c4ad1582…` |
| 5296182921832599 | `AT_LOG` | `PRIVATE_CLOUD_COMPUTE` | `…c4ad1582…` |
| 410322746470160 | `TOP_LEVEL_TREE` | *(shared)* | `…9b18e1d0…` |

The Top-Level Tree's key matches the one this project already pinned, and its
SHA-256 is the `signingKeySPKIHash` Apple advertises.

**No IDS_MESSAGING tree is listed.** That is the whole story for iMessage, and
it is a much better answer than "the RPC 404s".

## Structure

Apple's KT is a tree of trees.

```
                    Top-Level Tree (TLT)          ← witnessed, tier A
                            │
             each leaf is a per-application head
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
  PAT: iMessage      PAT: PCC            PAT: (others)
   visible in TLT     listed, readable    visible in TLT
   leaves only        head + proofs       leaves only
```

The witness cosigns the **Top-Level Tree**: an ECDSA-signed head, proven
append-only using Apple's own consistency proofs.

Per-application heads — including two iMessage trees — are read out of TLT
leaves and recorded as **observations**, never cosigned. They are signed by keys
Apple does not publish and are not bound to the root we verify. Publishing them
as attestations would claim more than the evidence supports; `applications.json`
says so explicitly in its own `note` field.

## The Apple Transparency (AT) log — fully verifiable

The PCC AT log is Apple's software transparency log, and everything a witness
needs is live and unauthenticated:

| capability | status |
|---|---|
| signed head, under the AT log's own key | ✅ verified |
| consistency proofs | ✅ verified, 14 hashes across 50 revisions |
| leaf reads with raw data | ✅ verified |
| **inclusion proofs** | ✅ **verified, with negative control** |

Measured: revision 49,515, size 55,094; leaf 7 (`rts.gateway.icloud.com`,
carrying RSA gateway keys) proven under a 16-hash path against a head verified
with Apple's key. A corrupted leaf is rejected.

Apple hashes **RFC 6962 style** — leaf `SHA-256(0x00‖data)`, node
`SHA-256(0x01‖left‖right)`, per `MerkleTree.swift` in `apple/security-pcc` — so
`golang.org/x/mod/sumdb/tlog` checks it directly with no new cryptography.

Requesting a proof is by `identifier` = **SHA-256 of the leaf's raw data**, not
by index:

```
ATLogInclusionProofRequest{ version=3, application=PRIVATE_CLOUD_COMPUTE(5), identifier=[sha256] }
```

`application=IDS_MESSAGING(1)` is rejected with `INVALID_REQUEST`. The endpoint
serves PCC and nothing else.

This is strictly more assurance than we currently publish for the Top-Level
Tree. It is *software* transparency rather than key transparency, so whether it
belongs in a KT witness's cosigning set is a positioning decision rather than a
technical one. See [TODO.md](../TODO.md).

## Traps

Every one of these returns **HTTP 200** with a plausible, wrong answer. None of
them looks like an error.

**`latestRevision` must be explicit.** Omit `revision = -1` from a `log_head`
request and the server returns 200 with the *empty tree* head.

**Merge-group bounds are required.** `log_leaves` without
`startMergeGroup=0, endMergeGroup=1` returns 200 and an empty leaf list.

**Consistency proofs live on a different surface.** `at_researcher/consistency_proof`
is listed in the bag but rejects requests; `at_client/consistency_proof` answers
the same question unauthenticated. The two `at_*` surfaces are not
interchangeable.

**Consistency proofs are keyed by revision, not size.** Size must be mapped to
revision by binary search over `log_head`. Apple may also split a requested
range into multiple adjoining proofs, which are chained with `tlog.CheckTree`.

**`logType` is per-request and silently wrong.** The Top-Level Tree path
hardcodes `logType=TOP_LEVEL_TREE`. Reusing it to ask about the AT log returns a
perfectly valid proof — *about the Top-Level Tree*. This one was caught only by
noticing that a probe had succeeded too easily; a proof that verifies is not the
same as a proof about the thing you asked about.

## TLS

`kttcc-prod.ess.apple.com` is issued by **Apple's own private CA**, not a public
root. macOS trusts it, so this works in development and fails in a distroless
container — a class of bug that lets the witness start normally with one adapter
silently dead.

Apple Root CA is embedded (`apple-root.cer`, SHA-256
`b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`) and pinned.

## What would unblock iMessage

Any one of:

- **`log-leaves-for-revision` appearing in the init bag.** Already specified;
  its response carries leaves with inclusion proofs. Worth re-checking the bag
  periodically — this is a deployment change, not a design change.
- **An IDS_MESSAGING tree appearing in `list_trees`**, with a published signing
  key.
- **`log_inclusion_proof` accepting `application=IDS_MESSAGING`.**

None needs new cryptography. The tree is RFC 6962 and this project already
verifies Apple proofs; it is purely a question of what Apple exposes.

Until then, iMessage heads stay observations, labelled as such.

## Sources

`apple/security-pcc` (`srd_tools/vre/pccvre/TransparencyLog/`) for the protos,
the init-bag mechanism and `MerkleTree.swift`'s hashing; everything about live
behaviour from probing production, because the schema and the deployment
disagree.
