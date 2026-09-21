# Threat model

What a dishonest key transparency server can actually do, who is capable of
noticing, and what this witness catches today.

The point of writing it down is to stop the three roles — client, auditor,
witness — from being conflated. Each catches things the others structurally
cannot, and a deployment that has two of the three is not "mostly covered": it
has a specific, nameable hole.

## The adversary

The server operator. It controls the directory, the proofs it serves, and which
client sees which response. It is assumed to want at least one of:

- **read a target's messages** by binding a key it holds to the target's identity
- **do so without the target noticing**, which is a much stronger requirement
- **without other users noticing**, which is stronger again

Nothing here assumes the operator is careless. The interesting attacks are the
ones that leave every signature valid and every proof checking out.

## The attacks

Grouped by which layer they abuse. The grouping matters because it maps onto who
can detect them.

### L — the log layer

The append-only structure the operator publishes.

| id | attack | what it looks like |
|---|---|---|
| **L1** | **Rollback** | serve an earlier root as current, undoing recent updates |
| **L2** | **Fork / split view** | maintain two divergent histories, show each to different clients |
| **L3** | **Targeted fork** | L2 aimed at one victim, everyone else sees the true history |
| **L4** | **Entry rewriting** | change the contents at a position already published |
| **L5** | **Omission** | never enter an update into the log at all |

L1, L2 and L4 are all detectable *in principle* from signed heads and proofs;
L3 is the hard one, because the victim is the only party with the false view and
has nobody to compare against.

### M — the map layer

What the directory *contains*. Every one of these can be done while keeping the
log perfectly append-only, because they change contents rather than order.

| id | attack | what it looks like |
|---|---|---|
| **M1** | **Key substitution** | bind an attacker-held key to a victim's label |
| **M2** | **Silent overwrite** | replace a binding without advancing its version counter |
| **M3** | **Version skip** | jump the counter so a key the user never published looks legitimate |
| **M4** | **Unauthorised removal** | delete a binding |
| **M5** | **Per-label rollback** | serve an older, validly-signed version of one label |
| **M6** | **Selective omission** | leave one label out of the map while the log looks complete |
| **M7** | **Padding abuse** | inflate the tree with fake entries to hide real activity in the noise |

### P — the proof layer

Lying about what the map contains. These are mostly closed by construction, and
are listed because "closed by construction" is a claim worth checking.

| id | attack | closed by |
|---|---|---|
| **P1** | steer a label to an index the operator chose | VRF verifiability — the operator cannot pick the index |
| **P2** | forge an inclusion proof | hash binding |
| **P3** | open one commitment two ways | binding commitments |

### D — degradation

Not attacks on the cryptography, but on the people checking it.

| id | attack | what it looks like |
|---|---|---|
| **D1** | **Auditor starvation** | serve clients normally, withhold proofs from auditors |
| **D2** | **Monitoring refusal** | rate-limit or refuse the endpoint a user needs to check their own key |
| **D3** | **Publication stop** | stop publishing audit proofs entirely |

D1 deserves emphasis. If an auditor's silence is indistinguishable from an
auditor that has not run, withholding is free. This is why *this* witness
publishes withholding as a signal rather than simply going quiet, and why
`consecutive_withheld` is a monitored metric rather than a log line.

### C — collusion

| id | attack | what it looks like |
|---|---|---|
| **C1** | server + auditor collude | signed roots endorse a dishonest map |
| **C2** | server + gossip transport collude | the party carrying clients' views is the party being checked |

C2 is not hypothetical. Where gossip is transported by the operator, the
operator chooses which views meet.

## Who can detect what

Three roles, three different vantages. None is a superset of another.

**The client** sees an O(log n) slice of the tree, its own history, and — this
is the part nobody else has — **what the value is supposed to be**. Only Alice's
device knows Alice's key did not change.

**The auditor** sees every entry, including the overwhelming majority no client
will ever query, and can therefore establish global well-formedness. It cannot
see search keys or values, so it cannot tell an authorised rotation from an
attacker's insertion.

**The witness** sees signed heads over time from an independent vantage, and —
if it compares with other witnesses — can establish that one history was shown
to everyone. It looks inside almost nothing.

| attack | client | auditor | witness | notes |
|---|---|---|---|---|
| L1 rollback | ✅ own stored head | ✅ | ✅ | any party retaining history |
| L2 fork | ⚠️ only vs its own past | ⚠️ signs once | ✅ **with gossip** | a single witness sees one view too |
| L3 targeted fork | ❌ | ❌ | ✅ **with gossip** | the victim has nobody to compare with |
| L4 entry rewriting | ⚠️ if it revisits | ✅ | ⚠️ **only if it opens entries** | head consistency cannot see it; our Signal ledger does |
| L5 omission | ✅ own updates | ❌ | ❌ | only the submitter knows it submitted |
| M1 key substitution | ✅ **own label only** | ❌ | ❌ | the auditor does not know whose key it should be |
| M2 silent overwrite | ✅ own label | ✅ | ❌ | construction proof catches the counter |
| M3 version skip | ✅ own label | ✅ | ❌ | |
| M4 removal | ⚠️ if it looks | ✅ | ❌ | |
| M5 per-label rollback | ✅ own label | ⚠️ | ❌ | client's stored version is the check |
| M6 selective omission | ✅ own label | ⚠️ | ❌ | |
| M7 padding abuse | ❌ | ⚠️ sees shape only | ❌ | auditor cannot distinguish real from fake |
| D1 auditor starvation | ❌ | ✅ **if it publishes** | ✅ | silence must be legible |
| D2 monitoring refusal | ✅ experiences it | ❌ | ❌ | |
| C1 server+auditor | ❌ | ❌ | ✅ **with gossip** | |
| C2 server+transport | ❌ | ❌ | ⚠️ independent transport only | |

Two conclusions fall out.

**No auditor can ever catch M1.** Key substitution against a user who never
checks is invisible to every party except that user. This is not a gap in any
implementation; it is what key transparency *is*. Auditing establishes that the
operator followed the rules, never that the answer is right.

**Every fork attack needs comparison, not just observation.** A witness that
records heads faithfully and never compares them with another party catches L1
and nothing else in the L2/L3/C1 family. Gossip is not a nice-to-have on top of
witnessing; it is the only thing that makes witnessing detect forks.

## Per ecosystem

For each: what the client checks, what a monitor *should* do, what this witness
can do today, and the gap between them.

### Signal

**The client** (`libsignal/rust/keytrans/src/verify.rs`) checks a great deal.
Per search: VRF proof, binary-search-proof well-formedness with monotonic
version counters, prefix-tree path, log batch inclusion, commitment opening,
the server's tree-head signature, timestamp within ±24h, consistency against
its own stored head and against the `distinguished` anchor, and — via
`SearchValue::check_equal` — that the returned value equals the identity key it
expected. Self-monitoring treats *any* version change as a hard failure. It
stores per-contact `StoredMonitoringData` so a later proof can be re-pinned to
the same VRF index, position and version.

**Signal's auditors** are load-bearing and mandatory. `rust/net/src/env.rs` maps
unconditionally to `DeploymentMode::ThirdPartyAuditing` with three hardcoded
production keys, and a head missing any of their fresh signatures is rejected as
`BadData`. Via `KeyTransparencyAuditorService.Audit` the auditor replays *every*
log entry as an `AuditorUpdate` (`NewTree | DifferentKey | SameKey`), keeps a
condensed prefix root and log frontier, and recomputes the map. That is real
construction auditing over entries no client will ever query. Signal is explicit
about the limit: auditors *"can't verify the accuracy of the recorded data"*.

**Gaps in Signal's own design:** there is **no gossip anywhere** — no peer root
exchange in libsignal, nothing in `key-transparency-server`. Anti-equivocation
rests entirely on auditors signing each `(size, root)` once, which the IETF
architecture draft calls out as a trust assumption: the mode *"require[s] an
assumption that the transparency log and the third-party manager or auditor do
not collude"*. So **C1 and L3 are undefended**.

| | |
|---|---|
| client covers | M1–M6 for its own labels, L1, L5 |
| Signal's auditors cover | L4, M2, M3, M4, M7 (shape) |
| **should** a witness do | independent head observation + **cross-witness comparison** → L2, L3, C1 |
| **can** we do today | tier A append-only; full search-proof verification for `distinguished` and one account; entry-immutability ledger across observations (L4) |
| **gap** | comparison. We hold an independent view but cannot yet contradict another party's, because no peer serves signed views |

Note we are **not** filling Signal's auditor role — it is filled and mandatory.
We are the independent observer that survives C1, which is the one thing Signal's
design assumes away.

### Apple

**The client** verifies inclusion of its own keys, cross-checked against an
E2EE CloudKit copy; inclusion proofs for peers at message time; append-only
consistency proofs on device; and a 48-hour Maximum Merge Delay on Signed
Mutation Timestamps. Out-of-band SAS verification codes let two users confirm a
binding directly, which substitutes for trusting the directory at all.

**Apple's auditor role is empty.** A "public auditing strategy in 2024" was
described and there is no evidence it shipped: no auditor API, no published
proofs, no follow-up since October 2023, and no ACKV section in the Platform
Security Guide. Apple states the consequence itself:

> there remains a set of consistency issues that can be detected only by
> third-party auditors

**Split-view defence** rests on self-monitoring, **Apple-transported sampled
gossip**, MASQUE anonymity on the PCC arm, and SAS codes. The second is C2 by
construction: the party carrying clients' views is the party being checked. The
Top-Level Tree gives a client self-consistency, not evidence that other clients
saw the same root.

| | |
|---|---|
| client covers | M1 for own keys, L1, peer inclusion at send time |
| Apple's auditors cover | **nothing — the role is unfilled** |
| **should** a witness do | construction audit of the iMessage map; independent head observation; gossip not transported by Apple |
| **can** we do today | PCC AT log fully verified (signed head, consistency, leaf reads, inclusion proofs with negative control). For iMessage: **heads only, as observations** |
| **gap** | the whole map layer. `list_trees` returns no IDS_MESSAGING tree; `log_inclusion_proof` rejects `application=IDS_MESSAGING`. Not a lack of effort — there is no surface |

This is the clearest case in the landscape: the operator names the missing role,
and publishes nothing that would let anyone fill it. `cmd/kt-unblock` watches for
the RPC that would change that.

### Meta — WhatsApp and Messenger

**The client** verifies a lookup with `akd_core::verify::lookup_verify`: the VRF
binds `(label, Fresh, version)` to a leaf label, the leaf hash is recomputed and
replayed to a root, the marker version exists, and the `Stale` label for that
version does **not** — proving the version returned is the freshest.

Two things it does *not* do, both load-bearing:

- **The `akd` crate checks no signature and never compares roots across epochs.**
  `root_hash` and `current_epoch` are inputs the application layer must obtain
  and trust. WhatsApp signs the root with a key baked into the app binary, and
  the client checks that — so the trust anchor is *Meta's own signature*.
  Whether the client pins or compares roots between epochs is **not documented**
  either way.
- **Key history is not enabled in clients.** The WhatsApp white paper states
  plainly that *"key history requests are not yet enabled in the current version
  of WhatsApp's clients"*. `key_history_verify` exists in the library and
  verifies exactly the chain that would catch a substitution — contiguous
  versions, stale labels for superseded ones, no hidden newer version — but as
  documented it is not running. No newer source contradicts this.

That second point is the most serious finding in this document. **M1 is the one
attack only the user can catch, and Meta's users are not equipped to catch it.**
The client's own-key check is limited to noticing its current key during an
ordinary lookup.

**Cloudflare's auditor** ingests the append-only proofs Meta publishes to a
public WORM bucket and asserts two things: epoch/digest global uniqueness, and
validity of each transition. `audit_verify` rebuilds the tree from
`unchanged_nodes` and requires the start hash, then from
`unchanged_nodes ∪ inserted` and requires the end hash — establishing that the
delta was insertions only, with no deletion or in-place rewrite, and that
inserted leaves carry the right epoch. Structure only: no VRFs, labels or
values, which is what makes the proofs anonymous.

Two caveats worth carrying:

- The signed attestation covers `{ciphersuite, namespace, timestamp, epoch,
  digest}` — **a single epoch, not a chain.** Non-equivocation is enforced
  *operationally*, by Cloudflare storing epochs in Durable Objects, not
  cryptographically by the signature.
- **The client never consumes the auditor's signature.** Users are directed to
  check it via a website or CLI. The cross-check is manual and out of band,
  which in practice means it does not happen.

There is no gossip.

| | |
|---|---|
| client covers | freshness of the version it fetched; **not** its own key history |
| Cloudflare covers | L4, M2, M3, M4 globally; epoch/digest uniqueness operationally |
| **should** a witness do | independent construction audit; independent uniqueness check; comparison with other observers |
| **can** we do today | tier A+ root-chain continuity across all published history; tier B construction audit, sampled at the tip and worked backwards through history by a fleet of verifiers; peer comparison for the logs we share |
| **gap** | M1 is unaddressed **by the design**, not by us. And our construction audit currently covers ~0.1% of published history |

### Proton

Proton is the mirror image of Meta, and the contrast is instructive.

**The client does the self-monitoring Meta's does not.** *Self Audit* fetches
every revision from the last verified one to the latest, **plus an absence proof
for `latestRev+1`** so the server cannot hide a newer malicious revision, checks
each Signed Key List's PGP signature, requires signature timestamps strictly
increasing (rollback prevention), and requires every key in each SKL to be
locally known. Users self-audit every active address. *Promise Audit* holds
values served before inclusion and checks they appear within a 72-hour maximum
merge delay.

**The trust anchor is external, not Proton's signature.** Each epoch computes
`chainhash_t = h(chainhash_{t-1} || roothash_t)` and Proton obtains a WebPKI
certificate whose SAN encodes it. The client requires **at least two SCTs from
two different CT log operators**. Equivocation would require forging a CT-logged
certificate.

The white paper is candid about the limits: clients **trust the SCTs and do not
scan CT logs**, and the chainhash chains epochs but *"does not guarantee that the
values in the tree are append-only. This needs to be verified separately."*

**Proton's auditor role is specified in detail and, as far as anyone can show,
vacant.** It is meant to check epoch contiguity, that each chainhash actually
appears in a CT log (*"must check the log, i.e. not simply trust the SCT"*),
that there is **exactly one `(epochid, chainhash, issuanceTime)` per epoch**,
update consistency by rebuilding each root from the last, and the deletion rules.
At last public review the implementation was *"still work-in-progress"*, and
there is no public auditor endpoint or dashboard. The white paper says clients
"trust that some External Auditor somewhere is scanning CT logs for
equivocation" — currently an assumption rather than an observed fact.

| | |
|---|---|
| client covers | M1–M5 for its own addresses, L1, promise-of-inclusion |
| Proton's auditors cover | **specified, not demonstrably deployed** |
| **should** a witness do | rebuild the tree; check epoch uniqueness in CT; check deletion rules |
| **can** we do today | full tree rebuild against the signed root, all 200,714,006 leaves, now recorded as audits; retention-window analysis of removals |
| **gap** | closed, mostly — see below |

**Update: three of Proton's specified auditor duties are now performed.**
`ConfirmInCT` already did the hard half — it rebuilds the CT Merkle leaf from
the precertificate and reads the entry through a tile reader authenticated
against the log's signed checkpoint, which is exactly the *"must check the log,
i.e. not simply trust the SCT"* requirement. Added since: the certificate
time-window rule (`|issuanceTime − notBefore| ≤ 24h`, without which
`CertificateTime` is a number Proton picks freely and folds into a name), and a
persistent epoch-commitment ledger that refuses a second differing
`(epochID, chainHash, issuanceTime)` and raises a fork. Persistence is the
point: an in-memory check only catches an operator that equivocates twice while
one process happens to be running.

On the deletion rules, one of the three is settled and two are not, for a
reason worth stating. `JudgeRemovals` settles *"only revisions superseded more
than 90 days ago"*: the window is published per epoch and each removed leaf
carries the epoch it entered, so a removal inside the window is a positive
contradiction.

The other two — latest revision never deleted, revisions deleted contiguously
from revision 1 — are about a label's revisions **as a set**, and one epoch's
diff does not contain that set. A gap in the revisions removed this epoch is
equally consistent with the missing revision having been removed legitimately
earlier. Calling that a violation would accuse Proton of something the evidence
does not show.

So `GroupRemovalsByLabel` gathers removals per address — possible because a
label is `VRF(email)[0:28] || revision`, and safe because the VRF is exactly
what stops the address being knowable — and reports irregular revision runs for
a human rather than judging them. Settling those two rules needs the label's
full revision set, which means the rebuilt tree, and is left until the
incremental auditor can supply it.

One empirical correction to the documentation: the white paper describes the
full leaf set as a *server-to-auditor* interface rather than a public
publication, and no public dump is documented. We nevertheless retrieve it — the
incremental auditor bootstraps a ~13.6 GB tree and applies ~3 MB diffs. So the
capability is real whether or not it is advertised.

## What this witness should do next

The per-ecosystem gaps are not evenly weighted.

1. **Gossip with signed peer views.** It is the only defence against L3 and C1,
   and *no* deployment surveyed here implements it — Signal has none, Meta has
   none, Proton assumes it, Apple transports its own. This is the single largest
   unclaimed role in the landscape.
2. **Proton epoch certificates in CT.** We already witness 69 CT logs. Checking
   that each Proton chainhash appears in them exactly once is the specific job
   Proton's design assigns an auditor and nobody is known to perform — and we
   are unusually well placed, since we hold both halves.
3. **Meta construction coverage.** Cloudflare already audits every epoch, so we
   are corroboration rather than sole cover; the value is independence, and
   independence is worth more at 10% coverage than at 0.1%.
4. **Apple** remains blocked on Apple.
