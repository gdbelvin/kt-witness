# Open questions

Things deliberately left unresolved, with enough context to pick them up cold.

## Pin the canonical beacon round (and: solve it by gossip?)

**The gap.** Tier-B sampling draws whichever drand quicknet round is latest at
decision time and records it. A third party can verify that round's signature and
recompute our selection — but nothing specifies *which* round is legitimate for a
given epoch. Rounds are 3 s apart, so a dishonest witness could redraw until an
epoch it wanted to skip deselects (~10 draws at p=0.1). Published coverage is
therefore an honest-witness claim, not a cryptographically enforced one.

**The obvious fix** is to make selection a pure function of `(epoch, public
data)`: define the canonical round as, say, the first quicknet round after the
epoch's observed publication. drand rounds map deterministically to wall-clock
time, so this is checkable once specified. Belongs in the canonicalization spec
alongside the origin mapping.

**The better fix may be gossip.** Pinning a canonical round only removes *our*
freedom to grind; it does nothing about the deeper problem that a single witness
is a single point of trust, and it requires everyone to agree on when an epoch
was "observed" — which is itself a per-witness judgement.

If witnesses gossip their sampling records to each other instead:

- **Grinding becomes detectable without a canonical round.** Independent
  witnesses draw independent beacon rounds, so their selections are independent.
  A witness that consistently declines the epochs others verify — or whose
  claimed rate does not match its observed selections across many epochs — stands
  out statistically. No single canonical round needs agreeing on.
- **Coverage composes.** Ten witnesses at p=0.1 each, sampling independently,
  give ~65% union coverage per epoch rather than 10%. The security argument
  strengthens with participation instead of requiring any one operator to fund
  204 GB/day.
- **It is the ecosystem's existing answer to split views anyway.** CT gossip
  (draft-ietf-trans-gossip) exists precisely so no participant has to be trusted
  individually. Sampling records are a natural thing to carry over the same
  channel as checkpoint views.

Open sub-questions: what exactly gets gossiped (full audit records, or just
`(epoch, sampled, beacon_round)` tuples?); whether the existing witness network
has any appetite for carrying non-checkpoint data; and whether the statistical
grinding test is strong enough to be worth stating as a security property rather
than a heuristic.

Worth raising with other witness operators before writing the spec — the answer
may be that gossip subsumes the canonical-round question entirely.

## Pin the tlog-witness origin-hash encoding

`internal/server.originHashes` accepts both hex and unpadded base64url of
SHA-256(origin), because the exact encoding in c2sp.org/tlog-witness has not been
confirmed against the spec text. Accepting both is a compatibility hedge, not a
design. Pin it and drop the other before publishing the endpoint for real.

## Meta: signature verification is unavailable

Meta's epoch signing key is not published anywhere reachable, so tier A+/B
attests our *observation* of the root chain, not Meta's signature over it. If a
key ever becomes available (or Cloudflare's auditor key is published in a
verifiable form), the AKD adapter should verify it and `DerivedHead()` should
become false for that source — which would also restore the stronger conclusive
treatment of head regressions in the witness core.

## Signal: what remains after tier A

Append-only is proven by deriving the service root from the auditors'
consistency proofs, and the **prefix tree is now verified too** — every poll
opens the `distinguished` key and checks VRF, prefix proof, batch inclusion and
commitment against that same root. See [docs/signal.md](docs/signal.md).

The tier stays A anyway, and the reason is the thing to remember: unlike Meta's
AKD proofs, Signal's search proofs are **per-label**, and the VRF exists
precisely so a third party cannot enumerate labels. So the sampling argument
that makes Meta's tier B meaningful does not transfer — sampling epochs is not
sampling labels — and no number of spot checks adds up to coverage. Full
coverage needs Signal's auditor feed, which is bilateral.

What remains reachable without Signal's cooperation is mostly durability:
the cross-observation entry ledger is in memory and should live in the store.

### Attribution in a Signal incident

Signal is now witnessed as one origin (`signal.org/kt`), not three, because the
three auditors are cross-checked into a single derived service root rather than
tracked separately. That makes attribution *better*, not worse:

- An auditor whose signed root fails its own consistency proof is identified by
  key in the error — the fault is that auditor's.
- Auditors whose roots are individually valid but imply different service roots
  produce the disagreement fork. At least one signed a root from a different
  history, and the response does not say which; the recorded evidence is the
  whole raw response so a third party can reach their own conclusion.
- A missing or wrong service signature over the derived root implicates Signal,
  not an auditor.

Say which of those three it was before disclosing anything.

## IETF keytrans: deliberately skipped

draft-ietf-keytrans-protocol-05 specifies data structures and cryptographic
computations but explicitly *no transport* (§2.1), and no public service speaks
it. Every real deployment invents its own binding (Signal: gRPC/protobuf+mTLS;
Cloudflare plexi: REST/JSON), so there is nothing to be conformant to on the
wire. The draft's auditor is also a stateful push consumer that replays every
log entry — a different shape from a pull-based witness. Revisit when a public
deployment exists.

## Apple: inclusion proofs (superseded — see docs/apple.md)

This section previously concluded, at length, that `at_researcher/log_inclusion_proof`
"does not accept any inclusion request we can construct" and that Apple's auditor
service "has no generic log-inclusion RPC". **Both claims were wrong**, and the
correction is worth keeping visible rather than quietly deleting, because of how
the mistake was made.

The endpoint takes `ATLogInclusionProofRequest{version, application, identifier}`
from `ATResearcherApi.proto` — a message the earlier hunt never tried, having
concentrated on `RevisionLogInclusionProofRequest`. And `application` must be
`PRIVATE_CLOUD_COMPUTE (5)`. The earlier probes swept values 0–3, so they missed
the one that works by two.

It is verified live: a leaf read from the PCC Apple Transparency log, a proof
requested by SHA-256 of its raw data, and a 16-hash path checked against a head
verified under that log's own key — with a negative control. Consistency proofs
work too. Apple hashes RFC 6962 style, as the old note correctly guessed.

The old note also treated `logLeavesForRevision`'s 404 as unexplained. It is
explained: Apple publishes an unauthenticated init bag listing the deployed
researcher endpoints, and that endpoint is not in it. **Apple's protos describe a
superset of what is deployed** — read the bag, not the schema.

iMessage is still not attestable, but now for a stated reason rather than a
symptom: `list_trees` returns the same three trees for every application value,
none of them IDS_MESSAGING, and `log_inclusion_proof` rejects
`application=IDS_MESSAGING` with `INVALID_REQUEST`.

Full detail, including every endpoint and identifier, is in
[docs/apple.md](docs/apple.md).

The generalisable lesson: a negative result about an API is only as good as the
input space that was swept, and "we tried many shapes and all failed" is much
weaker evidence than it feels like at the time.

## Blocked ecosystems

- **Google keytransparency** — archived 2024-10-11, no live deployment.

## Why construction auditing is the one that matters

Worth stating plainly, because tiers A and A+ look reassuring and are not
sufficient on their own.

A consistent chain of epoch hashes proves the operator did not rewrite the
*sequence* of commitments. It says nothing about whether each tree was derived
from the previous one legally, because a key directory is a mutable map. Removing
a binding, overwriting one without bumping its revision, or inserting at a
skipped revision all leave the epoch chain perfectly consistent and every
consistency proof valid.

Proton epoch 6709: 36,520 additions and **9,337 removals**. Roughly a fifth of a
single epoch's mutations are deletions, invisible from the chain.

Only tier B sees any of it. Today that is Meta (sampled) and Proton (one-shot,
validated). Signal, Apple and thelemail are head-consistency only, and Signal is
the most consequential gap.

Two things about Proton's tree that are easy to get wrong and were confirmed
against its C verifier rather than assumed: path bits are read **MSB-first**
(the header comment in merklenode.h says LSB-first and is wrong — the code in
node_is_next_sibling keeps the top bits), and an empty subtree is **32 zero
bytes at every depth** rather than a per-depth empty hash. The second is why a
lonely leaf costs one hash per level, and why the rebuild is ~46 billion
compressions.
