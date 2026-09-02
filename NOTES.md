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

Append-only is now proven (see the README), by deriving the service root from the
auditors' consistency proofs. What is still unverified is the **prefix tree**:
that each identifier-to-key binding sits where it should. That needs ECVRF
evaluation and the combined-tree search proof from `SearchResponse`, and is the
Signal analogue of tier B — the point at which we would be auditing construction
rather than witnessing heads.

Worth knowing before starting it: unlike Meta's AKD proofs, Signal's search
proofs are per-label, so a construction audit would sample *labels*, not epochs,
and the sampling argument would need rethinking from scratch.

### Attribution in a Signal incident

The three Signal auditors are witnessed as three separate origins, so a fork is
recorded against whichever origin observed it. That is right when an *auditor*
equivocates. But if Signal's *service* tree forked, the evidence would land on
whichever auditor origin we happened to see it through, and `/forks` would read
"auditor X forked" when the story is "Signal's tree forked, seen via auditor X".
Before disclosing anything here, check whether the other two origins show the
same contradiction — agreement across auditors points at the service, divergence
points at the auditor.

## IETF keytrans: deliberately skipped

draft-ietf-keytrans-protocol-05 specifies data structures and cryptographic
computations but explicitly *no transport* (§2.1), and no public service speaks
it. Every real deployment invents its own binding (Signal: gRPC/protobuf+mTLS;
Cloudflare plexi: REST/JSON), so there is nothing to be conformant to on the
wire. The draft's auditor is also a stateful push consumer that replays every
log entry — a different shape from a pull-based witness. Revisit when a public
deployment exists.

## Blocked ecosystems

- **Apple ACKV** — verification is client-only by design; public auditing was
  described as "planned" in 2024 with no evidence it shipped. Nothing to witness.
- **Google keytransparency** — archived 2024-10-11, no live deployment.
