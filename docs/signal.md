# Signal

`signal.org/kt` — **tier A**, plus a continuously verified per-label spot check.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to Signal.

## What is peculiar

Signal is the deployment with **no published root**. The service tree's root is
never served by any endpoint. It is also, unexpectedly, the most *open* of the
five: its client-facing KT endpoints are unauthenticated by design.

## Three assumptions that were wrong

All three came from reading documentation instead of probing.

**"Signal needs operator coordination."** It does not. The auditor plane
(`audit.kt.signal.org`, batched updates, `SetAuditorHead`) is bilateral and
needs a Signal-issued client certificate — but the client plane is wide open.
The server actively *rejects* requests carrying credentials. Signal moved from
an outreach phase to a code phase on the strength of one probe.

**"Signal can only reach tier S."** Reconstructing the unserved service root
looked like it needed the whole combined-tree search proof. It does not; see
below.

**"The prefix tree is out of reach."** The full search proof for the
`distinguished` key ships inside the same response as the tree head. It costs
nothing extra to verify and had simply never been parsed.

## Deriving the root nobody publishes

Signal deploys in third-party-auditing mode with three auditors. Each response
carries one `FullAuditorTreeHead` per auditor: that auditor's Ed25519-signed
root at its **own** tree size, plus a consistency proof up to the service's
size.

The insight is that a consistency proof does not merely *check* a root — run
forwards, it **determines** one. So each auditor independently yields the
service root, and three checks have to line up:

1. every auditor's signature over its own root verifies;
2. all auditors derive the **same** service root — they start from different
   sizes with different proof lengths, so agreement is meaningful;
3. Signal's own signature verifies over the derived root. Signal emits one
   signature per auditor key, each binding that key into the preimage.

```
auditor A  size 854,943,976  ──24-hash proof──┐
auditor B  size 855,005,604  ──24-hash proof──┼──▶ same root ◀── Signal's
auditor C  size 855,020,838  ──24-hash proof──┘    8bf0f19b…      3 signatures
```

`MinAuditors` defaults to 2, so no single auditor can move the witness's view
alone. Auditors disagreeing is the one conclusive contradiction this adapter
raises — though the response alone does not say *which* auditor lied.

Per-auditor lag is logged explicitly. Once the three are collapsed into one
derived root it would otherwise be invisible, and it is operationally useful.

### Signature preimage

From libsignal `TreeHead::to_signable_header`:

```
[0,0] ciphersuite ‖ mode(3) ‖ len16‖signing_key ‖ len16‖vrf_key ‖
len16‖auditor_key ‖ tree_size u64be ‖ timestamp i64be ‖ root
```

For an auditor's own head, the signer and the embedded auditor key are the same
key. For the service's head, the signer is the service key and the embedded key
selects which of its signatures is being checked.

## Two trees, and why the log tree alone is not enough

Signal's log tree uses **RFC 9420** left-balanced numbering, not RFC 6962's:
leaves at even indices, a node's level being its count of trailing one bits, and
a 33-byte node encoding (`interior` byte ‖ 32-byte value) that makes leaf and
interior hashes non-interchangeable. `logtree.go` reimplements it.

But the log tree only records *that* the directory changed. What it says lives
in a second structure, and the two are joined at each log leaf:

```
log leaf = SHA-256( prefix_root ‖ commitment )
```

### The prefix tree

Fixed depth, 256 levels, one per bit of the index, most-significant bit first:

```
leaf   = SHA-256(0x00 ‖ index ‖ counter_be32 ‖ pos_be64)
parent = SHA-256(0x01 ‖ left ‖ right)
```

A proof is therefore *always exactly 256 sibling hashes* — a length the server
cannot choose, which removes a class of proof-padding tricks outright. The leaf
binds the version counter and the key's first log position, so it cannot be
replayed elsewhere or made to claim a different version count.

### The index is not chosen by Signal

The prefix-tree position is the **VRF output** of the search key
(ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381 suite 0x03; `internal/vrf`). The
operator can compute it, anyone can verify it, and nobody can enumerate the
directory from it.

That last property is why the directory is not published, and it is the root
cause of every coverage limit below.

## The search, and who drives it

A search for a key is a binary search over log entries, on an **Implicit Binary
Search Tree**: the same left-balanced numbering reinterpreted as a search tree
over `[pos, n)`.

The important part is that the path is **not sent — it is recomputed**. The
witness knows the key's first position and the tree size, which fix the search
root; each step's direction comes from the version counter found in the previous
step's prefix proof. A server-driven path would be worthless, because a
dishonest server would simply walk you to whichever entry it preferred.

> Signal chooses the answers. It never chooses the questions.

The guide also enforces that version counters are **monotonic** along the
search: a later log entry reporting fewer versions than an earlier one is
claiming a published version was withdrawn, which the format does not permit.

## What every fetch verifies

The `distinguished` key — the one label a third party can name without knowing
anybody's identifier — is opened on every poll. Four independent mechanisms
chain into one root:

```
 identifier "distinguished"
        │
        │ 1. VRF proof (RFC 9381)          Signal cannot choose the index
        ▼
    index 4ce05147bfc5637c…
        │
        │ 2. prefix proof, 256 hashes      the leaf sits here and nowhere else
        ▼
    prefix root ──┐
                  ├─ SHA-256 ─▶ log leaf
    commitment ───┘
        │
        │ 3. batch inclusion proof         these entries really are in the log,
        ▼                                  at positions we recomputed ourselves
    log root ═══ must equal ═══ the root three auditors and
                                Signal's signature already agree on
        │
        │ 4. commitment opening            and it is about this key, this value
        ▼
    "1788354440"
```

Step 3's equality is the acceptance test. The root arrives twice by completely
separate routes — once from auditors' consistency proofs, once from a search
through the prefix tree — and a wrong implementation does not reach agreement by
luck.

Measured live: tree size 855,024,016, index `4ce05147…`, version 3645, 31 log
entries opened. Six negative controls (one flipped byte in each of the VRF
proof, prefix proof, commitment, inclusion proof, opening nonce, and search key)
all fail.

The offline tests use libsignal's own vectors — commitments, `batch_copath`, and
the proof guide — so the reimplementation is checked against the reference
rather than against itself.

### Commitments

```
HMAC-SHA256(fixed_key, nonce ‖ len16(search_key) ‖ search_key ‖ len32(value) ‖ value)
```

The fixed key is a domain separator, not a secret; hiding comes from the
per-entry nonce, which Signal reveals only to someone who asked for that key.
The length prefixes are what stop a commitment being reinterpreted under a
different split of the same bytes.

## Between snapshots: the entry ledger

A log position is immutable once written. Nothing above can see a violation of
that — head consistency is blind to it by construction, and a single search
proof only ever describes one moment.

Two proofs taken at different times, both chaining to roots Signal signed, make
the comparison possible. So the witness records the leaf hash of every entry a
verified search opens, and refuses any later proof that contradicts one:

```
observation 1  (size 855,041,538)   entries { 7: h₇, 15: h₁₅, 23: h₂₃, … }
observation 2  (size 855,043,102)   entries { 7: h₇, 15: h₁₅', … }
                                                        ▲
                              entry 15 changed contents ─┘  contradiction
```

Verified live: two searches moments apart shared 32 entries, all cross-checked.

**It withholds rather than accusing.** The evidence would justify a fork claim,
but a fork is permanent and public and this is a fresh reimplementation of
somebody else's tree math; a bug here would libel Signal irreversibly.
Withholding costs Signal nothing and gets a human's attention. Promotion is in
[TODO.md](../TODO.md), after a production record.

**Known limit: the ledger is in memory.** A restart loses it, so
between-snapshot coverage is per-process — and deployment restarts containers.
It belongs in the store; also in TODO.

## Monitor proofs: not reachable by a witness

`MonitorProof` — "proves that a single key has been correctly managed in the
log" — looked like the natural between-snapshot check. It is not available.

Probing `/monitor` on production, through the pinned client:

| request | result |
|---|---|
| empty body | HTTP 422 · `"aci must not be null"` |
| `aci: "distinguished"` | HTTP 422 — rejected at the parser; ACI must be a UUID |
| well-formed but unknown ACI | HTTP 403 |

Confirmed against Signal-Server's `KeyTransparencyController`: the endpoint is
unauthenticated (it explicitly *rejects* authenticated callers) but takes only
`aci`, `e164` and `usernameHash`, each requiring an `entryPosition` and
`commitmentIndex` from a prior search. Monitoring needs an account. The entry
ledger stands in for it.

## Why the tier stays A

Signal's proofs are **per-label**. They answer questions about identifiers the
asker can already name, and the VRF exists precisely so a third party cannot
enumerate the rest.

So verifying every proof obtainable still examines a vanishing fraction of the
directory — unlike Proton, where the entire leaf set is published and the whole
tree can be rebuilt. Calling this tier B would claim coverage that does not
exist, and the beacon-sampling argument that works for Meta does not transfer:
sampling epochs is not sampling labels.

**Full coverage needs Signal's auditor feed**, which is bilateral. That is a
conversation, not code — and it is the sort of conversation that goes better
with an operating record behind it.

## Operational notes

- `chat.signal.org` does not chain to public roots. Signal's private CA is
  embedded (`signal-root.cer`, taken from libsignal `rust/net/res/signal.cer`)
  and **pinned** — not added to the system pool, so only Signal's own CA may
  authenticate this host.
- Production keys are pinned from libsignal `rust/net/src/env.rs` and
  cross-checked against the live wire. Signal's blog names Signal, Cloudflare
  and Trail of Bits as the auditors; which key belongs to whom is published by
  nobody.
- `deriveRoot` has a documented limit: when the old size is a power of two the
  old tree is a single full subtree, so its root is inserted directly with
  nothing to check it against. Callers must always compare the derived root
  against one authenticated another way — which both callers here do, via
  Signal's signature.
- Search verification is on by default (`SkipSearchProof` zero value is false),
  so it needs no configuration change. The flag exists only for fixtures that
  forge tree heads and therefore have no prefix tree to open.

## Sources

Reimplemented from libsignal `rust/keytrans/`: `prefix.rs`, `commitments.rs`,
`implicit.rs`, `guide.rs`, `log.rs`, `left_balanced.rs`, `verify.rs`, and the
wire definitions in `src/proto/`. Endpoint behaviour from
signalapp/Signal-Server `KeyTransparencyController.java`, confirmed by probing.
