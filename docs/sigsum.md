# sigsum

## The short version

sigsum was carried in TODO.md as a judgement call: it has its own protocol and
its own witness network, so the question was whether to reimplement it or to
join. Reading `sigsum-go` dissolved the question. Neither is necessary.

Modern sigsum signs a **C2SP checkpoint body**:

```
sigsum.org/v1/tree/<hex sha256(log public key)>
<size>
<base64 root hash>
```

with **plain Ed25519** — no SSH signature wrapper, no prehashing — and its
cosignatures are literally `cosignature/v1`, the construction this project
already implemented and verified against two independent witnesses during
Phase 0.

So sigsum is not a third ecosystem. It is a note-carrying log wearing an ASCII
transport, and the adapter is a transcoder rather than a verifier.

Source: `sigsum-go/pkg/types/tree_head.go` — `FormatCheckpoint`,
`SigsumCheckpointOrigin`, `CosignatureNamespace = "cosignature/v1"`.

## The transport

Everything is `key=value` lines. `GET /get-tree-head`:

```
size=63886
root_hash=fff04be474522157c37d6ab214515ed4b92caadd279e831b7b1491641cf07276
signature=e4fb7b4e...
cosignature=<witness key hash> <timestamp> <signature>
cosignature=...
```

`GET /get-consistency-proof/<old>/<new>` returns the proof as ordered
`node_hash=<hex>` lines. sigsum uses RFC 6962 Merkle hashing, which is the same
construction `golang.org/x/mod/sumdb/tlog` implements, so the node list feeds
`tlog.CheckTree` directly with no conversion.

## Why the note is synthesized

sigsum does not serve its checkpoint in note form. The adapter rebuilds it.

That is safe here, and the reason is worth stating because "reconstruct the
thing you are about to verify" is normally an anti-pattern. The body is **fully
determined** by data we did not choose: the origin is a pure function of the
log's *pinned* public key, and the size and root come from the response whose
signature is then checked against that reconstruction. If any of the three were
wrong, the Ed25519 check would fail. The note is a re-encoding of verified data,
never a claim we invented.

The payoff is that everything downstream — cosigning, the store, publication,
the status page — treats sigsum identically to every other log. No sigsum-shaped
special case propagates past the adapter boundary.

## Identity is derived, not configured

The origin is `sigsum.org/v1/tree/` + hex SHA-256 of the log's public key. A log
cannot pick a name that collides with another's, and an operator cannot point
the adapter at a log without naming which log it is.

The config therefore takes `log_key_hex` and validates any configured `origin`
against the one the key implies, failing loudly on a mismatch. Pinning a key for
a different log than you think you are watching is a plausible mistake and a
silent one, so it is worth an explicit error.

Keys come from sigsum's built-in trust policies in `sigsum-go`:

| log | key | source policy | witnessed |
|---|---|---|---|
| `seasalp.glasklar.is` | `0ec7e168…841f25` | `sigsum-generic-2025-1.builtin-policy` | yes |
| `ginkgo.tlog.mullvad.net` | `f00c1596…e38314` | `sigsum-generic-2025-1.builtin-policy` | yes |
| `serviceberry.tlog.stagemole.eu` | `47e48160…abce39` | `sigsum-test-2025-3.builtin-policy` | test only |
| `test.sigsum.org/barreleye` | `4644af2a…0a5fe6` | `sigsum-test-2025-3.builtin-policy` | test only |

They are pinned in code, not fetched. A key fetched at runtime from the same
party that operates the log proves nothing: the log could serve whichever key
matches whatever history it wants to show.

**Only the two production logs are witnessed.** The other two come from sigsum's
*test* policy, and this project already excluded the `test.*` CT namespaces for
the same reason: a witness's published surface is a statement about what it
considers worth watching, and staging logs dilute it. They stay in the live test
suite, where exercising the adapter against more real deployments is pure gain,
and out of the deployed config, where an attestation about a throwaway log is
noise.

Every key above was confirmed by checking it actually verifies a signature on a
live head before the log was added — a key that merely appears in a policy file
is a claim, and pinning one unchecked would mean witnessing a log under an
origin nobody else computes.

## Assurance: tier A

sigsum serves consistency proofs, so append-only between observations is proven
and a failure is a genuine self-contradiction by the log — the adapter raises
`*source.ForkError` for it, which is never retried and triggers disclosure.

There is no higher tier to reach. sigsum is an append-only log of signed
checksums, not a key directory: there is no mutable map to rebuild, so "the tree
grew append-only, and every leaf is one the log published" is the whole of the
claim. That is a structural property of sigsum, not a limit of this adapter.

Cosignatures on the tree head are parsed and retained as **corroboration only**.
Like every cosignature read off a document we fetched ourselves, they sit over
the same body as the log's own signature and agree by construction; they cannot
detect a split view. See `internal/cosig` for why that distinction matters.

## Testing

`sigsum_live_test.go` runs against production and asserts three things: the
origin derives correctly from the pinned key, the log's signature verifies over
the reconstructed body, and the synthesized note opens under a stock note
verifier.

The third is the one that matters — it is the difference between "we can check
sigsum's signature" and "sigsum is indistinguishable from any other log to
everything downstream".

There is also a **negative control**, and it is not decoration. The positive
consistency test passes vacuously whenever the log has not grown since its
anchor was pinned: `VerifyConsistency` returns early when the sizes match, so
`CheckTree` never runs and a broken proof path would look exactly like a working
one. Both logs were in that state when the adapter was written. Corrupting the
anchor root forces the proof path to execute, and pins the error *type* —
a root the log never signed must surface as a fork, not as a retryable error,
because that difference decides whether the witness withholds quietly or
discloses publicly.
