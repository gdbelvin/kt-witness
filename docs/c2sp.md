# C2SP signed-note logs

`thelemail.com/keys` and any Sunlight-family log — **tier A**, or **tier B**
when entry verification is enabled.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to native C2SP logs.

## What is peculiar

These are the logs that need no bridge. Everything else in this project
canonicalises a KT epoch into a signed note; here the log already *is* a signed
note, and the witness ecosystem already knows how to talk to it.

That makes this adapter the reference point for the others — and the one place
where correctness can be checked against **other witnesses' signatures** rather
than only against the operator's.

## Verifying the ecosystem before joining it

Before writing an adapter, the target was corroborated: the C2SP
`cosignature/v1` format was reimplemented from spec and every signature line on
the live checkpoint verified.

| signer | keyid | alg | result |
|---|---|---|---|
| `thelemail.com/keys` | `76ead63c` | 0x01 Ed25519 note | ✅ over the checkpoint body |
| `witness.navigli.sunlight.geomys.org` | `a3e00fe2` | 0x04 `cosignature/v1` | ✅ |
| `witness.stagemole.eu` | `67f7aea0` | 0x04 `cosignature/v1` | ✅ |

Keys were fetched **independently** — stagemole from its own site, navigli from
`geomys.org/witness/navigli` — not taken from the checkpoint. Anyone can write a
known witness's name on a note line; only the signature settles it.

Two things came out of this. The log is corroborated by two real Sunlight-family
witnesses, so it is a genuine target. And a from-scratch cosignature
implementation agreeing with two independent witnesses is strong evidence the
core signing path is correct — which everything else in the project depends on.

## The cosignature format

```
alg     0x04
keyid   SHA-256(name ‖ "\n" ‖ alg ‖ key)[:4]
blob    keyid(4) ‖ timestamp(8) ‖ signature(64)
message "cosignature/v1\ntime <N>\n" + checkpoint body
```

The timestamp inside the signed message is what makes a cosignature a liveness
statement rather than a bare endorsement, and it is why unchanged logs are
re-signed hourly.

## Tier A: consistency computed locally

Consistency proofs are **computed from tiles**, not requested as proofs. The
tiles are bound to the signed root by the tile hash reader, so the proof is
built from data the log's own signature already covers.

This uses `filippo.io/torchwood` (`ParseCheckpoint`, `VerifyCheckpoint`,
`CosignatureSigner`, `TileFetcher`, `TileHashReaderWithContext`) and
`golang.org/x/mod/sumdb/tlog`. Inheriting the note format and consistency
machinery rather than writing them is most of why the core was cheap.

## Tier B: verifying the entries

With `verify_entries` set, the adapter also reads **data tiles** (level −1) and
checks that each added leaf's `tlog.RecordHash(entry)` matches the leaf hash
read *through the tile hash reader* — that is, through the path anchored at the
signed root.

That is a genuine construction audit: it proves the log grew by the entries it
published, not merely that it grew. For a small log it is nearly free, which is
why `thelemail.com/keys` runs at tier B continuously while Meta has to sample.

Entries within a data tile are framed with **2-byte big-endian length
prefixes**.

## Why keep a small log in the set

`thelemail.com/keys` is small — 93 entries at first contact — and that is
exactly what makes it useful:

- it is **fully replayable**, so tier B costs nothing and every entry can be
  checked every round;
- forks can be induced on demand against a locally run instance, which is how
  the refusal path is tested;
- it is cosigned by **other witnesses**, so our output can be compared against
  independent parties watching the same log. Nothing else in the set offers
  that.

It is the ecosystem's calibration target, not its most important log.

## Serving

This is also the adapter that closes the loop with the wider ecosystem:

```
GET  /<origin-hash>/checkpoint     C2SP monitoring endpoint
POST /add-checkpoint               accept pushes for native C2SP logs
```

The acceptance bar for the project is that existing tooling consumes this output
unmodified.

One unresolved detail: the server currently answers to **both** hex and unpadded
base64url encodings of `SHA-256(origin)`, because the spec text was never
confirmed. That should be pinned to one and the other dropped — see
[TODO.md](../TODO.md).

## The same-size race

The `tlog-witness` spec calls out a race where two conflicting checkpoints of
the same size are both accepted. The store's `CompareAndSet` performs the check
and the write inside **one bbolt transaction**, returning `ErrRaced` otherwise.
This requirement is the main reason the authoritative store is a transactional
database rather than the plain files that are actually published.

## Sources

C2SP `tlog-checkpoint`, `tlog-witness`, `tlog-cosignature`;
`filippo.io/torchwood`; and the live checkpoints of `tlog.thelemail.com`,
`witness.stagemole.eu` and `witness.navigli.sunlight.geomys.org`.
