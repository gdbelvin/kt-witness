# Fetching only `inserted`

**Status: design, not built. The soundness argument below is the part that needs
review — it changes what "verified" means, and everything else is engineering.**

Bandwidth is the binding constraint on this witness. The remaining backlog is
889,031 epochs and about 154 TB, against a residential line measured at ~885
Mbit/s, which is roughly three weeks even with the link entirely to itself. This
proposes downloading 7.67% of that.

## The measurement it rests on

Two facts, taken against WhatsApp's live CloudFront distribution on 2026-09-11:

```
$ curl -sI .../1181000/d36fa36f.../64faba15...
HTTP/2 200
content-length: 46676236
accept-ranges: bytes

$ curl -H "Range: bytes=0-4194303" ...
HTTP/2 206
content-range: bytes 0-4194303/46676236
```

Range requests are honoured. And running `akdtree.ScanLeading(prefix, 1, 0)` over
that 4 MB prefix:

```
field 1 run ends at 3580680  complete=true
=> inserted is the first 3,580,680 bytes = 7.67% of the proof
```

So `inserted` sits at the front — prost writes fields in number order, and
`SingleAppendOnlyProof` has `inserted = 1`, `unchanged_nodes = 2` — and its
extent is discoverable from a prefix. The other **92.33% is `unchanged_nodes`.**

`ScanLeading` already exists, with a doc comment describing exactly this caller:
"measures the run of records of one field at the front of a proof, for a caller
that holds only a prefix of it."

## What `unchanged_nodes` is

It is the previous epoch's tree. Verification today is:

```go
prev = Root(sort(unchanged))
curr = Root(merge(sort(unchanged), sort(commit(inserted, E))))
```

and the caller checks `prev == published_prev_E` and `curr == published_curr_E`.

Because the published roots chain, `published_prev_E == published_curr_{E-1}`.
So the first line is asserting that the operator's `unchanged` set rebuilds a
root we have **already computed ourselves**, if we verified epoch E-1.

We are spending 92% of our bandwidth re-downloading a set we can reconstruct.

## The proposal

Verify a contiguous run ascending, carrying the tree forward.

Let `S_E` be the sorted element multiset the verifier built for epoch E — the
`both` slice inside `Roots`, whose root it checked against `published_curr_E`.

For epoch E+1, fetch **only `inserted_{E+1}`** and compute:

```
curr_{E+1} = Root(merge(S_E, sort(commit(inserted_{E+1}, E+1))))
```

Check it against `published_curr_{E+1}`. No `unchanged_{E+1}` is fetched, and
`prev_{E+1}` needs no computation: it is `published_curr_E`, which we verified
last round.

Each run needs one full proof to seed it; every epoch after that costs 7.67%.

## Soundness

**Claim.** If `Root(S_E) == published_curr_E` and
`Root(merge(S_E, commit(inserted_{E+1}, E+1))) == published_curr_{E+1}`, then the
epoch E→E+1 transition is append-only, and the conclusion is no weaker than
what the current scheme establishes.

**What append-only means here.** That the tree published at E+1 contains every
node of the tree published at E, plus additions that are committed to E+1. The
proof format's way of asserting this is to hand over the two sets separately and
let the verifier rebuild both roots.

**Argument.** The construction exhibits a set `S_{E+1} = S_E ∪ commit(inserted_{E+1})`
with `S_E ⊆ S_{E+1}` by construction — `merge` is a union, it removes nothing —
and `Root(S_{E+1}) == published_curr_{E+1}`. Combined with
`Root(S_E) == published_curr_E`, that is precisely the statement: the tree behind
the published root at E+1 contains the tree behind the published root at E, plus
elements committed to E+1. Containment is not inferred from anything the
operator said; it is a property of the set we built.

**Why it is not weaker.** The current scheme obtains `S_E`'s role from the
operator's `unchanged_{E+1}`, checked only by `Root(unchanged_{E+1}) ==
published_prev_{E+1}`. Since `published_prev_{E+1} == published_curr_E ==
Root(S_E)`, any `unchanged_{E+1}` that passes today satisfies
`Root(unchanged_{E+1}) == Root(S_E)`. Under collision resistance of the tree hash
(BLAKE3, WhatsAppV1Configuration), `unchanged_{E+1} == S_E` except with
negligible probability.

So the current scheme is the proposed one *plus* a redundant round-trip through
a collision-resistance assumption. Substituting `S_E` removes that assumption
from the chain rather than adding one.

**Why it is arguably stronger.** Today, `unchanged` is the operator's claim
about the previous tree, and we accept it on a hash match. Under the proposal
the previous tree is the one we built and checked. An adversary who found a
second preimage for a subtree root could pass today's check with a set that is
not the real previous tree; they could not pass the proposed one, because we
never consult their set.

**What it does not weaken.**

- *Per-epoch root agreement* is unchanged. Every epoch's published current root
  is still independently reconstructed and compared.
- *Duplicate labels are still caught.* If a label in `inserted_{E+1}` collided
  with one already in `S_E`, `Root` errors — an element whose label terminates at
  an interior node is rejected explicitly ("a committed value would be dropped"),
  rather than silently deduplicated. So a re-insertion masquerading as an
  addition fails loudly.
- *The seed epoch* is verified the current way, in full.

**What it genuinely gives up.** Today each epoch re-derives the previous root
from freshly downloaded bytes, which would catch corruption of our own in-memory
tree. Under the proposal an undetected bit-flip in `S_E` propagates to every
later epoch in the run. Mitigation: runs are bounded (a few hundred epochs), and
the run's final root is still checked against a published value, so corruption
surfaces as a mismatch at the next epoch rather than passing silently. It
becomes a liveness/false-alarm risk, not a soundness one — and a mismatch already
triggers local re-verification.

**The dependency it introduces.** A run's later epochs depend on its earlier
ones being correct. This is a *sequential* dependency inside one worker, not a
trust relationship between machines: each worker seeds its own run from a full
proof it fetched and verified itself. No worker takes another's word for
anything, which is the property the whole work channel is built to preserve.

## Effect on the canary

It survives, and gets sharper.

The canary exists because a worker holding proofs for E and E+1 can shortcut:
`curr_E == prev_{E+1} == Root(unchanged_{E+1})`, so it can report two correct
roots for E without ever reading `inserted_E`. The canary answers this by
flipping a bit inside `inserted` — the region the shortcut skips.

Under the proposal `inserted` is *all the worker receives*. There is no
`unchanged` to derive an answer from, so the shortcut has no input. A flipped
bit in the only bytes it has still produces a wrong root, so the canary still
fires — and the thing it was defending against is now structurally impossible
rather than merely detectable.

The witness must serve the range rather than the whole proof, and must corrupt
within it. `PayloadOffset` already restricts flips to payload bytes.

## What it costs to build

**The generator must descend in ascending runs.** Today `cursors.backward`
walks down, one epoch at a time, selecting with `FirstUnverified`. A run needs
the *opposite* order internally: pick a window, seed at its bottom with a full
proof, then walk up. The descent across windows stays; the order within a window
inverts.

**Memory per concurrent run**, from measured proof sizes at 68 bytes per
in-memory `Element`:

| log | `unchanged` wire | elements | tree held | with merge scratch |
|---|---|---|---|---|
| whatsapp | 43 MB | 0.80 M | 54 MB | 109 MB |
| meta | 262 MB | 4.87 M | 331 MB | 662 MB |

So concurrency becomes ~10–15 Meta runs against the 44 GB container limit,
rather than 26 independent epochs. Fewer, longer-lived units of work — which
suits the queue, since it already hands out contiguous ranges.

**Fetching needs a prefix loop.** Ask for a generous prefix (9% plus slack),
run `ScanLeading`; if it reports the run incomplete, fetch more and resume from
the returned offset. `ScanLeading` is built for exactly this and takes `from`
for the purpose.

**Assignment semantics change.** A run is a chain: a worker that drops out
mid-run invalidates the rest, where today each epoch stands alone. The lease
already covers a contiguous range, so the unit is right, but partial-completion
accounting needs thought.

## What it is worth

154 TB → **~12 TB**. At the current 600 Mbit/s cap that is under two days
instead of twenty-four, and it removes the argument for uncapping the link at
all.

## Open questions for review

1. Is the collision-resistance argument above the right frame, or is there a
   property of `unchanged_nodes` I am treating as redundant that is not? This is
   the question that decides the whole thing.
2. Does AKD ever *change* a node's value between epochs without changing its
   label? The proposal assumes node-level append-only — that a label, once
   present, keeps its value. `Root`'s duplicate rejection means a violation
   fails loudly rather than silently, but if it happens routinely the design is
   wrong rather than merely noisy.
3. Should the seed epoch of each run be chosen adversarially (beacon-randomised)
   rather than at the window edge, so an operator cannot predict which epochs
   get a full independent check?
4. Is a bounded run length the right mitigation for in-memory corruption, or
   should `S_E` be re-derived from a full proof every N epochs regardless?
