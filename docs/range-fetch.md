# Fetching only `inserted` — proposed, measured, refuted

**Status: does not work. Kept because the refutation is more useful than the
idea was, and because the measurement that kills it is cheap to re-derive
wrongly.**

The proposal was to stop downloading `unchanged_nodes` — 92% of every proof's
bytes — on the grounds that it is the previous epoch's tree, which a verifier
that just did epoch E-1 already holds. A verifier would carry its tree forward,
fetch `inserted` alone by HTTP range request, and merge.

It rests on a false premise. `unchanged_nodes` is **not** the previous tree.

## What was true

Both of these hold and are worth keeping:

- **CloudFront honours range requests.** `accept-ranges: bytes`, HTTP 206, exact
  `content-range`. Verified against WhatsApp's distribution on 2026-09-11.
- **`inserted` is at the front and its extent is discoverable from a prefix.**
  prost writes fields in number order and `SingleAppendOnlyProof` has
  `inserted = 1`, so `akdtree.ScanLeading(prefix, 1, 0)` found the boundary at
  byte 3,580,680 of a 46,676,236-byte proof — 7.67% — inside a 4 MB fetch, with
  `ended=true`.

So the *fetching* half was sound. The verification half was not.

## What was false

`unchanged_nodes` is the **sibling frontier** for this epoch's insertions, not
the tree. Measured on two consecutive real WhatsApp proofs:

| | inserted | unchanged | inserted share |
|---|---|---|---|
| epoch 1,181,000 | 47,745 | 902,146 | 5.03% of elements |
| epoch 1,181,001 | 45,053 | 855,759 | 5.00% of elements |

19 unchanged nodes per inserted node is the shape of `O(k·log(n/k))` sibling
hashes, not of a tree with a billion leaves. **The operator is already sending
close to the minimum.** There is no redundancy to compress out, which was the
objection that prompted the test.

The frontier also depends on *where this epoch's insertions landed*, so it is
different every epoch. Two consequences, both measured:

**The sets differ.** With `S_E = unchanged_E ∪ commit(inserted_E, E)`:

```
Root(S_E)             = 64faba15d9c66524     <- equal, as they must be
Root(unchanged_{E+1}) = 64faba15d9c66524
|S_E| = 949,891   |unchanged_{E+1}| = 855,759   ratio 0.901
SETS IDENTICAL: false
```

Same root, different sets — 10% different. Not a hash collision: a compressed
trie deliberately collapses an untouched subtree into one node, so a set of
subtree roots and the set of leaves beneath them produce the same digest.

**This is exactly the step the soundness argument rested on**, and it is wrong.
The argument said: any `unchanged_{E+1}` passing today satisfies
`Root(unchanged_{E+1}) == Root(S_E)`, therefore under collision resistance the
two sets are equal. They are not equal, and collision resistance has nothing to
say about it, because `Root` is not injective over element sets by construction.

**And the substitution fails outright.** Carrying `S_E` forward and merging
epoch E+1's insertions:

```
Root(merge(S_E, commit(inserted_{E+1}, E+1)))
  = akdtree: element with label length 16 sits on the interior node covering it;
    a committed value would be dropped
```

`S_E` carries a collapsed subtree root at label length 16. Epoch E+1 inserts a
leaf *inside* that subtree. The merged set then contains both an interior node
and something beneath it, which `Root` rejects — correctly, and by the check
that exists precisely to stop a committed value being silently dropped.

The frontier a verifier holds was chosen for the previous epoch's insertions. It
is the wrong shape for the next epoch's, and nothing short of the full tree —
which a witness never receives — is the right shape for all of them.

## What survives

- **`ScanLeading` and the range-request finding** stay true and may be useful for
  something else. Nothing in the code changes.
- **The bandwidth problem is unchanged.** 154 TB is close to irreducible at this
  witness's end; the levers are the link, a worker on a fatter one, or asking the
  operator for bulk access.
- **The canary reasoning is untouched.** It defends against a worker that derives
  `curr_E` from `unchanged_{E+1}`, and both sets are still fetched in full.

## One thing worth asking an operator

A single append-only proof from E to E+N costs one frontier instead of N, so the
frontier's cost amortises. Meta and WhatsApp publish one proof per epoch; they
could publish periodic long-range ones alongside.

It proves something **weaker** — that everything in E survives to E+N, not that
each intermediate step was append-only, so an insert-then-remove inside the
window would pass. It is not a substitute for per-epoch verification, but it
would let a bandwidth-constrained witness establish a coarse guarantee over
history it cannot otherwise afford to check at all, and refine later.

## The lesson worth keeping

The premise was checkable in about twenty minutes — download two consecutive
proofs, decode, compare — and the design document was written before doing it.
The argument was internally valid and rested on a claim about the data that was
never measured. `docs/gpu_notes.md` records the same shape of error: a GPU
verifier that would have been correct, fast, and pointed at 7% of the problem.

Measure the premise first.
