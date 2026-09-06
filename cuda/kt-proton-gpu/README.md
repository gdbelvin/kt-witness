# kt-proton-gpu

Rebuilds Proton's key-directory root from a published epoch dump, on an NVIDIA
GPU.

## Why a full rebuild at all

Between epochs the right thing is an incremental update: a 7.5 MB diff changes
~108,000 of ~201 million leaves, and recomputing only the affected paths is
several orders of magnitude cheaper than rebuilding.

But an incremental chain carries its own state forward. If the retained tree is
ever wrong — a bug, a partial write, a corrupted block — every subsequent epoch
inherits the error, and each one still "verifies" against the next diff. Only a
rebuild from the published leaves re-anchors it. That is what this is for:
occasional, independent, and cheap enough that there is no excuse to skip it.

## The invariant

**A mismatch reported here is not evidence of anything.**

In this system a root that does not match the one Proton signed reads as the
operator misbehaving, which is the strongest finding the project can make. A GPU
is not an appropriate thing to make it on. So:

> If this program's root differs from the signed root, rebuild on the CPU and
> let the CPU decide. Never report, store, or act on a GPU mismatch directly.

The asymmetry is what makes the acceleration safe. A false mismatch costs one
CPU rebuild. A false *match* would require the GPU to land on Proton's signed
hash by accident, which is not a failure mode hardware has.

## What runs where

The per-leaf fold is 99.6% of the work and is perfectly parallel — 201M
independent chains of ~228 dependent hashes — so it runs on the GPU.

Assembling the folded nodes into a root is n-1 joins plus a lift wherever a
node's sibling subtree is empty. It is level-synchronous and a small fraction of
the cost, so it runs on the host with OpenMP, where it is simple enough to read
and check by eye.

## Measured on an NVIDIA A10 (24 GB, sm_86)

Real data: Proton's published dump for epoch 6730, 13,684,711,068 bytes,
201,245,751 leaves. **The root matched the tree hash Proton signed for that
epoch**, `b17a131948e58dd5139a036937311bc0d6d488829e5e3bc03fe4aa635ab4dfb6`.

| phase | time |
|---|---|
| upload 13.7 GB to VRAM | 5.8 s |
| **fold kernel** (41.8e9 hashes, 0.97 GH/s) | **43.2 s** |
| download 6.4 GB of node hashes | 9.2 s |
| assembly (first version) | 600.2 s |
| total | 658.3 s |

The kernel did its job; the assembly did not. It performed **1.8 billion lifts
against 201 million joins** — the empty-sibling case is not a rare correction,
it is 90% of the interior work — and a level-at-a-time sweep visited every live
node at all 256 levels to find them. That is the rewrite described above the
`assemble` function: lift each node straight to its pairing depth, ~28 rounds
instead of 256 sweeps.

Optimisations tried that did **not** help, so nobody pays for them twice:
two leaves per thread to hide round latency (1.05 → 1.06 GH/s — the kernel is
throughput-bound, not latency-bound); a rolling 16-word message schedule
instead of the full 64-word one (identical; nvcc had already made that choice);
block sizes from 128 to 512 (no difference). What did help: precomputing the
padding block's message schedule, which is identical for all 45.9 billion
hashes, and compiling the host assembly with `-Xcompiler -O3 -fopenmp` — `nvcc
-O3` alone optimises only device code, which is easy to miss and cost 3.4× on
the assembly pass.

## Correctness

`internal/source/proton`'s `TreeRootParallel` is the specification. The Go test
`TestWriteGPUVector` emits a synthetic dump plus the root that package computes
for it:

```sh
KT_GPU_VECTOR=/tmp/vec.bin KT_GPU_VECTOR_N=2000000 \
  go test ./internal/source/proton/ -run TestWriteGPUVector -v
```

The host SHA-256 here is written separately from the device one on purpose: two
implementations agreeing is weak evidence when they share source.

## Build and run

```sh
make                      # ARCH=sm_86 by default
./kt-proton-gpu <dump>    # prints JSON: root, timings, hash counts
```

The dump is Proton's published leaf set, `https://proton.me/kt/epoch.1.<epoch>`,
which is 13.7 GB. The whole thing is resident in VRAM during the fold, so the
card needs ~21 GB for a tree this size.
