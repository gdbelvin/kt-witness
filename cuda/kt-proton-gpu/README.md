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
| read + upload labels | 9.2 s |
| fold kernel (41.8e9 hashes) | 45.3 s |
| assembly, 38 rounds | 5.6 s |
| **total** | **60.1 s** |

Four versions to get there, and the cost model was wrong at every step except the
last. Recorded because the wrong guesses were each plausible.

**658 s.** Fold on the GPU, assembly on the host, one level at a time. Assembly
was 600 s of it — the empty-sibling lift turned out to be **1.8 billion
operations against 201 million joins**, and sweeping 256 levels re-visited every
live node to find them.

**279 s.** Lift each node straight to its pairing depth — a node acquires a
sibling at `max(lcp_left, lcp_right) + 1`, the same rule that places a leaf — so
~28 rounds replace 256 sweeps.

**105 s.** Move the lifts to the GPU. They are the same operation as the leaf
fold, so they belong on the same kernel.

**60 s.** Two changes, and only one of them was the one expected.

Nsight said the fold kernel was at **97.9% of SM throughput**, issuing 2.19
instructions per cycle against the GA10x integer pipe's limit of 2 — it cannot
be improved without changing the algorithm or the silicon. The compiler had
already fused `Ch` and `Maj` into single `LOP3.LUT` instructions, which is the
optimisation a hand-tuned kernel would reach for first.

The assembly kernel, though, was at 42% occupancy with 77 registers a thread and
21% DRAM throughput on a kernel that should touch no memory: its `uint8_t[32]`
node hashes were indexed dynamically and had spilled to local memory. Carrying
them as eight 32-bit words took registers to 40 and occupancy to 85% — and
bought only 7%, because occupancy was never the constraint.

**Divergence was.** A lift is a serial chain whose length varies from zero to
dozens, so a warp ran at its longest lane. The assembly performs about 2 billion
hashes, which at the fold kernel's demonstrated 1.0 GH/s is two seconds of work,
and it was taking forty. Sorting each round's groups by chain length before
running them — a one-byte radix key, costing 0.07 s — made the warps uniform and
took the assembly from **42.6 s to 5.6 s**.

The fold kernel is now 75% of the run and is immovable. What remains is the 9 s
of reading 12.5 GB off disk and gathering the labels, which is I/O rather than
compute.

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
