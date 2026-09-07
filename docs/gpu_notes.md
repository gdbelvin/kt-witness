# Optimising GPU work here: what to do, in what order

Written after taking a full Proton tree rebuild from 658 s to 60 s. The
destination was right; the route was not. Nearly all of the elapsed time went
into confident guesses that measurement later contradicted, and every one of
those guesses was cheap to test and expensive to assume.

This is the order to work in next time.

## 1. Split the total by phase, with host timers, before anything else

Five minutes of `clock_gettime` around each stage answers "what is actually
slow", and nothing else should happen until it has.

In this case the split was upload 12 s / fold kernel 43 s / assembly 600 s. The
assembly — the part written off in a comment as "0.4% of the work" — was 91% of
the runtime. Several hours were spent tuning the fold kernel, which was already
at the hardware limit, because that was the part that felt like the hard one.

## 2. Count the operations before optimising them

Add a counter per operation class and print it. Distribution assumptions are
usually wrong, and wrong in ways that invert the plan.

Here the assembly was believed to be `n-1` joins with occasional corrections.
The counters said **201 million joins and 1.8 billion lifts** — the "occasional
correction" was 90% of the work. Nothing about the fix was findable without that
number, and it cost four lines to obtain.

## 3. The ratio test — the single most valuable diagnostic

Take a kernel on the same hardware whose work is uniform and whose rate you
have measured. Compute what the slow phase *should* cost at that rate. Divide.

    assembly: ~2e9 hashes
    fold kernel, measured, same card: 1.0 GH/s
    expected: 2 s      actual: 40 s      ratio: 20x

A 20x gap on identical arithmetic is not a tuning problem, it is a structural
one — and for per-thread work of variable length it is nearly always **warp
divergence**. This ratio pointed straight at the answer and could have been
computed on day one from numbers already in hand.

Sorting the work by chain length before dispatch took the assembly from 42.6 s
to 5.6 s. The sort itself costs 0.07 s.

## 4. Run Nsight once, on the dominant kernel — for counters, not for time

    sudo ncu --kernel-name regex:"yourKernel" --launch-count 2 --metrics \
      sm__throughput.avg.pct_of_peak_sustained_elapsed,\
      sm__warps_active.avg.pct_of_peak_sustained_active,\
      launch__registers_per_thread,\
      dram__throughput.avg.pct_of_peak_sustained_elapsed,\
      sm__inst_executed.avg.per_cycle_active ./binary input

How to read it:

- `sm__throughput` near 100% means **stop**. The kernel is issuing as fast as
  the SM allows and no amount of restructuring will help. Ours was **97.9%**,
  which retired a whole afternoon's worth of planned optimisations.
- `sm__inst_executed.avg.per_cycle_active` against the pipe's limit says which
  pipe. On GA10x the INT32 pipe issues **2 warp-instructions/cycle** (64 of the
  128 lanes do integer). We measured 2.19 — at the ceiling.
- `dram__throughput` non-trivial on a kernel that should touch no memory means
  **local-memory spill**. Ours was 21%: `uint8_t[32]` arrays indexed dynamically
  do not live in registers. Carrying them as `uint32_t[8]` fixed it.
- Low `warps_active` is worth fixing but is often not the constraint. Ours went
  42% → 85% and bought **7%**.

**Do not use `ncu` for time attribution.** Its multi-pass replay distorts
durations badly: it reported the prefix scan at 23.6 s when host timers put it
at **0.03 s**, and that false lead was chased. Counters and rates from `ncu`,
time from host timers, and cross-check the two against wall clock.

## 5. Sanity-check every throughput claim against the hardware ceiling

    peak int ops/s = SMs x int lanes/SM x clock
    A10: 72 x 64 x 1.695e9 = 7.81e12

Then `ops-per-unit-work x claimed rate` must come out under it. A published
claim of "2.7-3.6 GH/s SHA-256 on an A10" needs 10-14e12 ops/s and is therefore
impossible; it was repeated here before being checked. Two minutes of
arithmetic disproves a number that would otherwise set the whole plan.

Corollary: hand-counting ops per unit of work to *estimate* efficiency is not
worth doing. It was attempted three times here and produced 22%, then 35-50%,
against a measured 97.9%. Run the profiler instead.

## 6. Benchmark the real path, not a synthetic proxy

`openssl speed -evp sha256` reported 1.34M hashes/s/core. The production path —
Go's `crypto/sha256` over a memory-mapped 12.5 GB file — sustained **374k/core**,
3.6x slower. Every estimate built on the synthetic number was optimistic by that
factor, including a prediction of 32 minutes for a step that took 1 h 56 m.

If the real path cannot be benchmarked directly, measure a completed run of it
and calibrate from that.

## 7. Write the VRAM budget down before writing the kernel

A table of every allocation and its size, summed, against the card's usable
memory. Two out-of-memory failures here were each about a gigabyte over, and
both were predictable on paper.

Two techniques that bought the headroom, worth reaching for early:

- **Stream what dies young.** Leaf values (7.2 GB) are dead the moment the leaf
  hashes exist, so they go up in 8M-leaf chunks instead of resident.
- **Size outputs from the scan, not from worst case.** Each round's output count
  is known before the round runs; allocating exactly that instead of the input
  size was the difference between fitting and not.

## 8. Keep a known-good oracle and check it after every change

Every version here was checked against a synthetic vector with a root from the
Go implementation, and against two real Proton trees with roots Proton signed.
Four rewrites of the assembly, and each one either matched all four or was
wrong — no judgement calls, no "close enough".

For a system whose output is an accusation about an operator, this is not
diligence, it is the point. Which is also why the GPU never decides: a mismatch
means rebuild on the CPU and let the CPU say.
