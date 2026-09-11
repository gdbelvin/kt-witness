# What it costs to run this

Measured, not estimated, except where marked. Every figure traces to a probe or
a timed run recorded in this repository.

## The short version

**Infrastructure is not the cost.** Witnessing ten origins — including Meta,
WhatsApp, Signal, Apple, Proton and 80 CT logs — needs about **a third of one
CPU core, a few TB/month of ingress, and ~45 GB of disk.** That is roughly $1,900
a year of real hardware, and near zero on a machine you already own.

The cost is **engineering and attention**: adapters that break when providers
change undocumented APIs without notice, and a human who notices and responds.
Any funding conversation should be about that, because that is what actually
runs out.

## Measured resource use

Poll interval 60 s. The table below was built assuming tier-B sampling at 0.1
for the AKD logs; see the correction under it, because that is not what the tip
actually does.

| Log | GB/day | TB/yr | CPU h/day | Disk GB | Basis |
|---|---:|---:|---:|---:|---|
| Meta / Messenger | 20.45 | 7.47 | 2.88 | 1 | 720 epochs/day × 284 MB, 10% sampled; 144 s CPU each |
| WhatsApp v2 | 16.85 | 6.15 | 1.28 | 1 | 2,880 epochs/day × 58.5 MB, 10% sampled; 2.7 s wall each |
| Proton | 0.03 | 0.01 | 1.90 | 40 | 6 epochs/day × 3.2 MB diff; 19 min rebuild; 13.6 GB tree ×2 retained. *Prospective* — the audit is not yet in the witness loop, so this disk is not used today |
| Signal | 0.71 | 0.26 | 0.05 | 1 | 490 KB per poll — the search proof rides in every response |
| Apple KT + AT | 0.06 | 0.02 | 0.02 | 1 | 183 B heads plus consistency proofs |
| thelemail | 0.07 | 0.03 | 0.02 | 1 | tiny log, every entry verified |
| static CT × 80 | 1.97 | 0.72 | 0.30 | ~0 | *modeled*: ~700 B checkpoint + ~2 × 8 KB tiles per poll |
| **Total** | **40.1** | **14.7** | **6.45** | **~45** | |

**~0.3 cores sustained. ~45 GB of disk.** See the correction below before
using the bandwidth total.

**The sampling premise in this table is wrong for the tip.** `sample_rate` 0.1
governs the *backlog* only: `audit.SelectionRate` returns 1 for any epoch inside
`DefaultTipWindow`, so every newly published epoch is audited exhaustively. The
"10% sampled" basis therefore understates steady-state Meta and WhatsApp by 10×.
For CPU that error is almost exactly cancelled by the Rust-to-Go speedup noted
below (10 ÷ 8), which is why the core figure barely moves. **For bandwidth it is
not cancelled by anything: the real steady-state ingress is nearer 370 GB/day,
up to ~11 TB/month at the table's conservative blob sizes, and probably about
half of that in practice — not 1.2 TB/month.** The funded plan's own "137 TB
across eight drives" for a year of retained proofs is ~375 GB/day, which agrees
with the exhaustive reading rather than the sampled one. The table has not yet
been rebuilt around this.

**These blob sizes are conservative.** Capturing a corpus of real proofs
measured Meta epochs at ~150 MB rather than 284 MB, WhatsApp at ~30–37 MB
rather than 58.5 MB, and Signal responses at ~370–455 KB rather than 490 KB.
The original figures came from single observations; the table below has not been
rewritten around the new ones because they vary per epoch, but real bandwidth is
likely nearer half of what is stated. Erring high is the right direction for a
number an operator plans capacity against.

**The CPU column is conservative too, and now doubly so.** The 144 s per Meta
epoch was measured against the Rust verifier that has since been replaced; the
in-process Go one costs about an eighth of the CPU. The table has not been
rewritten around that either, for the same reason as the sizes.

An earlier draft of this table put CT storage at 120 GB, assuming a persistent
tile cache. There is none — `NewTileFetcher` is used without `PermanentCache`,
so tiles are fetched, used and discarded. Consistency proofs need only internal
hash tiles, never the data tiles that hold certificates, so CT storage is
effectively zero and the real total is about a third of what was stated.

Three things worth noticing:

**The traffic is ingress.** A witness downloads proofs and publishes a few
kilobytes of checkpoints. Ingress is free or unmetered almost everywhere, which
is why 14.7 TB/year costs nothing on a dedicated box and would cost real money
only on a hyperscaler billing egress.

**Sampling is doing enormous work.** Meta at 100% would be 204 GB/day and
WhatsApp 168 GB/day, and at 0.1 they would be 20 and 17 — but that saving
applies only to the backlog, since the tip is audited exhaustively. The security
argument for
sampling is in [design.md](design.md); the economic argument is a 10× bill.

**Signal is the surprise.** It carries no tier-B cost at all, yet costs more
bandwidth than everything except the two AKD logs, because a full search proof —
256-hash prefix proofs, ~30 log entries — ships in *every* poll. Polling Signal
less often is the single easiest saving available.

## What a fundable service costs

Running this at home is nearly free. Running it as something another
organisation can *rely on* is different: it needs redundancy, a hardware-held
key, alerting, and somebody who answers.

| Item | Annual |
|---|---:|
| 2 × dedicated servers (64 GB, NVMe, unmetered gigabit) | $1,680 |
| Domain, DNS, monitoring and paging | $200 |
| Hardware signing keys (amortised) | $50 |
| **Infrastructure total** | **~$1,900** |
| Operations and maintenance, 120–180 h/yr | $18,000–45,000 |

For scale: Geomys runs an entire production Static CT *log* — which ingests and
serves everything, far heavier than witnessing — for **$10,350/year** all in.
A witness should never cost more than a log, and this one does not.

The operations figure is the honest one and the one to defend. It is not
babysitting. It is:

- **Provider churn.** Apple ships protos describing endpoints that are not
  deployed; Signal's tree math is reimplemented from a crate that changes;
  Meta's proofs arrive through a CDN that caches absence. Every one of those
  cost real debugging, and every one can recur.
- **Incident response.** Withholding is the enforcement mechanism, so a log that
  stops verifying needs a human to decide within hours whether it is a bug, an
  outage, or a disclosure.
- **Key custody and the published identity.** Once anyone lists the verifier key
  in a trust policy, rotating or losing it is their problem too.

## Per-ecosystem effort

One-time figures are replacement cost — what it took to build, in hours, from
this project's own history. Ongoing is share of maintenance attention, not
bytes, because bytes are nearly free and attention is not.

| Ecosystem | One-time | Ongoing share | Why |
|---|---:|---:|---|
| Signal | ~120 h | 25% | ECVRF, prefix tree, RFC 9420 log tree, search proofs, all reimplemented from libsignal |
| Apple (KT + AT) | ~80 h | 25% | Undocumented protobuf recovered by probing; protos describe more than is deployed; private CA |
| Meta / AKD | ~80 h | 12% | Rust sidecar, since replaced by an in-process Go verifier; CDN cache traps; backfill of 535k epochs |
| Proton | ~80 h | 15% | 256-level sparse tree recovered from a C verifier; 200M-leaf rebuild |
| WhatsApp | ~2 h | 8% | Shares the AKD adapter — configuration only |
| Static CT (80 logs) | ~16 h | 10% | RFC 6962 note verifier; then configuration |
| Shared core | ~120 h | 5% | Witness core, store, export, server, cosignatures |

Note what this table says about **WhatsApp**: the largest KT deployment in the
world was two hours of work, because Meta had already paid for the AKD adapter.
Marginal cost per additional log in a known family is close to zero. That is the
argument for funding the *ecosystem* rather than per-log.

## Asking providers to pay

There is a problem with this plan and it should be said first.

### The independence problem

**A witness paid by the operator it watches is not obviously independent.** The
entire value of the cosignature is that we have no stake in the answer. An
arrangement where Meta pays us to watch Meta invites exactly the question a
sceptic should ask, and "they pay but it doesn't influence us" is not a
verifiable claim.

This is solvable, but only deliberately:

- **Pool the funding.** Providers contribute to the operation as a whole, never
  per log. Nobody is buying their own audit.
- **Never make witnessing contingent on payment.** The logs are public. We
  witness them whether or not anyone pays, so withdrawing funding cannot
  silence a finding — which removes the lever that would make the conflict real.
- **Multi-year terms that cannot be cancelled for cause.** Funding that can be
  pulled the month after a disclosure is not funding, it is leverage.
- **Publish who pays, in the status output.** Alongside the verifier key.
- **Prefer an intermediary.** Money routed through a foundation is materially
  more credible than a direct invoice.

Without these, taking provider money makes the witness *less* valuable than
taking none.

### What the market currently pays: approximately nothing

Worth knowing before pitching:

- Public witnesses today are run as **free public-benefit infrastructure**.
  Geomys operates its Sunlight witness and a pro-bono CT log at its own cost.
- **Cloudflare gives KT auditing away.** It audits WhatsApp and Signal as a
  positioning and marketing play, not for fees. The incumbent's price is zero.

So the pitch cannot be "this is a service you need to buy" — someone already
gives a version of it away. The pitch that actually holds is **diversity**:

> Cloudflare being the *only* third-party KT auditor makes Cloudflare a single
> point of trust, which is the exact failure mode transparency exists to remove.
> Signal deploys three auditor keys because one auditor is not a meaningful
> check. A second independent auditor is worth more to the ecosystem than the
> first one was.

That argument is strongest for **Signal** (already committed to auditor
plurality), and for anyone whose threat model includes "our auditor and we are
both wrong."

### Suggested asks

| Tier | Who | Annual | Rationale |
|---|---|---:|---|
| 1 | Meta (Messenger + WhatsApp), Apple, large CT operators | $25,000–40,000 | Deep budgets; two of the heaviest adapters; WhatsApp alone is ~3B users |
| 2 | Signal, Proton | $10,000–15,000 | Nonprofits and smaller commercial; strongest philosophical alignment |
| 3 | Small CT and KT operators | $1,000–2,500 | Marginal cost is near zero; volume and legitimacy |

Two or three tier-1 sponsors plus two tier-2 makes this a properly funded,
redundant service with a part-time operator — roughly **$85,000/year**.

**The floor is much lower.** About **$25,000/year** covers infrastructure with
redundancy plus ~100 hours of maintenance: enough to keep ten origins witnessed,
current, and honest. Anything above that buys coverage of more ecosystems and
faster incident response.

### Better first stops than the providers

Public-interest funders carry none of the independence problem and are used to
exactly this shape of work:

- **Sovereign Tech Agency** (Germany) — has deployed over €24.6M into open
  digital infrastructure maintenance, which is precisely this category. The
  proposed EU Sovereign Tech Fund is modeled on it.
- **NLnet / NGI Zero** — historically the natural home for this, though the NGI
  Zero calls are paused as of mid-2026 pending the EU Tech Sovereignty package.
  Worth watching for the successor programme.
- **ISRG / Let's Encrypt** — sponsored Sunlight's development and has a direct
  interest in CT witness diversity.
- **Linux Foundation / OpenSSF** — plausible fiscal host, which also solves the
  intermediary problem above.

The strongest sequence is probably: get funded as public-benefit infrastructure
first, *then* invite providers to contribute to a pot that already exists. That
inverts the conflict — they are joining something independent rather than
commissioning their own audit.

## The precondition

None of this is sellable while the witness has never run. Ten origins are
verified; zero are operating. An operating record — uptime, published
checkpoints, a verifier key others can pin — is the entire basis of any funding
conversation, and it costs an afternoon.

## Running only overnight

Measured on the intended connection, 2026-09-02: **374 Mbps down, 42.5 Mbps up**,
30 ms idle latency. Downlink responsiveness degrades to 103 ms under load and
uplink to 517 ms — so saturating the link is noticeable, which is the reason to
confine the heavy work to a window.

The workload splits cleanly, because the two halves have opposite shapes.

**Tier A polling must run continuously** — it is what makes the witness useful,
since a checkpoint nobody watched between midnight and 8 a.m. cannot catch a
split view at 3 a.m. It is also free: everything except the AKD tier-B work is
**~2.9 GB/day, an average of 0.27 Mbps**, or under 0.1% of the downlink. It will
never be noticed.

**Tier B can be batched.** Meta's and WhatsApp's audit proofs stay in their
buckets, so an epoch published at noon can be audited at 3 a.m. with the same
proof and the same beacon-derived sampling decision. Nothing about the security
argument depends on auditing promptly.

Batching the 37.3 GB/day of tier B into an overnight window:

| Window | Sample 10% | Sample 50% | Sample 100% |
|---|---|---|---|
| 6 hours | 13.8 Mbps · 0.7 cores | 69 Mbps · 3.5 cores | 138 Mbps · 6.9 cores |
| **8 hours** | **10.4 Mbps · 0.5 cores** | 52 Mbps · 2.6 cores | 103 Mbps · 5.2 cores |
| 10 hours | 8.3 Mbps · 0.4 cores | 41 Mbps · 2.1 cores | 83 Mbps · 4.2 cores |

At the configured 10% rate an eight-hour window needs **10.4 Mbps — 2.8% of the
measured downlink**. There is no meaningful contention even during the day.

The more interesting result is the right-hand column. **A 374 Mbps connection
can sustain 100% construction auditing of both Meta and WhatsApp inside an
eight-hour window**, at 103 Mbps or 28% of capacity. Sampling was adopted
because continuous full audit looked infeasible; on this link, overnight, it is
not. The binding constraint becomes CPU — 41.6 CPU-hours/day compressed into
eight hours needs about **5.2 cores sustained** — not bandwidth. That is an
upper bound: it carries the Rust-era per-epoch cost of the table above, and the
verifier that replaced it costs about an eighth of it.

That is worth knowing before buying anything: the upgrade that would raise
assurance most is cores, not disks and not a faster line.

## Disks

Almost a non-issue, and worth stating plainly because it is easy to assume
otherwise:

| Need | Size |
|---|---|
| Database and published file mirror | <1 GB, growing ~1 GB/yr |
| Tier-B scratch, one proof in flight | 0 — the verifier holds the proof in memory; nothing is staged to `/tmp` |
| Proton tree, once the audit is in the loop | ~40 GB |
| Static CT | ~0 — no tile cache |
| **Total** | **~45 GB**, comfortably 100 GB with headroom |

This table does not count `audit.prefetch_dir`, which is a deliberate cache of
proofs downloaded ahead of verification and is bounded by `prefetch_bytes` — 64
GiB in the deployed config. It is a dial, not a requirement: set it to nothing
and the numbers above stand.

**Audit proofs are verified and discarded, never retained.** That is the
assumption that would change the answer: keeping Meta's and WhatsApp's proofs
would be ~136 TB/year at full rate, and there is no reason to. The evidence
worth keeping — checkpoints, audit decisions, fork evidence — is kilobytes.

So a single 1 TB NVMe drive is generous by a factor of twenty. Approximate
retail, September 2026, and worth checking rather than trusting:

| Drive | Approx. |
|---|---|
| 500 GB NVMe | $40–60 |
| 1 TB NVMe | $60–90 |
| 2 TB NVMe | $110–160 |

**Recommendation: buy no disks yet.** ~45 GB almost certainly fits on the
existing machine. If anything is worth spending on, it is cores — which is what
would let sampling rise from 10% toward 100%.
