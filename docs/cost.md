# What it costs to run this

Measured, not estimated, except where marked. Every figure traces to a probe or
a timed run recorded in this repository.

## The short version

**Infrastructure is not the cost.** Witnessing ten origins — including Meta,
WhatsApp, Signal, Apple, Proton and 80 CT logs — needs about **a quarter of one
CPU core, 1.2 TB/month of ingress, and 153 GB of disk.** That is roughly $1,900
a year of real hardware, and near zero on a machine you already own.

The cost is **engineering and attention**: adapters that break when providers
change undocumented APIs without notice, and a human who notices and responds.
Any funding conversation should be about that, because that is what actually
runs out.

## Measured resource use

Poll interval 60 s; tier-B sampling at 0.1 for the AKD logs.

| Log | GB/day | TB/yr | CPU h/day | Disk GB | Basis |
|---|---:|---:|---:|---:|---|
| Meta / Messenger | 20.45 | 7.47 | 2.88 | 1 | 720 epochs/day × 284 MB, 10% sampled; 144 s CPU each |
| WhatsApp v2 | 16.85 | 6.15 | 1.28 | 1 | 2,880 epochs/day × 58.5 MB, 10% sampled; 2.7 s wall each |
| Proton | 0.03 | 0.01 | 1.90 | 28 | 6 epochs/day × 3.2 MB diff; 19 min rebuild; 13.6 GB tree ×2 retained |
| Signal | 0.71 | 0.26 | 0.05 | 1 | 490 KB per poll — the search proof rides in every response |
| Apple KT + AT | 0.06 | 0.02 | 0.02 | 1 | 183 B heads plus consistency proofs |
| thelemail | 0.07 | 0.03 | 0.02 | 1 | tiny log, every entry verified |
| static CT × 80 | 1.97 | 0.72 | 0.30 | 120 | *modeled*: ~700 B checkpoint + ~2 × 8 KB tiles per poll |
| **Total** | **40.1** | **14.7** | **6.45** | **153** | |

**0.27 cores sustained. 1.2 TB/month.**

Three things worth noticing:

**The traffic is ingress.** A witness downloads proofs and publishes a few
kilobytes of checkpoints. Ingress is free or unmetered almost everywhere, which
is why 14.7 TB/year costs nothing on a dedicated box and would cost real money
only on a hyperscaler billing egress.

**Sampling is doing enormous work.** Meta at 100% would be 204 GB/day and
WhatsApp 168 GB/day. At 0.1 they are 20 and 17. The security argument for
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
| Meta / AKD | ~80 h | 12% | Rust sidecar, CDN cache traps, backfill of 535k epochs |
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
