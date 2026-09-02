# Progress

Where the project actually stands, including the things that turned out
differently than expected. Written to be read cold.

## Status

Five Key Transparency deployments witnessed by one process, verified live
against production. ~5,000 lines of Go plus a Rust sidecar, ~2,300 lines of
tests, 79 tests, 13 commits.

| Log | Tier | What is proven |
|---|---|---|
| `thelemail.com/keys` | **A** | Signed checkpoint, append-only via locally computed consistency proof |
| `meta.messenger.kt/v1` | **A+** | Root-chain continuity across all published history |
| `proton.me/kt/v1` | **A+** | Epoch hash chain, plus the WebPKI certificate committing to each chain hash |
| `signal.org/kt` | **A** | Service root derived from three auditors, confirmed by Signal's signature, append-only across observations |
| `apple.com/kt/top-level-tree` | **A** | ECDSA-signed head, append-only via Apple's consistency proofs |

Plus seven Apple per-application trees tracked as **observations** — including
two iMessage trees — which are deliberately never cosigned.

Backfilled: **535,390 Meta epochs** (89,395→624,784, zero gaps, under 2 minutes)
and Proton's entire 501-epoch retention window.

## Three assumptions that were wrong

Each of these was believed on the basis of documentation rather than a probe, and
each was overturned by actually trying.

**Signal needed operator coordination.** It does not. Its KT client endpoints are
unauthenticated *by design* — the server rejects requests that carry credentials.
The plan had Signal as an outreach phase; it became a code phase.

**Signal could only reach tier S.** The service root is never served, and
reconstructing it looked like it required the whole combined-tree search proof.
But each auditor tree head carries a signed root *plus* a consistency proof up to
the service size, and a consistency proof run forwards *determines* a root. Three
auditors, different sizes, different proof lengths, all deriving the same root —
and all three of Signal's signatures verifying over it.

**Apple was blocked.** That came from Apple's 2023 blog post, not from probing.
Apple's promised public auditing was indeed never announced, but the
infrastructure is live and open: signed tree heads and consistency proofs, both
unauthenticated. Then the Top-Level Tree turned out to be a *log of
per-application heads*, which is the only public route to iMessage's KT state.

## Bugs worth remembering

Most were caught by testing the thing rather than trusting that it worked.

**A CDN cache would have publicly accused Meta of forking.** CloudFront serves
stale *negative* listings, and `Cache-Control: no-cache` does not bypass it. A
cached "absent" mid-walk looks exactly like a hole in Meta's history. Fixed with
cache-busting, then hardened by reclassifying absence as retryable — only a
positive contradiction can now be a fork.

**The same bug, one layer up.** The witness core still treated a size regression
as conclusive, and Meta's size comes from a chain of absence observations. Sources
now declare `DerivedHead()`; derived heads withhold rather than accuse.

**Livelocks, three times.** Meta catch-up, tier-B auditing, and unfetchable
epochs each had a path that retried forever without advancing. All now bounded
and converging.

**A fork detected during `Fetch` was silently dropped.** The one conclusive
detection the Signal work added — auditors disagreeing on the derived root — was
raised on a path the core only wrapped, so nothing was persisted or poisoned.

**Three container bugs, all silent.** An arm64 sidecar inside an amd64 image; a
missing `libgcc_s.so.1`; and Apple's host being issued by Apple's own private CA,
which macOS trusts and a distroless image does not. Each let the witness start
normally with only tier B or one adapter dead.

**Fork evidence printed garbled roots.** `%x` on a `tlog.Hash` hits its
`String()` method and hex-encodes base64 text. Published evidence, so it mattered.

## Design decisions that held up

**Tiers are in the type system.** Every assertion names what it proves. A weaker
tier was added rather than letting Signal's early adapter imply more than it
checked, and Apple later occupied it before being promoted.

**Accusation requires contradiction, never absence.** A missing object, a failed
download, a proof that will not parse — all withhold and retry. Only a positive
contradiction poisons a log, because the accusation is permanent and public.

**A fork is permanent.** A log that equivocates and then reverts does not quietly
regain a cosignature.

**Self-validating acceptance tests.** Signal's log tree was accepted because
three auditors independently derived one root and three signatures verified over
it. Apple's hashing was established by running a production proof through an
existing RFC 6962 implementation. Neither could plausibly pass by accident.

## Deployment

Prepared, not deployed. `deploy/` holds a production config for
`witness.kt.gdbsecurity.com` and a runbook that generates the signing key on the
target so the private key never leaves it. The image is distroless, two builders
(Go core, Rust AKD sidecar), verified cosigning all five ecosystems from inside
the container.

Measured load: ~20 GB/day at the chosen tier-B sample rate, ~3.7 GB peak RSS per
verification, ~300 KB/day of database growth.

## Next

See [TODO.md](TODO.md). The two that would most change what we can claim are
binding Apple's iMessage heads to the verified root, and moving the signing key
into hardware before anyone pins it.
