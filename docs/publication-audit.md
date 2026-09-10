# Audit of the git history before publication

Run 2026-09-09, against 191 commits and 1,961 objects, before making the
repository public. The question asked was narrow and worth stating precisely:
**is there anything in any commit, including in files since deleted, that must
not be published?**

Conclusion: **no credentials, in HEAD or in history.** One cleanup was required
and is in the commit that carries this file. Three categories of disclosure are
present, judged acceptable, and recorded below so the judgement is reviewable
rather than implicit.

## Method

1. `gitleaks detect --source .` across all 190 commits — 214 findings, every one
   triaged by hand.
2. A second scan with deliberately over-triggering patterns for the classes
   gitleaks does not cover: PEM and OpenSSH private keys, the `note`/sigsum
   secret-key format, Tailscale auth keys, Cloudflare tunnel secrets, GitHub and
   AWS tokens, bearer headers, password assignments, Grafana and InfluxDB
   credentials, public and private IPv4, tailnet names, phone numbers, postal
   addresses, and email addresses. Script: `docs/publication-scan.py`.
3. Every path ever added, including deleted files, listed and reviewed for
   non-source material.
4. `.gitignore` reviewed against what it is supposed to protect.

Deliberately over-triggering, because a scan that reports nothing is
indistinguishable from a scan that is not looking.

## gitleaks: 214 findings, 0 real

All 214 are `generic-api-key`, which fires on any high-entropy string. Every one
sits in one of these fields:

| Count | Field | What it is |
|---:|---|---|
| 203 | `log_key` | CT log **public** keys, in `deploy/witness.json`, `witness.example.json`, `deploy/ct-logs.json` |
| 4 | `log_key_hex` | The same, hex-encoded |
| 3 | `auditor_key` | Signal's auditor **public** keys |
| 2 | `ProdSigningKey`, `ProdVRFKey` | Signal's production **public** keys, pinned in libsignal `rust/net/src/env.rs` |
| 2 | `signalVRFKey`, `pccKey` | Test vectors |

A witness hardcodes the public keys of the logs it audits; that is the whole
mechanism. Publishing them is not a leak, it is the point — they are what lets a
reader confirm the witness checked the log it claims to have checked.

## The one real finding: 43 MB of compiled binaries

`bin/kt-akd-diff`, `bin/kt-worker` and `kt-worker` were tracked. Go binaries
embed the absolute source paths of the machine that built them, so all three
carried `/Users/<operator>/dev/kt-witness/...` throughout.

Not a credential, and not much of a disclosure — the operator's username is
already in every commit's author line. It is still 43 MB of Mach-O that has no
business in a source repository, and every one of them rebuilds from
`deploy/RUNBOOK.md`.

Untracked, and `.gitignore` extended. The existing `/kt-witness` entry was
anchored for the witness binary specifically and simply never grew to cover the
worker or the diff harness.

**They remain in history.** Removing them would mean a rewrite and a force-push
over a published merge, which is a worse trade than 43 MB of dead weight: no
file exceeds GitHub's limits, and nothing in them is sensitive. If the repository
is ever rewritten for another reason, drop them then.

## Private network topology: removed

The witness host, the GPU host, the witness's Tailscale address and the tailnet
name appeared across `compose.yaml`, `deploy/gpu/compose.yaml`,
`deploy/RUNBOOK.md`, `deploy/gpu/README.md`, `deploy/grafana/README.md`,
`deploy/caddy/witness.caddy`, two flag defaults, and the `internal/workrpc`
tests.

An earlier draft of this document argued for leaving them: RFC1918 and CGNAT
addresses are not routable, they mean nothing to anyone not already on the
network, and placeholders make a runbook worse at the one job it has. The
operator overruled that, and the operator is right about the part that argument
missed — the question is not whether the addresses are exploitable but whether
they are anyone else's business, and they are not. Topology is not a secret and
is still not public information.

So they now live in `.env`, which is gitignored, with the template and the
reasoning in `deploy/infra.example.env`:

| Variable | What it names |
|---|---|
| `KT_WITNESS_LAN_IP` | the LAN address the work channel binds |
| `KT_GPU_LAN_IP` | the GPU host serving Proton rebuilds |
| `KT_TAILNET` | the tailnet, for docs and dashboard uploads |

**The substitution is fail-closed, and this is the important part.** The host_ip
half of a Docker port mapping *is* the confinement for the work channel:
`10.0.0.5:18090:8090` publishes on one interface, `18090:8090` publishes on all
of them. A plain `${KT_WITNESS_LAN_IP}` would render the second form whenever
the variable is unset, turning a missing file into an internet-facing
unauthenticated work queue — a strictly worse outcome than the disclosure this
change exists to prevent. Both use sites are therefore written
`${VAR:?message}`, which makes Compose refuse to start. Verified by removing
`.env`:

```
error while interpolating services.kt-witness.ports.[]: required variable
KT_WITNESS_LAN_IP is missing a value: set KT_WITNESS_LAN_IP in .env
```

The flag defaults in `cmd/kt-worker` (`-server`) and `cmd/kt-gpu-rootd`
(`-listen`) are now empty and required, each exiting 2 with an explanation.
Neither was defensible in a public repository: a baked-in default is correct for
exactly one operator and silently wrong for everyone else, and in
`kt-gpu-rootd`'s case the tempting convenience default — `:8099` — is precisely
the bind-everything failure its own help text warns about.

Test fixtures use generic addresses (`192.168.0.10`, `100.100.100.100`) that
exercise the same RFC1918 and CGNAT branches without naming a real machine.
`internal/workrpc` tests pass unchanged.

### Deploying this

`.env` is gitignored, so it does not travel with the repository and **must be
created on each host before `docker compose up`** — the witness host and the GPU
host both. Compose fails loudly if it is missing, which is the intended
behaviour and not a regression.

## Disclosed, and judged acceptable

### Addresses that look public but are not

`5.4.1.1` is a citation of RFC 9381 §5.4.1.1. `104.21.6.56` is a test fixture
labelled, in the fixture itself, "a public address" — it exists to prove the
listen-address check *rejects* public addresses. `1.1.1.1` and `8.8.8.8` are
resolver examples. `192.168.16.3` in `deploy/tailscale/compose.tailscale.yaml`
is Docker's own bridge assignment, described to explain a proxy resolution
quirk, and names no machine of the operator's.

### Email

`gdb@gdbsecurity.com` appears throughout, and deliberately: it is the contact
address in `funding.json`, which has to be reachable. `a funder's published contact` is
a funder's published contact, from research notes.

## What was checked and found clean

- **No private key of any kind.** No PEM, no OpenSSH, no `PRIVATE+KEY+` (the
  `note` secret-key format this witness would use), in any commit.
- **No Tailscale auth key.** `deploy/tailscale/tailscale.env` holds `op://`
  1Password references, not values; the only `tskey-` string in history is the
  11-character placeholder `tskey-auth…`. A key was exposed in an operator chat
  session on 2026-09-05 and should be rotated on that basis, but it never
  reached the repository.
- **No Cloudflare tunnel credentials.** `TunnelSecret` and `AccountTag` appear
  once each, in a commit message explaining what the token encodes.
- **No tokens, passwords, or bearer headers** of any kind.
- **`.gitignore` covers what matters**: `*.key`, the operator's live
  `/witness.json`, `*.db`, `/deploy/cloudflared/*.json`, `/secrets/`, and
  `/data/` — the last being the important one, since it holds the witness signing
  key, the bolt database, *and* the Tailscale node state, which authenticates the
  host to the tailnet even though nothing about the path suggests it.
- **`.claude/` was never committed**, and is excluded.
- **No database, no `data/`, no runtime state** in any commit.

## Still in history — open decision

Everything above removes the addresses from the working tree. **They remain in
the 191 commits behind it**, and `git log -p` finds them in seconds. If the
requirement is that the operator's network is not in the repository at all, only
a history rewrite satisfies it.

This is the right moment to decide, and close to the last one. The repository is
still private, has never been public, has no forks, and has exactly one merged
pull request, so a rewrite costs almost nothing today: re-clone the two working
copies and move on. After publication it costs the ability to rewrite at all —
every fork and clone keeps the old objects, and the addresses become
unretractable.

Weighed against: a rewrite changes all 191 commit SHAs, so the commit messages
this project uses as its engineering record stay intact but every reference to a
SHA in a document or an issue breaks, and it needs a force-push over the merged
merge commit.

Recommendation: rewrite, before making the repository public, since the
disclosure is exactly what the operator asked to prevent and the window closes
at publication. Not done here — a history rewrite and a force-push are the
operator's call, not an auditor's.

## Cleared for publication

Subject to the two decisions that are not this document's to make: whether to
commission the $2,000–5,000 legal review of the disclosure process
(`BUSINESS-CASE.md` §8b calls it the one genuinely uncovered risk), and rotating
the Tailscale key mentioned above.
