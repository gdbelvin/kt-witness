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

## Disclosed, and judged acceptable

### Private network topology

`192.168.0.10` (the witness host), `192.168.0.11` (the GPU host),
`100.100.100.100` (the witness's Tailscale address), and `example-tailnet.ts.net`
appear in `compose.yaml`, `deploy/RUNBOOK.md`, `deploy/gpu/README.md`,
`deploy/caddy/witness.caddy`, two flag defaults, and the `internal/workrpc`
tests.

Left in place. These are RFC1918 and CGNAT addresses: they are not routable from
the internet and mean nothing to anyone not already inside the network. The
tailnet name is already public, since the witness served on
`kt-witness.example-tailnet.ts.net` before the custom domain existed. Replacing them
with documentation-range placeholders would make the runbook materially worse at
the only job it has, which is telling the operator which host is which during an
incident.

One consequence is worth knowing rather than fixing here: `cmd/kt-worker` and
`cmd/kt-gpu-rootd` carry LAN addresses as **flag defaults**, so a stranger who
clones this gets defaults pointing at machines they do not own. That is a
usability wart in a public repo, not a security problem, and changing a running
deployment's defaults during a publication audit is the wrong moment.

### Addresses that look public but are not

`5.4.1.1` is a citation of RFC 9381 §5.4.1.1. `104.21.6.56` is a test fixture
labelled, in the fixture itself, "a public address" — it exists to prove the
listen-address check *rejects* public addresses. `100.100.100.100` is inside
`100.64.0.0/10`, so CGNAT rather than public. `1.1.1.1` and `8.8.8.8` are
resolver examples.

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

## Cleared for publication

Subject to the two decisions that are not this document's to make: whether to
commission the $2,000–5,000 legal review of the disclosure process
(`BUSINESS-CASE.md` §8b calls it the one genuinely uncovered risk), and rotating
the Tailscale key mentioned above.
