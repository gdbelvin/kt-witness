# The landscape

What exists, what this witness covers, and what it would take to cover the rest.

Every row is either **verified** — probed live, with the evidence named — or
explicitly marked as unverified. Nothing here is inferred from documentation
alone, because in this project documentation has been wrong about four separate
things.

## Where we are

Ten origins are witnessed today, drawn from six protocol families:

| Origin | Family | Tier | Adapter |
|---|---|---|---|
| `thelemail.com/keys` | C2SP signed note | **B** | `c2sp` |
| `meta.messenger.kt/v1` | AKD | **A+ / B** | `akd` |
| `whatsapp.kt/v2` | AKD | **A+ / B** | `akd` |
| `proton.me/kt/v1` | Proton epochs | **A+ / B** | `proton` |
| `signal.org/kt` | Signal KT | **A** + per-label spot check | `signal` |
| `apple.com/kt/top-level-tree` | Apple KT | **A** | `apple` |
| `apple.com/at/pcc` | Apple AT | **A** | `apple` |
| 3 × static CT | C2SP signed note | **A** | `c2sp` + `staticct` |

## The shape of the problem

The single most useful finding is that **the transparency-log world has largely
converged on one format**, and this witness already speaks it.

C2SP `tlog-checkpoint` — a signed note over a Merkle tree, served as
`tlog-tiles` — now covers Sunlight, Tessera, static CT, the Go checksum
database, Rekor v2 and every Sunlight-family log. That means *breadth is mostly
a configuration problem*, and the interesting work is in the ecosystems that
predate the convergence or deliberately differ.

That is why 80 CT logs cost one small verifier rather than an adapter.

## Certificate Transparency

By population, this is most of the transparency-log world.

### Static CT — **verified, 80 of 80**

`internal/staticct` verifies the RFC 6962 tree head signature (note algorithm
0x05), which `x/mod/sumdb/note` does not implement. Every static CT log in
Google's list verifies with a key taken only from that list, across ~10
independent operators; seven operators' logs were then fetched and proven
append-only through the `c2sp` adapter, with Google's advancing
1,142,903,207 → 1,142,903,362 between observations.

Adding the remaining 77 is a config change. Whether to is an operational
decision about load and about whether more CT witnesses are wanted — the
ecosystem already has several, and joining a well-witnessed log adds less than
being the *only* witness of a KT log.

**Not offered: tier B.** Static CT serves entries at `tile/entries` with a
different encoding from `tlog-tiles`' `tile/data`, so the entry reader does not
apply and claiming construction auditing would be false.

### RFC 6962 CT — **covered elsewhere; do not duplicate**

42 classic logs remain. They serve `get-sth` / `get-sth-consistency` over JSON
rather than signed notes, so they need a small adapter. They also have the
oldest and densest monitoring ecosystem of anything here. Low value per unit of
work; listed for completeness.

## Key Transparency

| Deployment | Status | Notes |
|---|---|---|
| Meta / Messenger | **witnessed, A+/B** | [meta.md](meta.md) |
| WhatsApp v2 | **witnessed, A+/B** | Largest KT deployment by users; 30 s epochs |
| Proton | **witnessed, A+/B** | The only fully published directory; [proton.md](proton.md) |
| Signal | **witnessed, A** + spot check | [signal.md](signal.md) |
| Apple iMessage | **observations only** | No IDS_MESSAGING tree exists to query; [apple.md](apple.md) |
| Google keytransparency | **dead** | Archived 2024-10-11, no deployment |
| IETF keytrans | **nothing to witness** | The draft specifies no transport |

### The plexi namespace list

Cloudflare's plexi publishes **107 namespaces**. Of those:

- **12 publish a `log_directory`** — the only ones a third party can verify
  independently. Two are witnessed here (Messenger, WhatsApp v2); the rest are
  `Disabled`, `test.*`, or unattributed `cf-kt-msgr` deployments.
- **95 do not.** They are Online with a root, but the *only* source of that root
  is plexi's own word. Witnessing one would attest to what Cloudflare says about
  Meta rather than to anything Meta published, which is not a transparency
  claim. **These are deliberately not witnessed.**

That distinction is the useful output of the survey: the number of KT logs that
*look* auditable is an order of magnitude larger than the number that are.

## Software and artifact transparency

| System | Format | Status |
|---|---|---|
| **Apple AT (PCC)** | Apple protobuf | **witnessed**, and the only Apple tree with verifiable inclusion proofs |
| **Go checksum database** | C2SP signed note | **Verified live**: serves a note over `go.sum database tree`, size 61,882,169. Needs two small changes — the checkpoint is at `/latest`, not `/checkpoint`, and tiles use the older sumdb layout rather than `tlog-tiles`. |
| **Sigstore Rekor** | signed note | **Partly verified**: `rekor.sigstore.dev/api/v1/log` returns a signed tree head, and Rekor v2 answers `/api/v2/checkpoint` with HTTP 200. Not yet verified through an adapter. |
| **sigsum** | own format | **Verified reachable**: `get-tree-head` returns size, root, signature and **three cosignatures** — it already has a witness network, and its own witnessing protocol. A separate adapter, and arguably a place to join rather than duplicate. |
| Android binary transparency | tlog-tiles | Unverified; believed to be a Sunlight-family log |
| npm / PyPI attestations | Rekor-backed | Covered transitively by witnessing Rekor |

Note the Go checksum database is a *good* target despite the small adapter work:
it is the single point of trust for the entire Go module ecosystem, and it has
few independent witnesses.

## What is worth doing next, and why

Ordered by assurance gained per unit of work.

1. **Nothing — deploy.** Ten origins are verified and none is running. Breadth
   multiplies the value of an operating witness and multiplies nothing at all
   otherwise. This is still the binding constraint.
2. **Proton's construction audit inside the loop.** Validated as a command;
   needs a scheduler and 13.6 GB of retained state.
3. **Go checksum database.** Small, well-specified, high-value, few witnesses.
4. **The remaining 77 CT logs.** Pure configuration.
5. **Rekor.** Verify the checkpoint through the adapter; if it is a plain note,
   it is configuration too.
6. **sigsum.** Its own protocol, and it already has witnesses — join the network
   rather than reimplement it.

## What is deliberately excluded

- **Any `test.*` or `Disabled` namespace.** A cosignature on a test log pollutes
  the published surface.
- **Logs whose only root source is a third party's assertion.** Ninety-five
  plexi namespaces fall here. Witnessing them would relay trust, not verify it.
- **Ecosystems with mature witness networks** where the marginal witness adds
  little — noted rather than built, so the effort goes where coverage is thin.
