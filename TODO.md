# TODO

Ordered by what would most improve what we can honestly claim. Background and
reasoning for most of these is in [NOTES.md](NOTES.md).

## Before anyone relies on this witness

- [ ] **Move the signing key to hardware.** It is currently a file on disk. That
      is acceptable for a first unattended run and not acceptable once others
      list the key in a trust policy. Ecosystem norm is a TKey or Armored-Witness
      class device.
- [x] **Pin the `tlog-witness` origin-hash encoding.** Resolved by checking:
      c2sp.org/tlog-witness specifies only `POST <submission prefix>/add-checkpoint`
      and never defines what the prefix contains, so there is nothing to pin to.
      Accepting both encodings is the considered design, and now says so.
- [ ] **Publish the verifier key** at a stable location and get it into consumer
      trust policies. Deliberately last of these three: publishing is what
      invites people to depend on us.

## Raising assurance

- [ ] **Apple: bind per-application heads to the verified root.** iMessage heads
      are read from Top-Level Tree leaves but are only *observations* — signed by
      keys Apple does not publish, and not tied to the root we verify.
      Blocked, and now for a documented reason rather than a symptom:
      `list_trees` returns the same three trees for every application value and
      none of them is IDS_MESSAGING, and `log_inclusion_proof` rejects
      `application=IDS_MESSAGING` with `INVALID_REQUEST`. See
      [docs/apple.md](docs/apple.md).
      Watch the init bag for `at-researcher-log-leaves-for-revision`: it is
      declared in Apple's proto but absent from the live bag, and its response
      carries leaves *with* inclusion proofs, which would solve this outright.
- [x] **Apple: witness the PCC Apple Transparency log.** Done — `apple.com/at/pcc`
      is the seventh origin: signed head under its own key, consistency proofs,
      leaf reads and inclusion proofs, all verified live with negative controls
      (`internal/source/apple/atlog_live_test.go`). It is the strongest Apple
      assertion available — stronger than what we publish for the Top-Level Tree.
- [x] **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381).** Done — `internal/vrf`,
      verification only. Passes all three RFC 9381 vectors including the
      intermediate hash-to-curve point, and verifies a live proof from Signal's
      production service.
- [x] **Signal: search-proof verification.** Done — every fetch opens the
      `distinguished` key and checks VRF, prefix tree, batch inclusion and
      commitment down to a root three auditors and Signal's signature already
      agree on. Validated live with six negative controls.
      The tier stays A deliberately: Signal's proofs are per-*label*, so a third
      party can only audit labels it can name, and no number of spot checks is a
      construction audit. Full coverage still needs the operator's auditor feed.
- [x] **Signal: between-snapshot check.** Done — `entryLedger` records the leaf
      hash of every entry a verified search opens and refuses a later proof that
      contradicts one. This is the only Signal check that can see an entry's
      contents change.
- [x] **Persist the Signal entry ledger.** Done — a `log_entries` bucket, loaded
      once on first use, bounded at 65,536 per origin keeping the lowest ids —
      those are the entries a search revisits, while the frontier churns.
- [ ] **Promote a contradicted Signal entry to a fork.** The ledger currently
      withholds. The evidence would justify accusing — two proofs, both rooted in
      heads Signal signed, disagreeing about an immutable log position — but the
      tree math is a fresh reimplementation and a fork is permanent and public.
      Promote once this has a production record.
- [ ] **Signal: monitor proofs.** Not reachable by a witness. `/monitor` is
      unauthenticated but requires an ACI: it rejects `distinguished` at the
      parser (HTTP 422) and returns 403 for a well-formed but unknown ACI. Would
      need an account. The entry ledger stands in for it.
- [x] **Proton: tree re-verification (tier B).** Done — `kt-proton-audit`
      rebuilds all 200,714,006 leaves and matches the signed tree hash.
- [x] **Proton between-snapshot audit.** Done and validated end to end:
      `kt-proton-audit -from 6708 -epoch 6709` applies the published 3 MB diff to
      epoch 6708's tree and reproduces 6709's signed hash exactly. Merge 37 s,
      rebuild 18m45s.
- [ ] **Run Proton tier B inside the witness loop.** The audit works as a
      command; the witness process does not yet run it every epoch. Needs the
      13.6 GB tree kept on disk between epochs and a scheduler that tolerates a
      ~19-minute job against a ~4-hour epoch cadence.
- [ ] **Judge Proton's removals.** Epoch 6709 alone removed 9,337 leaves.
      Proton permits deletion within a ~90-day window, so the audit should check
      each removal against that window rather than merely counting it.
- [ ] **Proton: confirm certificates in a CT log** rather than trusting their
      embedded SCTs. Proton's whole design leans on CT as the equivocation
      channel, so this closes the loop it was built around.
- [ ] **Meta: verify Meta's own signature.** Today the head is *derived* from
      object listings, not signed, which is why `DerivedHead()` is true and head
      regressions are withheld rather than accused. If a key ever becomes
      pinnable, flip that and the stronger treatment returns.

## Correctness and operability

- [ ] **Canonicalise the beacon round for tier-B sampling.** Selection currently
      uses whichever drand round was latest at decision time. Rounds are 3 s
      apart, so a dishonest witness could redraw until an epoch it wanted to skip
      deselects. Either pin the canonical round as a function of the epoch, or —
      more likely better — solve it by gossip between witnesses, which also makes
      coverage compose. See NOTES.md.
- [x] **Retention for the `audits` bucket.** Done — 200,000 decisions per origin,
      oldest dropped first. bbolt never returns freed pages to the filesystem,
      so an unbounded bucket was a slow leak.
- [x] **Alert on sustained withholding.** Done — escalates to ERROR after 20
      consecutive failures, exports `kt_witness_consecutive_withheld`, and a
      Grafana alert fires on it. Occasional withholding is the system working;
      sustained withholding was indistinguishable from it in a stream of WARNs.
- [ ] **Export the search-proof and ledger state.** The file mirror in
      `internal/export` publishes heads, audits and forks but says nothing about
      what the Signal search proofs opened. A witness's product is evidence other
      people can read, so state that only exists in log lines is half-published.
- [x] **Second-writer safety.** Already safe: bbolt takes an exclusive flock, so
      a second process blocks rather than corrupting. The opaque "timeout" it
      produced now names the actual cause.

## Ecosystem

- [x] **Publish the AKD → signed-note canonicalisation as a spec.** Done —
      [docs/akd-checkpoint.md](docs/akd-checkpoint.md), precise enough for an
      independent implementer to produce byte-identical checkpoints.
- [ ] **Pin the minted origin strings in code, not config.** Writing the spec
      surfaced this: an origin like `meta.messenger.kt/v1` exists only in
      `witness.json`, so two operators running this witness could mint different
      origins for the same log and produce cosignatures nobody can aggregate.
      Aggregation is the entire point of a shared canonicalisation. The spec now
      fixes the convention; the code should enforce it.
- [ ] **Consume other witnesses' cosignatures.** The strongest split-view
      evidence available is not our own observation but a *disagreement between
      independent witnesses*: a log that shows us one history and
      `witness.stagemole.eu` another has equivocated, and neither of us can see
      that alone. Several logs we already witness carry cosignature lines from
      other witnesses in the checkpoint we fetch — those are free datapoints we
      currently parse past and discard.
      Concretely: verify the other witnesses' cosignature lines on every
      checkpoint we fetch, record what each of them attested at what size, and
      compare against our own view. A same-size-different-root disagreement with
      a witness whose key we can verify is a conclusive contradiction, and one
      we can reproduce for a third party.
      This is strictly easier than the full gossip protocol below, needs no
      cooperation from anyone, and uses bytes already on the wire. Start here.
- [ ] **Gossip with other witnesses.** Cross-witness comparison is how split
      views are actually caught, and it would subsume the beacon-canonicalisation
      problem above.
- [x] **WhatsApp.** Done — `whatsapp.key-transparency.v2` is Online with a
      public log directory and needed no code at all. v1 stays untouched
      (`Disabled`). Tier B verified feasible: one real proof through the
      existing sidecar in 2.7 s. Cost differs from Messenger — 30 s epochs at
      ~58.5 MB, so ~17 GB/day at the 0.1 sample rate.
- [x] **Witness the static CT logs.** Done — `cmd/kt-ctconfig` generates the
      config from Google's list and verifies each checkpoint signature before
      including it. 80 tiled logs → **69 witnessed**, 11 excluded (5 `rejected`,
      6 past their temporal window), 0 verification failures.
      It also caught that two of the three hand-picked logs were already dead:
      Geomys Tuscolo2026h1 is `rejected` and LE Twig2026h1's window ended
      2026-06-16, so we had been cosigning heads that can never move.
- [x] **Go checksum database.** Done — witnessed at `go.sum database tree`.
      torchwood already covered the sumdb tile layout (`WithTilePath` plus
      `ReadSumDBEntry`), so no custom reader was needed; the adapter gained a
      configurable checkpoint path and tile layout. Verified live at size
      61,921,367 including all 1,000 new entries, with a negative control that
      is refused as a `ForkError`.
      Configured at tier A on purpose: at that size a first-observation entry
      sweep would read ~242k data tiles.
- [ ] **Sigstore Rekor.** `/api/v2/checkpoint` answers 200 and v1 serves a
      signed tree head; verify one through the adapter and it is likely
      configuration. Witnessing Rekor covers npm and PyPI attestations
      transitively.
- [ ] **sigsum.** Its own protocol, and it already has a witness network —
      joining is probably worth more than reimplementing.
- [ ] **IETF keytrans.** Revisit when a public deployment exists. The draft
      specifies no transport, so there is currently nothing to be conformant to
      on the wire.
