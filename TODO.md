# TODO

Ordered by what would most improve what we can honestly claim. Background and
reasoning for most of these is in [NOTES.md](NOTES.md).

## Before anyone relies on this witness

- [ ] **Move the signing key to hardware.** It is currently a file on disk. That
      is acceptable for a first unattended run and not acceptable once others
      list the key in a trust policy. Ecosystem norm is a TKey or Armored-Witness
      class device.
- [ ] **Pin the `tlog-witness` origin-hash encoding.** `internal/server`
      currently answers to *both* hex and unpadded base64url of SHA-256(origin)
      because the spec text was never confirmed. Decide, drop the other.
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
- [ ] **Apple: witness the PCC Apple Transparency log.** Newly reachable and
      fully validated — signed head under its own key, consistency proofs, leaf
      reads, and inclusion proofs, all verified live with negative controls
      (`internal/source/apple/atlog_live_test.go`). It would be the strongest
      Apple assertion available, stronger than what we publish for the Top-Level
      Tree. It is *software* transparency rather than key transparency, so
      whether it belongs in a KT witness's cosigning set is a positioning call,
      not a technical one.
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
- [ ] **Persist the Signal entry ledger.** It lives in memory, so a restart
      loses it and between-snapshot coverage is per-process — and deployment
      restarts containers. It belongs in the store alongside the heads.
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
- [ ] **Retention for the `audits` bucket.** Grows ~300 KB/day forever. Fine for
      years; still unbounded. Note bbolt does not reclaim space without
      compaction.
- [ ] **Alert on sustained withholding.** A log that never verifies is currently
      only visible as repeated log lines. Withholding is the enforcement
      mechanism, so a persistent one is exactly what a human should see.
- [ ] **Export the search-proof and ledger state.** The file mirror in
      `internal/export` publishes heads, audits and forks but says nothing about
      what the Signal search proofs opened. A witness's product is evidence other
      people can read, so state that only exists in log lines is half-published.
- [ ] **Second-writer safety.** The store assumes a single writer. Two containers
      on one volume would corrupt state; nothing currently prevents it.

## Ecosystem

- [ ] **Publish the AKD → signed-note canonicalisation as a spec.** The mapping
      that lets the existing witness network consume a KT log is the reusable
      part of this project, and it is currently only code.
- [ ] **Gossip with other witnesses.** Cross-witness comparison is how split
      views are actually caught, and it would subsume the beacon-canonicalisation
      problem above.
- [x] **WhatsApp.** Done — `whatsapp.key-transparency.v2` is Online with a
      public log directory and needed no code at all. v1 stays untouched
      (`Disabled`). Tier B verified feasible: one real proof through the
      existing sidecar in 2.7 s. Cost differs from Messenger — 30 s epochs at
      ~58.5 MB, so ~17 GB/day at the 0.1 sample rate.
- [ ] **Witness the remaining 77 static CT logs.** All 80 in Google's list
      verify; three are configured. Pure configuration from here, but the load
      and the question of whether more CT witnesses are wanted are operational
      decisions. See [docs/landscape.md](docs/landscape.md).
- [ ] **Go checksum database.** Serves a C2SP note and is the single point of
      trust for the whole Go module ecosystem, with few independent witnesses.
      Needs two small changes: its checkpoint is at `/latest` rather than
      `/checkpoint`, and its tiles use the older sumdb layout rather than
      `tlog-tiles`.
- [ ] **Sigstore Rekor.** `/api/v2/checkpoint` answers 200 and v1 serves a
      signed tree head; verify one through the adapter and it is likely
      configuration. Witnessing Rekor covers npm and PyPI attestations
      transitively.
- [ ] **sigsum.** Its own protocol, and it already has a witness network —
      joining is probably worth more than reimplementing.
- [ ] **IETF keytrans.** Revisit when a public deployment exists. The draft
      specifies no transport, so there is currently nothing to be conformant to
      on the wire.
