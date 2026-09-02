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
      keys Apple does not publish, and not tied to the root we verify. Blocked on
      a capability, not an encoding: Apple's auditor service declares no generic
      log-inclusion RPC. Watch for `logLeavesForRevision` appearing in the
      researcher bag; its response carries leaves *with* inclusion proofs and
      would solve this outright. The tree is RFC 6962, so folding a proof needs
      no new cryptography.
- [x] **ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381).** Done — `internal/vrf`,
      verification only. Passes all three RFC 9381 vectors including the
      intermediate hash-to-curve point, and verifies a live proof from Signal's
      production service.
- [ ] **Signal: prefix-tree audit (tier B).** The largest remaining assurance
      gap, since Signal is tier A only — head-consistency, which cannot see an
      illegal mutation. The VRF half is done; what remains is the prefix tree and
      the combined-tree search proof, both of which arrive in the same
      unauthenticated `distinguished` response (field 2, ~300 KB).
      Note the sampling argument does not carry over: Signal's proofs are
      per-*label*, not per-epoch, so a third party can only audit labels it can
      name. Full coverage still needs the operator's auditor feed.
- [x] **Proton: tree re-verification (tier B).** Done — `kt-proton-audit`
      rebuilds all 200,714,006 leaves and matches the signed tree hash.
- [ ] **Run Proton tier B continuously.** The pieces exist (`ApplyDiff` merges
      the ~3 MB per-epoch delta), but the loop is not wired: it needs the 13.6 GB
      tree kept on disk between epochs, and an end-to-end run of
      dump &rarr; diff &rarr; rebuild against a *later* epoch's signed hash. Only
      the one-shot full audit has been validated against production so far.
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
- [ ] **Second-writer safety.** The store assumes a single writer. Two containers
      on one volume would corrupt state; nothing currently prevents it.

## Ecosystem

- [ ] **Publish the AKD → signed-note canonicalisation as a spec.** The mapping
      that lets the existing witness network consume a KT log is the reusable
      part of this project, and it is currently only code.
- [ ] **Gossip with other witnesses.** Cross-witness comparison is how split
      views are actually caught, and it would subsume the beacon-canonicalisation
      problem above.
- [ ] **WhatsApp.** Not a config copy-paste: `whatsapp.key-transparency.v1`
      reports status `Disabled` with inconsistent epochs. Check `v2` first.
- [ ] **IETF keytrans.** Revisit when a public deployment exists. The draft
      specifies no transport, so there is currently nothing to be conformant to
      on the wire.
