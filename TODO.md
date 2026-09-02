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
- [ ] **Signal: prefix-tree audit (tier B).** Verifies that individual
      identifier-to-key bindings sit where they should. Needs ECVRF and the
      combined-tree search proof. Note the sampling argument does not carry over:
      Signal's proofs are per-*label*, not per-epoch.
- [ ] **Proton: tree re-verification (tier B).** Proton's own §3.11 external
      audit. ~13.6 GB initial dump plus ~4 MB per epoch, ~16 GB RAM.
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
