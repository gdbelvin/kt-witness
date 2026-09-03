# TODO

Ordered by what would most improve what we can honestly claim. Background and
reasoning for most of these is in [NOTES.md](NOTES.md).

## Status

Everything reachable by writing code is done. What remains falls into three
kinds, and the distinction matters more than the count:

**Blocked on someone else** — no amount of work here moves these. A YubiKey
5.7+ (this key is 5.2.7, and PIV Ed25519 needs 5.7); Apple deploying an RPC
that exists in their proto but not their service; Signal's `/monitor` requiring
an account; Meta publishing a pinnable key; another witness serving the signed
checkpoints it already holds; IETF keytrans having any public deployment.

**Watch these automatically, don't re-check them by hand.** `cmd/kt-unblock`
probes each precondition above and reports which have become reachable. It
exists because the real failure mode is not being blocked — it is a conclusion
going stale unnoticed. Production Sigstore Rekor v2 had been live since
2025-09-23 while this file still said "wire it the day a production v2 endpoint
exists"; the earlier check had found only the staging instance and was never
revisited. Witnessing it turned out to need no new code at all.

    go run ./cmd/kt-unblock          # or -json for monitoring

"Still blocked" is the expected result and exits 0, so this is safe to run on a
schedule without training anyone to ignore it.

**Deliberately deferred** — promoting a contradicted Signal entry to a fork
waits for a production record, because a fork is permanent and public and the
tree math is a fresh reimplementation. Publishing the verifier key waits for
hardware, because publishing is what invites people to depend on it.

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
- [x] **Signal: account monitoring.** DONE — verified against production.
      The blocker was never "unauthenticated access" — `/search` answers a bare
      request from anywhere — but that it requires an `aci` AND an
      `aciIdentityKey`, and the identity key is a real cryptographic input (the
      tree's commitment is over it) held only by a registered device. The
      operator supplied both from Signal Desktop; they live in 1Password and
      reach the process through the environment, never the config file.
      `internal/source/signal/account.go` searches the account on an interval
      and runs the same three-way check plus VRF, prefix tree, batch inclusion
      and commitment opening, requiring the proof to resolve to the root the
      signed head and the auditors already agree on. The ACI search key is
      `b"a"` + the bare 16 UUID bytes, taken from libsignal — the ACI branch
      deliberately omits the ServiceId kind byte, which is the detail that would
      otherwise fail at the VRF with no useful diagnostic.
      Two rules are pinned by tests: a transport failure (rate limit, timeout,
      5xx) must NOT withhold the cosignature, or Signal could silence its own
      auditor by throttling it; and the ACI never appears in logs or published
      output, only a stable hash.
      **This does not raise the tier**, and is not a step towards it. It moves
      per-label coverage from one label to two out of hundreds of millions. Its
      value is a second, independent exercise of the verification path against
      an ordinary entry rather than the one label every client checks.
      Live: the account proof verifies at tree size 860,072,136, resolving to a
      different tree index from the distinguished entry, so a genuinely second
      point in the tree is being exercised.
      Three bugs fell out of writing the tests, all worth remembering.
      The account search reused the distinguished verification path and so
      overwrote `lastSearch`, silently changing what "the last search" meant for
      every reader of it. The first negative control asked for a *different*
      ACI and was testing the wrong system — Signal answers HTTP 403 for an ACI
      that is not the caller's, so the proof machinery is never reached; the
      control now perturbs the search KEY against a genuine response, and also
      checks the `a` type prefix is bound by swapping in the e164 prefix.
      And the VRF failure formatted the search key with `%q`, printing the raw
      ACI bytes into an error — found by reading the negative control's own
      output. `TestNoErrorLeaksTheSearchKey` now drives the verifier into
      several failure paths and asserts no message carries the identifier in
      raw, hex or string form.
- [x] **Proton: tree re-verification (tier B).** Done — `kt-proton-audit`
      rebuilds all 200,714,006 leaves and matches the signed tree hash.
- [x] **Proton between-snapshot audit.** Done and validated end to end:
      `kt-proton-audit -from 6708 -epoch 6709` applies the published 3 MB diff to
      epoch 6708's tree and reproduces 6709's signed hash exactly. Merge 37 s,
      rebuild 18m45s.
- [x] **Run Proton tier B inside the witness loop.** Done —
      `proton.IncrementalAuditor` retains the tree between epochs so each step
      is a 3 MB diff rather than a 13.6 GB download, and the witness runs it on
      its own goroutine at a 30-minute cadence against Proton's ~4-hour epochs.
      Safety is in the file handling: a partial download or interrupted merge is
      never picked up as a tree (it would rebuild to a wrong root and read as
      Proton misbehaving), the old base is removed only once its successor is in
      place, and an audit refuses to start below a free-space floor — filling
      the volume would stop the witness, which is worse than an unaudited epoch.
      A mismatch retains the evidence on disk and reports; it does not poison
      the log without a human.
- [x] **Judge Proton's removals.** Done — a removal is explained when its
      `minEpochID` predates the removing epoch's published `StartEpochID`.
      Verified live across five epochs and 45,816 removals: all explained, with
      the largest removed epoch landing exactly on the window boundary. The rule
      is inferred from behaviour rather than promised, so a failure withholds
      and is published, never accused.
- [x] **Proton: confirm certificates in a CT log.** Done — the precertificate's
      RFC 6962 Merkle leaf is rebuilt and matched against the hash the CT log's
      own signed checkpoint carries at the index the SCT names, verified from
      tiles locally rather than by asking the log for a proof or trusting the
      SCT's promise. Confirmed live: epoch 6712's certificate is entry
      593,786,554 of `tuscolo2026h2.sunlight.geomys.org`.
      Only verified against one CA shape so far; a differently encoded
      certificate would withhold rather than corrupt, which is the right
      failure mode but is unproven.
- [ ] **Meta: verify Meta's own signature.** Today the head is *derived* from
      object listings, not signed, which is why `DerivedHead()` is true and head
      regressions are withheld rather than accused. If a key ever becomes
      pinnable, flip that and the stronger treatment returns.

## Correctness and operability

- [x] **Canonicalise the beacon round for tier-B sampling.** Done — the round is
      now `RoundAt(decidedAt)`, the first quicknet round strictly after the
      moment the decision was settled, derived from the published chain genesis
      and 3 s period. Both properties hold at once: the round postdates
      publication so the operator cannot predict the sample, and it is
      determined rather than chosen so we cannot re-draw. A decision already on
      record keeps its original round, since re-deriving would itself be a
      re-draw.
      Residual risk, worth being honest about: the witness still chooses the
      *timestamp* it records. Falsifying that is far harder than silently
      retrying — it means publishing a false time that a third party can check
      against the epoch's own publication — but gossip is still the complete
      answer.
- [x] **Retention for the `audits` bucket.** Done — 200,000 decisions per origin,
      oldest dropped first. bbolt never returns freed pages to the filesystem,
      so an unbounded bucket was a slow leak.
- [x] **Alert on sustained withholding.** Done — escalates to ERROR after 20
      consecutive failures, exports `kt_witness_consecutive_withheld`, and a
      Grafana alert fires on it. Occasional withholding is the system working;
      sustained withholding was indistinguishable from it in a stream of WARNs.
- [x] **Export the search-proof and ledger state.** Done —
      `searches/<log>.json` carries the last verified search proof and
      `entries/<log>.jsonl` the cross-observation ledger, both with notes
      stating what they do *not* prove: a per-label spot check is not a
      construction audit, and a missing entry id means "unrecorded", never
      "absent from the log". The file mirror in
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
- [x] **Pin the minted origin strings in code, not config.** Done —
      `internal/source/origins.go` defines the canonical spellings and every
      minting adapter rejects anything else at construction. Logs that sign
      their own checkpoints are untouched: the origin is in the note, so it is
      theirs to choose and not ours to police.
- [x] **Consume other witnesses' cosignatures.** The strongest split-view
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
      **Done.** `internal/cosig` verifies other witnesses' cosignature lines on
      every checkpoint we fetch, the store records what each attested at each
      size, and two signed attestations disagreeing at one size is escalated as
      a split view. Verified live: `witness.stagemole.eu` attests
      `thelemail.com/keys` at size 99 with root `jm6wmVaB…`, read from bytes we
      were downloading anyway.
      A disagreement is reported, not acted on: the evidence does not say which
      party was served the false history, and poisoning a log on the strength of
      a signature we merely relayed needs a human first.
- [ ] **Ask upstream for a signed peer-view endpoint.** The missing piece for
      real gossip is small: litewitness already holds the signed checkpoints it
      has cosigned, but serves only `POST /add-checkpoint` — every retrieval
      path 404s. An endpoint returning the checkpoint a witness holds would make
      cross-witness detection conclusive, because the convicting signature is
      the *log's own*: two log signatures over different roots at one size is
      the log convicting itself, needing nobody to be trusted.
- [~] **Gossip with other witnesses.** Cross-witness comparison is how split
      views are actually caught, and it would subsume the beacon-canonicalisation
      problem above.
      **Detection half done** — the witness now polls peers' published views
      hourly and reports a peer publishing a different root at a size we also
      hold (`startPeerPolling` in cmd/kt-witness, `internal/cosig/peer.go`).
      That is the part that is possible today, and it is the part that matters:
      cosignatures read off a checkpoint *we* fetched cannot detect a split view
      at all, because every signature there sits over the same body and agrees
      by construction. Only an independently obtained view can differ.
      It stays **detection only**, and cannot become more until the item below
      lands: peer status pages are unsigned, so a divergence is the cue to go
      and obtain the signed artifact, never something to publish. The witness
      does not accuse on unsigned evidence.
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
- [x] **Sigstore Rekor.** DONE — production Rekor **v2** is live and is now
      witnessed as `log2025-1.rekor.sigstore.dev`, at 93 million entries.
      The item said "wire it the day a production v2 endpoint exists". It does:
      the Sigstore TUF trusted root lists exactly two active tlogs, and the
      second is `log2025-1.rekor.sigstore.dev` (`PKIX_ED25519`, valid from
      2025-09-23), serving `/api/v2/checkpoint` and `/api/v2/tile/...`.
      The pleasing part is that it needed **no new code at all**. v2 signs a
      bare signed note with plain Ed25519 and serves tlog-tiles, so it is just
      a `c2sp` log with a vkey — none of the bespoke machinery v1 forced is
      required. Tier A, with real consistency proofs.
      `internal/rekor` (the v1 ECDSA verifier — bare `SHA-256(SPKI)[:4]` key
      hash, DER ECDSA over the body including its trailing newline) is retained
      and still passing, but is **not** wired: v1 remains unwitnessable, because
      it wraps its note in a JSON envelope and serves no tiles, so there is
      nothing to build a consistency proof from. That is a property of v1, not
      an outstanding task — v2 is where Sigstore is going.
- [x] **sigsum.** DONE — and the judgement call dissolved on contact with the
      source. Modern sigsum signs a C2SP checkpoint body
      (`sigsum.org/v1/tree/<hex sha256(key)>`) with plain Ed25519, and its
      cosignatures are literally `cosignature/v1`. It is not a separate
      ecosystem; it is a note-carrying log wearing an ASCII transport. So there
      was nothing to reimplement and nothing to join: `internal/source/sigsum`
      transcodes `get-tree-head` into the equivalent signed note and hands it to
      the machinery that was already there.
      Witnessing all four logs in sigsum's built-in policies at tier A —
      `seasalp.glasklar.is`, `ginkgo.tlog.mullvad.net`,
      `serviceberry.tlog.stagemole.eu` and `test.sigsum.org/barreleye` —
      with append-only proven from the log's own `get-consistency-proof`.
      See docs/sigsum.md.
- [ ] **IETF keytrans.** Revisit when a public deployment exists. The draft
      specifies no transport, so there is currently nothing to be conformant to
      on the wire.
