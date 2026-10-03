# IETF Key Transparency

`ietf-keytrans/<sha256 of the log's Configuration>`, **tier A**.

Generic mechanism is in [design.md](design.md); this covers only what is
peculiar to logs speaking draft-ietf-keytrans-protocol-05.

## There is still no public deployment

The draft specifies no transport, so "an IETF KT log" is not something this
witness can find on the internet. The adapter speaks the HTTP binding of the
keytrans reference log (`POST /v1/distinguished`, TLS-encoded bodies), which
GDB Security operates. When another deployment appears it will need its own
transport shim, but everything from the response bytes inward is the draft's.

## It is the Signal adapter's protocol, grown up

Signal's KT is an early version of this protocol by the same author. The log
tree is identical down to the tag byte in each node hash: `H(tag || left ||
tag || right)`, 0 for a leaf and 1 for an interior node. Three things differ:

- **Proof shape.** IETF proofs carry only heads of *balanced* subtrees, and
  batch inclusion, consistency and the auditor's root into one list. So
  verification is one recursion that decides per node whether the value is
  retained, computable, or the next proof element, rather than RFC 6962's
  consistency walk.
- **What the verifier must remember.** A consistency proof is checked against
  the previous head's full subtree hashes *and* the timestamp and prefix root
  of each entry on its frontier, not just its root. The adapter keeps the
  last few such views in the witness database (`source_state` bucket). A
  witness that loses them cannot prove the next head and withholds until it
  re-observes the log from scratch.
- **Identity.** Every signature covers the log's full `Configuration`: keys,
  mode and parameters. The origin is derived from its hash, as sigsum's is
  derived from its key, so every witness of a log mints the same origin
  without anyone choosing a name.

## How a head is fetched

A Distinguished request with a stop position past the end of the log. That
walk (§10.1) recurses only down the right spine and stops at each entry, so it
touches nothing but frontier entries, whose timestamps the §4.2 view update
already carries. The response is therefore exactly the view update: no prefix
proofs, one prefix root per served timestamp, and the log tree proof. The
adapter checks that shape strictly rather than parsing a general response.

## What is checked

- The log's signature over `TreeHeadTBS`: the pinned Configuration, size and
  root, where the root is derived from the retained view and the proof. A
  failure here, with a retained view, is the consistency check failing.
- Timestamps never decrease with position.
- In third-party auditing mode, the auditor's signature over the root at its
  own size (derived from the same proof), and that it trails the log by no
  more than `max_auditor_lag`. The auditor is recorded as a cosigner.

Not checked: that each prefix tree was built correctly from the last. That is
the third-party auditor's job (§15.2), and would be this adapter's tier B.

## Testing

`testdata/` holds real exchanges recorded from the reference log by its
`cmd/keytrans-fixtures`, in both contact-monitoring and auditing modes: a first
observation, two growth steps, an unchanged head, a fresh view, and a fork (a
log under the same keys whose history diverges after genesis). The fake log in
the tests only answers requests it recorded, so the adapter's request encoding
is checked byte for byte. Every byte of a recorded response is flipped in turn
and each corruption must be rejected.

It has also run end to end as processes: keytrans-server on disk, its auditor,
and `kt-witness -once` per round, across a log restart, and against the same
log wiped and rebuilt under the same keys, which was refused.

## Config

```json
{
  "type": "keytrans",
  "endpoint": "https://kt.example.com",
  "configuration": "<hex of the encoded Configuration, pinned out of band>"
}
```

`origin` may be given; if so it must equal the derived one.
