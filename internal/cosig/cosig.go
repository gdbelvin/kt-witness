// Package cosig reads other witnesses' cosignatures off the checkpoints we
// already fetch.
//
// # What this actually establishes, and what it does not
//
// It is worth being exact, because an earlier version of this comment
// overclaimed and the distinction is the whole point.
//
// The signature that can convict a log is the LOG'S OWN. A checkpoint body
// carries (origin, size, root) and the log signs it; witnesses countersign that
// same body. Two log signatures over different roots at one size is the log
// contradicting itself, and that is conclusive and attributable.
//
// A cosignature read off a checkpoint WE fetched does not give that. Both
// signatures — ours and theirs — sit on the same document, so they cannot
// disagree with each other by construction. What this establishes is
// CORROBORATION: another witness, whose key we hold independently, has seen and
// vouched for the same history we are looking at. That is genuinely useful —
// it is evidence the log is not showing us a private view — but it is not
// detection, because a log serving two histories would simply put a different
// set of cosignatures on each.
//
// Detecting the split needs the other witness's INDEPENDENTLY OBTAINED
// checkpoint, carrying the log's signature over their view. See peer.go for why
// that is not fetchable today and what would make it so.
//
// # Why it is nearly free
//
// Those cosignatures are already in the bytes we download. A C2SP checkpoint
// carries one signature line per witness that has cosigned it, and until now we
// parsed straight past them to reach the log's own signature. Reading them
// costs no extra request, no cooperation from anyone, and no protocol beyond
// the one already in use — which makes it strictly easier than the gossip
// arrangement it approximates.
//
// # What it is not
//
// Absence of another witness's cosignature is not evidence: they may be behind,
// may not watch this log, may be down. Only a positive disagreement counts,
// which is the same rule the rest of this project follows.
package cosig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

// Observation is one other witness's attestation, read from a checkpoint.
type Observation struct {
	// Witness is the cosigner's name, from its verifier key.
	Witness string
	// Origin, Size and Root are what that witness attested.
	Origin string
	Size   int64
	Root   string
	// Timestamp is the cosignature's own timestamp, which is what makes it a
	// liveness signal rather than a bare endorsement.
	Timestamp uint64
}

// Verifier holds the witnesses whose cosignatures we are prepared to believe.
//
// A cosignature from a key we cannot verify is worth nothing — anyone can write
// any name on a note line — so unknown signers are ignored rather than recorded.
type Verifier struct {
	byName map[string]*torchwood.CosignatureVerifier
}

// NewVerifier builds a verifier from C2SP cosignature verifier keys.
func NewVerifier(vkeys []string) (*Verifier, error) {
	v := &Verifier{byName: make(map[string]*torchwood.CosignatureVerifier, len(vkeys))}
	for _, k := range vkeys {
		cv, err := torchwood.NewCosignatureVerifier(k)
		if err != nil {
			return nil, fmt.Errorf("cosig: parse witness key %q: %w", k, err)
		}
		v.byName[cv.Name()] = cv
	}
	return v, nil
}

// Names lists the witnesses this verifier knows.
func (v *Verifier) Names() []string {
	out := make([]string, 0, len(v.byName))
	for n := range v.byName {
		out = append(out, n)
	}
	return out
}

// Observe verifies every cosignature on a checkpoint that comes from a witness
// we know, and returns what each of them attested.
//
// Signatures from unknown witnesses, and lines that do not verify, are skipped
// silently: a forged line costs an attacker nothing to add, so its presence is
// not information. Only a line that verifies under a key we hold is evidence.
func (v *Verifier) Observe(origin string, signedNote []byte) ([]Observation, error) {
	if len(v.byName) == 0 {
		return nil, nil
	}
	list := make([]note.Verifier, 0, len(v.byName))
	for _, cv := range v.byName {
		list = append(list, cv)
	}
	verifiers := note.VerifierList(list...)

	// note.Open with UnverifiedNote semantics: we want the signatures that DO
	// verify, and do not care that others do not — the log's own signature has
	// already been checked by the caller, which is what makes the body
	// trustworthy enough to read a size and root out of.
	n, err := note.Open(signedNote, verifiers)
	if err != nil {
		// No cosignature we can verify. Not a finding: the other witnesses may
		// simply not watch this log.
		return nil, nil
	}

	size, root, ok := parseBody(n.Text, origin)
	if !ok {
		return nil, fmt.Errorf("cosig: checkpoint body for %s is not parseable", origin)
	}

	out := make([]Observation, 0, len(n.Sigs))
	for _, sig := range n.Sigs {
		if _, known := v.byName[sig.Name]; !known {
			continue
		}
		ts, err := cosignatureTimestamp(sig.Base64)
		if err != nil {
			// A verified signature whose timestamp will not parse is odd enough
			// to skip rather than record with a wrong time.
			continue
		}
		out = append(out, Observation{
			Witness: sig.Name, Origin: origin,
			Size: size, Root: root, Timestamp: ts,
		})
	}
	return out, nil
}

// parseBody reads size and root from a checkpoint body, requiring the origin to
// match: a correctly cosigned checkpoint for a different log says nothing about
// this one.
func parseBody(text, wantOrigin string) (size int64, root string, ok bool) {
	lines := strings.SplitN(text, "\n", 4)
	if len(lines) < 3 || lines[0] != wantOrigin {
		return 0, "", false
	}
	var n int64
	if _, err := fmt.Sscanf(lines[1], "%d", &n); err != nil {
		return 0, "", false
	}
	return n, lines[2], true
}

// Conflict reports two attestations of different roots at one size.
//
// This is conclusive ONLY when both carry the log's own signature over their
// respective bodies: a log cannot have signed two roots at one size, and that
// is the log convicting itself. Two witness cosignatures on the same document
// can never reach this state, so in practice it is reachable only once peer
// checkpoints can be fetched — see peer.go.
//
// Which party was served the false history is not determined by the evidence.
// Only that somebody was.
type Conflict struct {
	Origin    string
	Size      int64
	A, B      string // witness names
	RootA     string
	RootB     string
	Timestamp uint64
}

func (c *Conflict) Error() string {
	return fmt.Sprintf(
		"split view on %s at size %d: %s attests root %s, %s attests root %s; "+
			"a log cannot have two roots at one size, so it served different "+
			"histories to different parties",
		c.Origin, c.Size, c.A, c.RootA, c.B, c.RootB)
}

// cosignatureTimestamp reads the seconds field out of a cosignature/v1 blob.
//
// The blob is keyid(4) ‖ timestamp(8, big-endian) ‖ signature(64). torchwood's
// verifier checks the signature but does not expose the timestamp, and the
// timestamp is the part that makes a cosignature a liveness statement rather
// than a bare endorsement — so it is worth the eight bytes of parsing.
func cosignatureTimestamp(b64 string) (uint64, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, err
	}
	if len(raw) != 4+8+ed25519.SignatureSize {
		return 0, fmt.Errorf("cosig: signature blob is %d bytes, want %d",
			len(raw), 4+8+ed25519.SignatureSize)
	}
	return binary.BigEndian.Uint64(raw[4:12]), nil
}
