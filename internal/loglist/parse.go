// Package loglist discovers logs from witness-network.org log lists and makes
// them available to the push endpoint.
//
// The format is https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md.
// The network's participation rules add two obligations on top of it: the
// lists must be re-fetched automatically, at least weekly, and a changed list
// must never remove or update a log the witness already has. The second one is
// the security property — see internal/store/pushlogs.go for why — and it is
// enforced there, by a store that can only add.
package loglist

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Header is the only list format this package understands.
const Header = "logs/v0"

// Entry is one log as a list describes it.
type Entry struct {
	// VKey is the log's verifier key in vkey form.
	VKey string
	// Origin is the log's checkpoint origin: the list's origin line if it had
	// one, otherwise the vkey's key name, as the format specifies.
	Origin string
	// QPD is the number of add-checkpoint requests per day the log may make,
	// in [1, 2^31).
	QPD int64
	// Contact reaches the log operator. Free text, for humans.
	Contact string
}

// KeyType returns the vkey's signature type byte (0x01 is Ed25519). Parse has
// already checked the key decodes, so this cannot fail on a parsed Entry.
func (e Entry) KeyType() byte {
	_, _, key, _ := splitVKey(e.VKey)
	return key[0]
}

// Parse reads a whole log list.
//
// Any syntax error rejects the WHOLE list, not just the offending entry. A
// list is published as a unit; one malformed entry means the publisher's
// tooling went wrong, and nothing else in that revision has earned our trust.
// Rejecting it costs little — the caller keeps what it already had and tries
// again next interval — while applying a half-understood list could admit a
// log under a mis-parsed origin that, being add-only, we could never undo.
//
// Parse checks vkey syntax (name, 8-hex key ID, base64 key material) but not
// the key's algorithm. The format restricts keys to Ed25519 and ML-DSA-44;
// whether a given key can actually be verified is the caller's question, and
// an entry we can't verify is best skipped rather than taking the list down
// with it.
//
// An origin listed twice is a syntax error too: the list would be telling us
// two things about one log, and we have no basis to pick either.
func Parse(r io.Reader) ([]Entry, error) {
	p := parser{seen: make(map[string]bool)}
	sc := bufio.NewScanner(r)
	// A vkey line for ML-DSA-44 is about 1.8 KB; the default 64 KiB token
	// limit is ample, but say so explicitly rather than rely on it.
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		p.lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := p.line(line); err != nil {
			return nil, fmt.Errorf("loglist: line %d: %w", p.lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("loglist: read: %w", err)
	}
	if !p.header {
		return nil, fmt.Errorf("loglist: missing %q header", Header)
	}
	if p.cur != nil {
		return nil, fmt.Errorf("loglist: log %q at end of list is incomplete (expecting %s)", p.cur.Origin, strings.ReplaceAll(p.want, "-or-", " or "))
	}
	return p.out, nil
}

// parser is a small state machine over the strict line order
//
//	vkey, [origin], qpd, contact
//
// want names the next line the current entry needs.
type parser struct {
	lineNo int
	header bool
	out    []Entry
	seen   map[string]bool

	cur  *Entry
	want string // "vkey" (between entries), "origin-or-qpd", or "contact"
}

func (p *parser) line(line string) error {
	if !p.header {
		if line != Header {
			return fmt.Errorf("expected %q header, got %q", Header, line)
		}
		p.header = true
		p.want = "vkey"
		return nil
	}

	if line == Header {
		return errors.New("duplicate header")
	}
	key, val, ok := strings.Cut(line, " ")
	if !ok || val == "" {
		return fmt.Errorf("malformed line %q: want KEY VALUE", line)
	}

	switch {
	case p.want == "vkey" && key == "vkey":
		name, _, _, err := splitVKey(val)
		if err != nil {
			return err
		}
		p.cur = &Entry{VKey: val, Origin: name}
		p.want = "origin-or-qpd"
		return nil

	case p.want == "origin-or-qpd" && key == "origin":
		// Checkpoint origins match byte for byte, so one that starts with
		// whitespace (a doubled separator) could never receive a push.
		if strings.TrimSpace(val) != val {
			return fmt.Errorf("origin %q has leading whitespace", val)
		}
		p.cur.Origin = val
		p.want = "qpd"
		return nil

	case (p.want == "origin-or-qpd" || p.want == "qpd") && key == "qpd":
		n, err := parseQPD(val)
		if err != nil {
			return err
		}
		p.cur.QPD = n
		p.want = "contact"
		return nil

	case p.want == "contact" && key == "contact":
		p.cur.Contact = val
		if p.seen[p.cur.Origin] {
			return fmt.Errorf("origin %q listed more than once", p.cur.Origin)
		}
		p.seen[p.cur.Origin] = true
		p.out = append(p.out, *p.cur)
		p.cur = nil
		p.want = "vkey"
		return nil
	}

	return fmt.Errorf("unexpected %q line, expecting %s", key, strings.ReplaceAll(p.want, "-or-", " or "))
}

// parseQPD enforces the format's exact encoding: ASCII digits only, no leading
// zeroes, in [1, 2^31). strconv alone would accept "+5" and "007".
func parseQPD(s string) (int64, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("qpd %q: not a decimal number", s)
		}
	}
	if s[0] == '0' {
		return 0, fmt.Errorf("qpd %q: must be at least 1, with no leading zeroes", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n >= 1<<31 {
		return 0, fmt.Errorf("qpd %q: out of range [1, 2^31)", s)
	}
	return n, nil
}

// splitVKey checks a vkey's shape, <name>+<hex key ID>+<base64 type||key>, and
// returns its parts.
//
// Cut, not Split: base64 key material may itself contain '+' (the real lists
// have keys ending in one). A key name may not, so the first two '+' are the
// separators.
func splitVKey(vkey string) (name, id string, key []byte, err error) {
	name, rest, ok := strings.Cut(vkey, "+")
	if !ok {
		return "", "", nil, fmt.Errorf("vkey %q: missing key ID", vkey)
	}
	id, b64, ok := strings.Cut(rest, "+")
	if !ok {
		return "", "", nil, fmt.Errorf("vkey %q: missing key material", vkey)
	}
	if name == "" || strings.ContainsAny(name, " \t\n") {
		return "", "", nil, fmt.Errorf("vkey %q: bad key name", vkey)
	}
	if len(id) != 8 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", "", nil, fmt.Errorf("vkey %q: key ID must be 8 lowercase hex digits", vkey)
	}
	key, err = base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) < 2 {
		return "", "", nil, fmt.Errorf("vkey %q: bad key material", vkey)
	}
	return name, id, key, nil
}
