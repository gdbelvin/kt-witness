package keytrans

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The TLS presentation language reader, and just enough of
// draft-ietf-keytrans-protocol-05's structures to verify tree heads.
//
// Message vectors are read with element-count prefixes, the reading the
// reference log takes because the draft's byte-length bounds could not hold
// the structures they describe. Only messages are affected: everything signed
// is scalars and byte strings.

var errTruncated = errors.New("keytrans: truncated message")

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errTruncated
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *reader) fixed(n int) []byte { return append([]byte(nil), r.take(n)...) }
func (r *reader) opaque16() []byte   { return r.fixed(int(r.u16())) }

func (r *reader) optU64() *uint64 {
	switch p := r.u8(); p {
	case 0:
		return nil
	case 1:
		v := r.u64()
		return &v
	default:
		r.fail(fmt.Errorf("keytrans: presence octet %d", p))
		return nil
	}
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return fmt.Errorf("keytrans: %d trailing bytes", len(r.b))
	}
	return nil
}

func hashes(r *reader, n int) [][32]byte {
	out := make([][32]byte, 0, min(n, 4096))
	for i := 0; i < n && r.err == nil; i++ {
		var h [32]byte
		copy(h[:], r.take(32))
		out = append(out, h)
	}
	return out
}

// Cipher suites (§17.1).
const (
	suiteP256    = 0x0001
	suiteEd25519 = 0x0002
)

// Deployment modes (§11.2).
const (
	modeContactMonitoring    = 1
	modeThirdPartyManagement = 2
	modeThirdPartyAuditing   = 3
)

// configuration is the parsed Configuration. raw is the exact encoding the
// operator pinned, which is what every tree head signature covers, so it is
// used verbatim rather than re-encoded.
type configuration struct {
	raw             []byte
	suite           uint16
	mode            uint8
	signatureKey    []byte
	auditorKey      []byte
	maxAuditorLag   uint64
	auditorStartPos uint64
	maxAhead        uint64
	maxBehind       uint64
	rmw             uint64
	maximumLifetime *uint64
}

func parseConfiguration(raw []byte) (*configuration, error) {
	r := &reader{b: raw}
	c := &configuration{raw: append([]byte(nil), raw...)}
	c.suite = r.u16()
	c.mode = r.u8()
	c.signatureKey = r.opaque16()
	_ = r.opaque16() // vrf_public_key: witnesses never evaluate the VRF
	switch c.mode {
	case modeContactMonitoring, modeThirdPartyManagement:
		_ = r.opaque16() // leaf_public_key
	case modeThirdPartyAuditing:
		c.maxAuditorLag = r.u64()
		c.auditorStartPos = r.u64()
		c.auditorKey = r.opaque16()
	default:
		r.fail(fmt.Errorf("keytrans: unknown deployment mode %d", c.mode))
	}
	c.maxAhead = r.u64()
	c.maxBehind = r.u64()
	c.rmw = r.u64()
	c.maximumLifetime = r.optU64()
	if err := r.done(); err != nil {
		return nil, fmt.Errorf("keytrans: configuration: %w", err)
	}
	if c.suite != suiteP256 && c.suite != suiteEd25519 {
		return nil, fmt.Errorf("keytrans: unsupported cipher suite 0x%04x", c.suite)
	}
	return c, nil
}

// treeHeadTBS is the TreeHeadTBS a log signs (§11.2).
func (c *configuration) treeHeadTBS(size uint64, root [32]byte) []byte {
	out := append([]byte(nil), c.raw...)
	out = binary.BigEndian.AppendUint64(out, size)
	return append(out, root[:]...)
}

// auditorTreeHeadTBS is the AuditorTreeHeadTBS an auditor signs (§11.3).
func (c *configuration) auditorTreeHeadTBS(timestamp, size uint64, root [32]byte) []byte {
	out := append([]byte(nil), c.raw...)
	out = binary.BigEndian.AppendUint64(out, timestamp)
	out = binary.BigEndian.AppendUint64(out, size)
	return append(out, root[:]...)
}

type treeHead struct {
	size      uint64
	signature []byte
}

type auditorTreeHead struct {
	timestamp uint64
	size      uint64
	signature []byte
}

const (
	headSame    = 1
	headUpdated = 2
)

// combinedTreeProof (§12.3). Prefix proofs are counted but not kept: a
// tree-head request must not contain any.
type combinedTreeProof struct {
	timestamps   []uint64
	prefixProofs int
	prefixRoots  [][32]byte
	inclusion    [][32]byte
}

// distinguishedResponse is a DistinguishedResponse (§13.6).
type distinguishedResponse struct {
	headType uint8
	head     *treeHead
	auditor  *auditorTreeHead
	proof    combinedTreeProof
}

func parseDistinguishedResponse(b []byte, c *configuration) (*distinguishedResponse, error) {
	r := &reader{b: b}
	d := &distinguishedResponse{headType: r.u8()}
	switch d.headType {
	case headSame:
	case headUpdated:
		d.head = &treeHead{size: r.u64(), signature: r.opaque16()}
		if c.mode == modeThirdPartyAuditing {
			d.auditor = &auditorTreeHead{timestamp: r.u64(), size: r.u64(), signature: r.opaque16()}
		}
	default:
		r.fail(fmt.Errorf("keytrans: unknown FullTreeHeadType %d", d.headType))
	}
	n := int(r.u8())
	for i := 0; i < n && r.err == nil; i++ {
		d.proof.timestamps = append(d.proof.timestamps, r.u64())
	}
	d.proof.prefixProofs = int(r.u8())
	for i := 0; i < d.proof.prefixProofs && r.err == nil; i++ {
		skipPrefixProof(r)
	}
	d.proof.prefixRoots = hashes(r, int(r.u8()))
	d.proof.inclusion = hashes(r, int(r.u16()))
	if err := r.done(); err != nil {
		return nil, fmt.Errorf("keytrans: DistinguishedResponse: %w", err)
	}
	return d, nil
}

func skipPrefixProof(r *reader) {
	n := int(r.u8())
	for i := 0; i < n && r.err == nil; i++ {
		switch t := r.u8(); t {
		case 1, 3:
		case 2:
			r.take(64) // PrefixLeaf
		default:
			r.fail(fmt.Errorf("keytrans: bad PrefixSearchResultType %d", t))
		}
		r.u8() // depth
	}
	r.take(32 * int(r.u16()))
}

// distinguishedRequest encodes DistinguishedRequest{last, stop}.
func distinguishedRequest(last *uint64, stop uint64) []byte {
	var out []byte
	if last == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = binary.BigEndian.AppendUint64(out, *last)
	}
	out = append(out, 1)
	return binary.BigEndian.AppendUint64(out, stop)
}
