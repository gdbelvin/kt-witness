// Package pbwire is a minimal read-only protobuf decoder.
//
// Generated code would be more convenient, but every adapter here needs only a
// handful of field numbers from a few nested messages, and this stays small
// enough to audit in full — which matters more, since it parses attacker-shaped
// input on the path to a signature check.
//
// It deliberately keeps length-delimited fields as raw sub-slices. Signature
// verification often covers bytes exactly as transmitted, and re-serializing a
// decoded message is not guaranteed to reproduce them.
package pbwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Message maps field numbers to their values, in order of appearance.
// Varints are stored as 8 bytes, big-endian, so a field can be read either way.
type Message map[int][][]byte

func Parse(b []byte) Message {
	out := Message{}
	i := 0
	for i < len(b) {
		k, ni, ok := uvarint(b, i)
		if !ok {
			return out
		}
		i = ni
		field, wire := int(k>>3), k&7
		switch wire {
		case 0:
			v, ni, ok := uvarint(b, i)
			if !ok {
				return out
			}
			i = ni
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], v)
			out[field] = append(out[field], buf[:])
		case 2:
			n, ni, ok := uvarint(b, i)
			if !ok || ni+int(n) > len(b) || ni+int(n) < ni {
				return out
			}
			i = ni
			out[field] = append(out[field], b[i:i+int(n)])
			i += int(n)
		case 5:
			if i+4 > len(b) {
				return out
			}
			i += 4
		case 1:
			if i+8 > len(b) {
				return out
			}
			i += 8
		default:
			return out
		}
	}
	return out
}

func uvarint(b []byte, i int) (uint64, int, bool) {
	var s uint64
	var sh uint
	for {
		if i >= len(b) || sh > 63 {
			return 0, i, false
		}
		x := b[i]
		i++
		s |= uint64(x&0x7f) << sh
		if x&0x80 == 0 {
			return s, i, true
		}
		sh += 7
	}
}

// First returns the first value for a field, or nil.
func First(m Message, field int) []byte {
	if v := m[field]; len(v) > 0 {
		return v[0]
	}
	return nil
}

// Uint64 returns a varint field's value, or 0 if absent.
//
// Callers must not treat 0 as merely "absent": a field that is genuinely zero is
// indistinguishable here, and for a tree size that difference is the difference
// between an empty log and a missing field.
func Uint64(m Message, field int) uint64 {
	v := First(m, field)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

// Field is one field occurrence as it appeared on the wire.
type Field struct {
	Num    int
	Wire   byte   // 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32
	Varint uint64 // wire 0 only
	Bytes  []byte // wire 2: a sub-slice of the input; wire 1/5: the raw 8/4 bytes
}

// Fields is the strict counterpart to Parse: it returns every field in order,
// with its wire type, and fails on anything Parse would quietly stop at — a
// truncated varint or length, a varint wider than 64 bits, field number 0, a
// group, or bytes left over at the end.
//
// Parse's leniency is fine where a signature over the raw bytes is checked
// afterwards. It is not fine where the decoded fields *are* the thing being
// verified: there a truncated message that decodes to a plausible prefix, or a
// varint read where bytes were sent, is a different message than the one sent.
// Keeping the wire type lets the caller refuse that confusion.
func Fields(b []byte) ([]Field, error) {
	var out []Field
	i := 0
	for i < len(b) {
		k, ni, err := strictUvarint(b, i)
		if err != nil {
			return nil, fmt.Errorf("pbwire: tag at offset %d: %w", i, err)
		}
		i = ni
		num, wire := k>>3, byte(k&7)
		if num == 0 || num > 1<<29-1 {
			return nil, fmt.Errorf("pbwire: invalid field number %d at offset %d", num, i)
		}
		f := Field{Num: int(num), Wire: wire}
		switch wire {
		case 0:
			if f.Varint, i, err = strictUvarint(b, i); err != nil {
				return nil, fmt.Errorf("pbwire: field %d: %w", num, err)
			}
		case 2:
			n, ni, err := strictUvarint(b, i)
			if err != nil {
				return nil, fmt.Errorf("pbwire: field %d length: %w", num, err)
			}
			if n > uint64(len(b)-ni) {
				return nil, fmt.Errorf("pbwire: field %d claims %d bytes, %d remain", num, n, len(b)-ni)
			}
			f.Bytes = b[ni : ni+int(n)]
			i = ni + int(n)
		case 1, 5:
			w := 8
			if wire == 5 {
				w = 4
			}
			if len(b)-i < w {
				return nil, fmt.Errorf("pbwire: field %d truncated fixed%d", num, 8*w)
			}
			f.Bytes = b[i : i+w]
			i += w
		default:
			return nil, fmt.Errorf("pbwire: field %d has unsupported wire type %d", num, wire)
		}
		out = append(out, f)
	}
	return out, nil
}

// strictUvarint decodes a varint of at most ten bytes whose value fits in 64
// bits.
func strictUvarint(b []byte, i int) (uint64, int, error) {
	var v uint64
	for n := 0; n < 10; n++ {
		if i >= len(b) {
			return 0, i, errors.New("truncated varint")
		}
		x := b[i]
		i++
		if n == 9 && x > 1 {
			return 0, i, errors.New("varint overflows 64 bits")
		}
		v |= uint64(x&0x7f) << (7 * n)
		if x&0x80 == 0 {
			return v, i, nil
		}
	}
	return 0, i, errors.New("varint longer than ten bytes")
}

// AppendVarint appends a varint, for building the small requests these APIs need.
func AppendVarint(b []byte, v uint64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b = append(b, c)
		if v == 0 {
			return b
		}
	}
}

// AppendTag appends a field tag with the given wire type.
func AppendTag(b []byte, field int, wire byte) []byte {
	return AppendVarint(b, uint64(field)<<3|uint64(wire))
}
