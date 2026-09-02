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

import "encoding/binary"

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
