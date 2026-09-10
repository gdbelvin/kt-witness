package akdtree

import (
	"encoding/binary"
	"fmt"
)

// Where things are in a proof, as distinct from what they are.
//
// Decode answers "what": it turns 284 MB of wire format into elements and
// costs a pass over every byte to do it. The proof server needs something
// else — it is streaming bytes it will never decode, and it needs to know
// which of them belong to `inserted` before the first one goes out. That is a
// question about the framing alone, so it is answered by reading the framing
// alone: varint tags and lengths, skipping every body.
//
// Why the server needs it at all is the append-only shortcut. The published
// roots chain, so curr_E == prev_{E+1} == Root(unchanged_{E+1}). A worker
// holding proof E+1 can therefore produce both of epoch E's roots out of the
// two unchanged sets and never read inserted_E at all — two correct roots, no
// append-only check. The witness's canary catches that only if the bit it
// flips lands in bytes the shortcut skips, and a bit chosen uniformly over the
// whole file almost never does: `unchanged` is the entire previous tree and
// `inserted` is one epoch of additions. On the test fixture that is 11.8% of
// the bytes, and on a Meta proof of several million nodes it is smaller still.

// Range is a half-open byte range [Start, End) of a proof's encoding.
type Range struct{ Start, End int }

// record is one length-delimited protobuf record and where it sits. It is the
// framing and nothing more: no body is copied and no element is decoded.
type record struct {
	Field     int
	Wire      uint64
	Start     int // offset of the field key
	BodyStart int // offset of the body; equal to End for non length-delimited
	End       int // offset just past the record
}

// nextRecord frames the record beginning at pos.
//
// The record is written through r rather than returned, so a caller scanning
// millions of elements supplies one and reuses it.
//
// walk in decode.go frames the same wire format and does not call this, which
// is deliberate and measured: routing it through here cost 14% of Decode's
// throughput, because walk runs four more times inside every element and does
// not need the one thing this adds. Change the rules in one and change them in
// the other.
//
// partial reports that data holds only part of the record. That distinction is
// the reason this exists separately from walk: a caller reading a proof off a
// socket sees a half-arrived element and a corrupt one as the same thing
// otherwise, and the first means "read more" while the second means "stop".
func nextRecord(data []byte, pos int, r *record) (partial bool, err error) {
	key, n := binary.Uvarint(data[pos:])
	if n == 0 {
		return true, nil
	}
	if n < 0 {
		return false, fmt.Errorf("akdtree: malformed field key at byte %d", pos)
	}
	r.Field, r.Wire, r.Start = int(key>>3), key&7, pos
	pos += n

	switch r.Wire {
	case 2: // length-delimited
		l, m := binary.Uvarint(data[pos:])
		if m == 0 {
			return true, nil
		}
		if m < 0 {
			return false, fmt.Errorf("akdtree: malformed length for field %d", r.Field)
		}
		pos += m
		if uint64(len(data)-pos) < l {
			return true, nil
		}
		r.BodyStart, r.End = pos, pos+int(l)
	case 0: // varint
		_, m := binary.Uvarint(data[pos:])
		if m == 0 {
			return true, nil
		}
		if m < 0 {
			return false, fmt.Errorf("akdtree: malformed varint in field %d", r.Field)
		}
		r.BodyStart, r.End = pos+m, pos+m
	case 5: // fixed32
		if len(data)-pos < 4 {
			return true, nil
		}
		r.BodyStart, r.End = pos+4, pos+4
	case 1: // fixed64
		if len(data)-pos < 8 {
			return true, nil
		}
		r.BodyStart, r.End = pos+8, pos+8
	default:
		return false, fmt.Errorf("akdtree: unsupported wire type in field %d", r.Field)
	}
	return false, nil
}

// FieldRanges reports where a top-level field lives in a proof's encoding.
//
// Adjacent records of the same field are coalesced, which is not a nicety: a
// prost-encoded proof writes fields in number order, so all of `inserted`
// precedes all of `unchanged_nodes` and this returns exactly one range per
// field however many million elements the proof holds. Returning a range per
// element instead would allocate tens of megabytes of ranges to describe a
// proof — the per-element cost this package exists to avoid, reappearing in
// the code that was meant to be the cheap way of asking.
//
// Coalescing is by adjacency rather than by assumption, so an encoder that did
// interleave the two fields would produce several ranges here and every caller
// would still be correct; it would only be less compact.
func FieldRanges(data []byte, field int) ([]Range, error) {
	var out []Range
	var r record
	for pos := 0; pos < len(data); {
		partial, err := nextRecord(data, pos, &r)
		if err != nil {
			return nil, err
		}
		if partial {
			return nil, fmt.Errorf("akdtree: truncated field %d at byte %d", r.Field, r.Start)
		}
		pos = r.End
		if r.Field != field {
			continue
		}
		if n := len(out); n > 0 && out[n-1].End == r.Start {
			out[n-1].End = r.End
			continue
		}
		out = append(out, Range{Start: r.Start, End: r.End})
	}
	return out, nil
}

// ScanLeading measures the run of records of one field at the front of a proof,
// for a caller that holds only a prefix of it.
//
// It returns the offset just past the last complete record of that field.
// ended reports that the run is over — a record of some other field begins at
// that offset — as opposed to the caller simply having run out of bytes, in
// which case it should read more and call again. Passing the previous end back
// as from resumes the scan there rather than re-reading what has already been
// framed, so following a stream costs one pass over the prefix in total and
// not one per read.
//
// from must be an offset a previous call returned, or zero.
//
// A record that is not length-delimited is an error rather than something to
// skip: every top-level field of a SingleAppendOnlyProof is a submessage, so
// anything else means these are not the bytes we think they are, and a caller
// choosing where to corrupt a proof should hear that rather than guess.
func ScanLeading(data []byte, field, from int) (end int, ended bool, err error) {
	pos := from
	var r record
	for pos < len(data) {
		partial, err := nextRecord(data, pos, &r)
		if err != nil {
			return pos, false, err
		}
		if partial {
			return pos, false, nil
		}
		if r.Wire != 2 {
			return pos, false, fmt.Errorf("akdtree: field %d has wire type %d, not a proof element", r.Field, r.Wire)
		}
		if r.Field != field {
			return pos, true, nil
		}
		pos = r.End
	}
	return pos, false, nil
}

// PayloadOffset locates the n-th payload byte of a top-level field, and reports
// how many payload bytes that field has. A negative n counts without locating;
// found is false when n is past the end.
//
// Payload means the bytes a verifier hashes and nothing else: each element's
// label_val and its 32-byte value. Every tag, length prefix and label_len
// varint is excluded, and the exclusion is the point. A flipped bit in a length
// desynchronises the framing from that byte onward, so Decode rejects the whole
// proof rather than one element — and "this proof does not parse" is the same
// verdict an honest verifier returns, which tells a canary nothing about
// whether the worker did the work. A flipped bit in a payload cannot change any
// length, so the proof still decodes, every element is still present, and only
// the roots move. That is the answer a worker which skipped the append-only
// check cannot produce.
//
// One pass, no allocation, and no element is decoded — the nested scan reads
// lengths and skips bodies exactly as the top-level one does.
func PayloadOffset(data []byte, field, n int) (offset, total int, found bool, err error) {
	var r, e, l record
	for pos := 0; pos < len(data); {
		partial, err := nextRecord(data, pos, &r)
		if err != nil {
			return 0, total, false, err
		}
		if partial {
			return 0, total, false, fmt.Errorf("akdtree: truncated field %d at byte %d", r.Field, r.Start)
		}
		pos = r.End
		if r.Field != field || r.Wire != 2 {
			continue
		}
		// AzksElement: field 1 is the NodeLabel submessage, field 2 the value.
		for q := r.BodyStart; q < r.End; {
			partial, err := nextRecord(data, q, &e)
			if err != nil {
				return 0, total, false, err
			}
			if partial {
				return 0, total, false, fmt.Errorf("akdtree: truncated element field %d at byte %d", e.Field, e.Start)
			}
			q = e.End
			if e.Wire != 2 {
				continue
			}
			switch e.Field {
			case 1: // NodeLabel: field 1 is label_val, field 2 the varint length
				for s := e.BodyStart; s < e.End; {
					partial, err := nextRecord(data, s, &l)
					if err != nil {
						return 0, total, false, err
					}
					if partial {
						return 0, total, false, fmt.Errorf("akdtree: truncated NodeLabel field %d at byte %d", l.Field, l.Start)
					}
					s = l.End
					if l.Field == 1 && l.Wire == 2 {
						if !found && n >= total && n < total+l.End-l.BodyStart {
							offset, found = l.BodyStart+n-total, true
						}
						total += l.End - l.BodyStart
					}
				}
			case 2: // value
				if !found && n >= total && n < total+e.End-e.BodyStart {
					offset, found = e.BodyStart+n-total, true
				}
				total += e.End - e.BodyStart
			}
		}
	}
	return offset, total, found, nil
}
