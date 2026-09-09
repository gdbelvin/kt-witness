package akdtree

import (
	"encoding/binary"
	"fmt"
)

// The proof wire format, from akd_core's types.proto:
//
//	message NodeLabel             { optional bytes label_val = 1; optional uint32 label_len = 2; }
//	message AzksElement           { optional NodeLabel label = 1; optional bytes value = 2; }
//	message SingleAppendOnlyProof { repeated AzksElement inserted = 1;
//	                                repeated AzksElement unchanged_nodes = 2; }
//
// Decoded by hand rather than through generated code, for the same reason the
// tree is a flat array: a 279 MB Meta proof holds about 3.6 million elements,
// and a generated decoder allocates a struct and two byte slices for each one.
// That is several million allocations to produce 40 bytes of fixed-size data
// per element — the cost this package exists to remove, reappearing before the
// first hash is taken.
//
// Two passes: count, allocate exactly, fill. The count pass reads the same
// bytes a second time but touches no memory, and it is cheaper than growing
// two large slices.

// Decode parses a SingleAppendOnlyProof into its two element sets.
func Decode(data []byte) (inserted, unchanged []Element, err error) {
	var ni, nu int
	if err := walk(data, func(field int, _ []byte) error {
		switch field {
		case 1:
			ni++
		case 2:
			nu++
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	inserted = make([]Element, 0, ni)
	unchanged = make([]Element, 0, nu)
	err = walk(data, func(field int, body []byte) error {
		e, err := decodeElement(body)
		if err != nil {
			return err
		}
		switch field {
		case 1:
			inserted = append(inserted, e)
		case 2:
			unchanged = append(unchanged, e)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return inserted, unchanged, nil
}

// walk calls fn for each length-delimited field of the top-level message.
func walk(data []byte, fn func(field int, body []byte) error) error {
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return fmt.Errorf("akdtree: malformed field key")
		}
		data = data[n:]
		field := int(key >> 3)
		switch key & 7 {
		case 2: // length-delimited
			l, n := binary.Uvarint(data)
			if n <= 0 || uint64(len(data)-n) < l {
				return fmt.Errorf("akdtree: truncated field %d", field)
			}
			body := data[uint64(n) : uint64(n)+l]
			data = data[uint64(n)+l:]
			if err := fn(field, body); err != nil {
				return err
			}
		case 0: // varint
			_, n := binary.Uvarint(data)
			if n <= 0 {
				return fmt.Errorf("akdtree: malformed varint in field %d", field)
			}
			data = data[n:]
		case 5:
			if len(data) < 4 {
				return fmt.Errorf("akdtree: truncated fixed32 in field %d", field)
			}
			data = data[4:]
		case 1:
			if len(data) < 8 {
				return fmt.Errorf("akdtree: truncated fixed64 in field %d", field)
			}
			data = data[8:]
		default:
			return fmt.Errorf("akdtree: unsupported wire type in field %d", field)
		}
	}
	return nil
}

func decodeElement(body []byte) (Element, error) {
	var e Element
	var sawLabel, sawValue bool
	err := walk(body, func(field int, b []byte) error {
		switch field {
		case 1: // NodeLabel
			sawLabel = true
			return walk(b, func(f int, lb []byte) error {
				switch f {
				case 1:
					// Labels are sent minimised: the encoder strips TRAILING
					// zero bytes and the decoder left-aligns what is left into
					// a 32-byte array. Trailing rather than leading, because a
					// label is a bit-path read from the most significant bit of
					// byte zero, so its tail is the part that is unused.
					if len(lb) > 32 {
						return fmt.Errorf("akdtree: label_val is %d bytes, want at most 32", len(lb))
					}
					copy(e.Label[:], lb)
				}
				return nil
			})
		case 2: // value
			sawValue = true
			if len(b) != 32 {
				return fmt.Errorf("akdtree: value is %d bytes, want 32", len(b))
			}
			copy(e.Value[:], b)
		}
		return nil
	})
	if err != nil {
		return Element{}, err
	}
	// label_len is a varint inside NodeLabel, which walk skips over, so read it
	// separately rather than making walk return varint payloads it would
	// allocate for.
	if err := walk(body, func(field int, b []byte) error {
		if field != 1 {
			return nil
		}
		return readLabelLen(b, &e.Len)
	}); err != nil {
		return Element{}, err
	}
	if !sawLabel || !sawValue {
		return Element{}, fmt.Errorf("akdtree: element missing label or value")
	}
	if e.Len > 256 {
		return Element{}, fmt.Errorf("akdtree: label_len %d exceeds 256", e.Len)
	}
	return e, nil
}

func readLabelLen(nodeLabel []byte, out *uint32) error {
	data := nodeLabel
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return fmt.Errorf("akdtree: malformed NodeLabel field key")
		}
		data = data[n:]
		field := int(key >> 3)
		switch key & 7 {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return fmt.Errorf("akdtree: malformed label_len")
			}
			if field == 2 {
				*out = uint32(v)
			}
			data = data[n:]
		case 2:
			l, n := binary.Uvarint(data)
			if n <= 0 || uint64(len(data)-n) < l {
				return fmt.Errorf("akdtree: truncated NodeLabel field %d", field)
			}
			data = data[uint64(n)+l:]
		case 5:
			if len(data) < 4 {
				return fmt.Errorf("akdtree: truncated fixed32")
			}
			data = data[4:]
		case 1:
			if len(data) < 8 {
				return fmt.Errorf("akdtree: truncated fixed64")
			}
			data = data[8:]
		default:
			return fmt.Errorf("akdtree: unsupported wire type in NodeLabel")
		}
	}
	return nil
}
