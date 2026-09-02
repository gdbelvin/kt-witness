package signal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Signal's prefix tree and commitment scheme, reimplemented from libsignal
// (rust/keytrans/src/prefix.rs and commitments.rs).
//
// # What the prefix tree is for
//
// The log tree records *that* the directory changed; the prefix tree records
// *what* it says. Each log entry commits to a prefix-tree root, and the prefix
// tree is indexed by the VRF output of the search key — so a binding's position
// is not chosen by the operator but forced by a value anyone can verify.
//
// That is the whole point. Without it, a log could be perfectly append-only,
// perfectly consistent, every root correctly signed, and still hand one user a
// different key for a contact than it hands everyone else: the two answers
// would live at different positions in a tree nobody checks the shape of. The
// prefix proof is what pins an answer to the one position its identifier
// permits.
//
// # Structure
//
// A fixed-depth binary tree of 256 levels, one per bit of the 32-byte index,
// read most-significant bit first. A proof is therefore always exactly 256
// sibling hashes — a length the operator cannot choose, which removes a whole
// class of proof-padding tricks. Hashes are domain separated by position:
//
//	leaf   = SHA-256(0x00 ‖ index ‖ counter_be32 ‖ pos_be64)
//	parent = SHA-256(0x01 ‖ left ‖ right)
//
// The leaf binds the *counter* (how many versions of this key exist) and *pos*
// (where the key first appeared in the log), so a leaf cannot be replayed at
// another position or made to claim a different version count.

const prefixTreeDepth = 8 * 32

// prefixLeafHash is the leaf of the prefix tree for an index at log position pos
// with version counter ctr.
func prefixLeafHash(index hash, ctr uint32, pos uint64) hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(index[:])
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], ctr)
	h.Write(b[:4])
	binary.BigEndian.PutUint64(b[:], pos)
	h.Write(b[:])
	var out hash
	copy(out[:], h.Sum(nil))
	return out
}

func prefixParentHash(left, right hash) hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out hash
	copy(out[:], h.Sum(nil))
	return out
}

// evaluatePrefixProof walks the 256 sibling hashes from the leaf back to the
// root, taking the direction at each level from the corresponding bit of the
// index. The proof is given root-first, so it is consumed in reverse: proof[i]
// is the sibling at depth i, and bit 255-i of the index decides which side the
// running value is on.
func evaluatePrefixProof(index hash, ctr uint32, pos uint64, proof []hash) (hash, error) {
	var zero hash
	if len(proof) != prefixTreeDepth {
		return zero, fmt.Errorf("signal/prefix: proof has %d hashes, want %d",
			len(proof), prefixTreeDepth)
	}
	value := prefixLeafHash(index, ctr, pos)
	for i := range proof {
		n := len(proof) - i - 1
		// Bit n of the index, most-significant bit of each byte first.
		if index[n/8]&(1<<(7-n%8)) == 0 {
			value = prefixParentHash(value, proof[i])
		} else {
			value = prefixParentHash(proof[i], value)
		}
	}
	return value, nil
}

// commitmentKey is the fixed HMAC key from libsignal's commitments.rs. It is a
// domain separator, not a secret: the hiding property comes from the per-entry
// nonce ("opening"), which the service reveals only to a client that asked for
// this particular key.
var commitmentKey = []byte{
	0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
	0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
}

// verifyCommitment checks that commitment opens to value under searchKey with
// the given 16-byte nonce.
//
// This is the step that makes a search proof say something about an identifier
// rather than about an opaque index. Everything up to here proves a commitment
// sits at the right place in a correctly built tree; only this proves the
// commitment is to the value the service claims, for the key we asked about.
func verifyCommitment(searchKey, commitment, value, nonce []byte) bool {
	if len(nonce) != 16 || len(commitment) != sha256.Size {
		return false
	}
	if len(searchKey) > 0xffff {
		return false
	}
	m := hmac.New(sha256.New, commitmentKey)
	m.Write(nonce)
	var b [4]byte
	binary.BigEndian.PutUint16(b[:2], uint16(len(searchKey)))
	m.Write(b[:2])
	m.Write(searchKey)
	binary.BigEndian.PutUint32(b[:], uint32(len(value)))
	m.Write(b[:])
	m.Write(value)
	return hmac.Equal(m.Sum(nil), commitment)
}

// marshalUpdateValue is the framing the commitment is taken over: a big-endian
// 32-bit length followed by the value. Without the length prefix, a commitment
// to one value could be reinterpreted as a commitment to a different split of
// the same bytes.
func marshalUpdateValue(value []byte) []byte {
	out := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(value)))
	return append(out, value...)
}

// logLeafHash is the leaf of the *log* tree: the prefix-tree root at that entry
// together with the commitment recorded there. This is the join between the two
// trees — it is what makes a log entry mean "at this point, the directory was
// this shape and contained this commitment".
func logLeafHash(prefixRoot, commitment hash) hash {
	h := sha256.New()
	h.Write(prefixRoot[:])
	h.Write(commitment[:])
	var out hash
	copy(out[:], h.Sum(nil))
	return out
}
