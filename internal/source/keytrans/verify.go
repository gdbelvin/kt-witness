package keytrans

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// view is what a verifier retains about a tree head (§4.2): its size, its
// full subtree heads, and the timestamp and prefix tree root of each entry on
// its frontier. Consistency of the next head is proven against all of it.
type view struct {
	Size         uint64           `json:"size"`
	Root         [32]byte         `json:"root"`
	FullSubtrees [][32]byte       `json:"full_subtrees"`
	Frontier     map[uint64]entry `json:"frontier"`
	// AuditorSize is the size of the last verified auditor head, for the
	// auditor_start_pos check (§11.3 step 1).
	AuditorSize uint64 `json:"auditor_size,omitempty"`
}

type entry struct {
	Timestamp  uint64   `json:"ts"`
	PrefixRoot [32]byte `json:"prefix_root"`
}

// verified is a fully checked response.
type verified struct {
	view    *view
	auditor *auditorTreeHead
}

// verifyHead checks a DistinguishedResponse to a request made with old as the
// retained view (nil for a first observation) and a stop position beyond the
// end of the log.
//
// Such a walk (§10.1) recurses only down the right spine while entries are
// distinguished and stops at each, so it touches nothing but frontier entries,
// whose timestamps the view update already carries. The response is therefore
// exactly the §4.2 view update: no prefix proofs, a prefix root for every
// served timestamp, and the log tree inclusion proof. That is checked
// strictly, so a response carrying anything else is rejected rather than
// partly understood.
func verifyHead(c *configuration, d *distinguishedResponse, old *view) (*verified, error) {
	var n, m uint64
	if old != nil {
		m = old.Size
	}
	switch d.headType {
	case headSame:
		if old == nil {
			return nil, errors.New("keytrans: unchanged head for a first observation")
		}
		n = m
	case headUpdated:
		n = d.head.size
		if n == 0 || (old != nil && n <= m) {
			return nil, fmt.Errorf("keytrans: tree head size %d does not advance from %d", n, m)
		}
	}
	if d.proof.prefixProofs != 0 {
		return nil, errors.New("keytrans: tree-head response carries prefix proofs")
	}

	ts := map[uint64]uint64{}
	roots := map[uint64][32]byte{}
	if old != nil {
		for x, e := range old.Frontier {
			ts[x], roots[x] = e.Timestamp, e.PrefixRoot
		}
	}
	var provided []uint64
	next := 0
	for _, x := range updateView(m, n) {
		if _, ok := ts[x]; ok {
			continue
		}
		if next >= len(d.proof.timestamps) {
			return nil, errors.New("keytrans: proof is missing timestamps")
		}
		ts[x] = d.proof.timestamps[next]
		next++
		provided = append(provided, x)
	}
	if next != len(d.proof.timestamps) {
		return nil, errors.New("keytrans: proof has unexpected timestamps")
	}
	// The walk itself must find everything it touches already known.
	for _, x := range frontier(n) {
		if _, ok := ts[x]; !ok {
			return nil, fmt.Errorf("keytrans: frontier entry %d not established", x)
		}
	}

	// Timestamps never decrease with position (§12.3).
	positions := make([]uint64, 0, len(ts))
	for x := range ts {
		positions = append(positions, x)
	}
	sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
	for i := 1; i < len(positions); i++ {
		if ts[positions[i]] < ts[positions[i-1]] {
			return nil, fmt.Errorf("keytrans: timestamp at entry %d goes backwards", positions[i])
		}
	}

	// Prefix roots arrive in position order for served timestamps.
	sort.Slice(provided, func(i, j int) bool { return provided[i] < provided[j] })
	if len(d.proof.prefixRoots) != len(provided) {
		return nil, errors.New("keytrans: wrong number of prefix roots")
	}
	leaves := map[uint64][32]byte{}
	for i, x := range provided {
		roots[x] = d.proof.prefixRoots[i]
		leaves[x] = leafHash(ts[x], roots[x])
	}

	b := &batch{size: n, leaves: leaves}
	if old != nil {
		b.oldSize, b.retained = old.Size, old.FullSubtrees
	}
	if d.auditor != nil {
		if d.auditor.size == 0 || d.auditor.size > n {
			return nil, errors.New("keytrans: auditor tree size out of range")
		}
		b.auditor = d.auditor.size
	}
	res, err := b.verify(d.proof.inclusion)
	if err != nil {
		return nil, err
	}

	out := &view{Size: n, Root: res.root, FullSubtrees: res.fullSubtrees, Frontier: map[uint64]entry{}}
	for _, x := range frontier(n) {
		out.Frontier[x] = entry{Timestamp: ts[x], PrefixRoot: roots[x]}
	}
	if old != nil {
		out.AuditorSize = old.AuditorSize
	}

	if d.headType == headSame {
		if res.root != old.Root {
			return nil, errors.New("keytrans: proof does not match the retained head")
		}
		return &verified{view: out}, nil
	}
	if err := verifySig(c.suite, c.signatureKey, c.treeHeadTBS(n, res.root), d.head.signature); err != nil {
		if old != nil {
			// The root here was derived from our retained view plus the
			// proof, so this is also the consistency check failing: the
			// log signed a tree that does not extend the one we kept.
			// From here we cannot tell a fork from a broken proof.
			return nil, fmt.Errorf("keytrans: the log's signed head at size %d does not extend the view retained at size %d "+
				"(a fork, or a malformed proof): %w", n, m, err)
		}
		return nil, fmt.Errorf("keytrans: tree head signature: %w", err)
	}
	if c.mode == modeThirdPartyAuditing {
		a := d.auditor
		if old != nil && old.AuditorSize < c.auditorStartPos {
			return nil, errors.New("keytrans: auditor started after our last view")
		}
		rightmost := ts[n-1]
		if rightmost < a.timestamp || rightmost-a.timestamp > c.maxAuditorLag {
			return nil, errors.New("keytrans: auditor head lags beyond max_auditor_lag")
		}
		if err := verifySig(c.suite, c.auditorKey, c.auditorTreeHeadTBS(a.timestamp, a.size, res.auditorRoot), a.signature); err != nil {
			return nil, fmt.Errorf("keytrans: auditor tree head signature: %w", err)
		}
		out.AuditorSize = a.size
	}
	return &verified{view: out, auditor: d.auditor}, nil
}

var errSig = errors.New("signature does not verify")

// verifySig checks a signature under the suite's scheme (§17.1).
func verifySig(suite uint16, pub, msg, sig []byte) error {
	switch suite {
	case suiteEd25519:
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
			return errSig
		}
		return nil
	case suiteP256:
		// Uncompressed point; signature is r || s, each 32 bytes.
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
		if err != nil || len(sig) != 64 {
			return errSig
		}
		digest := sha256.Sum256(msg)
		if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errSig
		}
		return nil
	}
	return fmt.Errorf("unsupported cipher suite 0x%04x", suite)
}
