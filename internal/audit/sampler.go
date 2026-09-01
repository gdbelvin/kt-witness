package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

// Selected reports whether an epoch falls in the audit sample, given the beacon
// randomness drawn after that epoch was published.
//
// The rule is deliberately simple and fully specified so anyone can recompute
// it from the published record:
//
//	selected  <=>  first 8 bytes of SHA-256(randomness || ":" || epoch)
//	               interpreted big-endian  <  rate * 2^64
//
// Determinism matters more than elegance here: this is the function a third
// party runs to check we are not quietly under-sampling.
func Selected(randomnessHex string, epoch int64, rate float64) (bool, error) {
	if rate <= 0 {
		return false, nil
	}
	if rate >= 1 {
		return true, nil
	}
	rnd, err := hex.DecodeString(randomnessHex)
	if err != nil {
		return false, fmt.Errorf("sampler: randomness not hex: %w", err)
	}

	h := sha256.New()
	h.Write(rnd)
	h.Write([]byte(":"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(epoch))
	h.Write(buf[:])
	sum := h.Sum(nil)

	draw := binary.BigEndian.Uint64(sum[:8])

	// Compare in float space against 2^64. Precision here is far finer than any
	// sampling rate we would configure, and the alternative (big.Int) buys
	// nothing an auditor would notice.
	threshold := rate * math.Pow(2, 64)
	return float64(draw) < threshold, nil
}
