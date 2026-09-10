package store

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// BenchmarkFirstUnverified at the scale that actually exists.
//
// This moved from a thirty-second timer to the lease path — every request for
// work asks it — so "a single ordered cursor walk" needs to be a measurement
// rather than a claim. WhatsApp's history is about 516,000 epochs and Meta's
// about 631,000; the interesting case is a long verified prefix, because that
// is what the scan has to cross before it finds anything.
func BenchmarkFirstUnverified(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 500_000} {
		b.Run(fmt.Sprintf("%d-verified", n), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "s.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			const origin = "whatsapp.kt/v2"
			// One transaction for the whole fixture. RecordAudit takes its own
			// Update per call, and half a million fsyncs is a benchmark of
			// bbolt's write path rather than of the scan.
			now := time.Now().UTC()
			if err := s.db.Update(func(tx *bolt.Tx) error {
				bkt := tx.Bucket(bucketAudits)
				for e := 1; e <= n; e++ {
					enc, err := json.Marshal(&Audit{Origin: origin, Epoch: int64(e),
						Verified: true, Sampled: true, DecidedAt: now})
					if err != nil {
						return err
					}
					if err := bkt.Put(auditKey(origin, int64(e)), enc); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				at, ok, err := s.FirstUnverified(origin, 1, int64(n)+1000)
				if err != nil || !ok || at != int64(n)+1 {
					b.Fatalf("at=%d ok=%v err=%v", at, ok, err)
				}
			}
		})
	}
}
