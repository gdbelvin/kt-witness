package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// RecordConstructionAudit marks one unit of published history as verified.
//
// Shares the audit bucket with epoch-based auditing so AuditCoverage — and
// therefore the tier calculation — counts both without knowing which kind of
// log it is looking at. The strategy name distinguishes them in the record.
func (s *Store) RecordConstructionAudit(origin string, index int64) error {
	return s.RecordAudit(&Audit{
		Origin: origin, Epoch: index,
		// Not sampled: every entry in the range is read and hashed, so rate 1
		// records that this index was checked outright.
		Sampled: true, Rate: 1, Strategy: "entries",
		Verified: true, Attempts: 1, DecidedAt: time.Now().UTC(),
	})
}

// ConstructionAuditedThrough returns the end of the unbroken run of verified
// indices starting at zero.
//
// Deliberately the run from zero rather than the highest verified index: an
// entry log's claim is "every index up to here is checked", and the highest
// index would report a hole-riddled range as complete.
//
// The bool distinguishes "index 0 is audited" from "nothing is audited". Those
// share a representation if you return only an int64, and that conflation has
// already caused two bugs here — a fully audited log reporting a verified run
// of zero, and a completed sweep being read as an unstarted one.
func (s *Store) ConstructionAuditedThrough(origin string) (int64, bool, error) {
	verified := make(map[int64]bool)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var a Audit
			if json.Unmarshal(v, &a) != nil {
				continue
			}
			if a.Verified {
				verified[a.Epoch] = true
			}
		}
		return nil
	})
	if err != nil {
		return 0, false, fmt.Errorf("store: construction audited through for %s: %w", origin, err)
	}
	if !verified[0] {
		return 0, false, nil
	}
	through := int64(0)
	for verified[through+1] {
		through++
	}
	return through, true, nil
}
