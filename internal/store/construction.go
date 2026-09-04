package store

import "time"

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
