package c2sp

import (
	"context"
	"strings"
	"testing"
)

type recorder struct{ idx []int64 }

func (r *recorder) RecordConstructionAudit(_ string, i int64) error {
	r.idx = append(r.idx, i)
	return nil
}

// TestBackfillRefusedWithoutEntryVerification: declaring a construction history
// we have no intention of checking would make the coverage denominator real and
// the numerator permanently zero — a stalled audit rather than an absent one.
func TestBackfillRefusedWithoutEntryVerification(t *testing.T) {
	// Built directly rather than through New: the refusal under test happens
	// before any network or key handling, and a fixture key that fails to parse
	// would turn this into a skipped test that checks nothing.
	s := &Source{origin: "example.com/log", cfg: Config{VerifyEntries: false}}
	_, err := s.Backfill(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "does not verify entries") {
		t.Fatalf("want a refusal naming entry verification, got %v", err)
	}
}

// TestMaxAuditEntriesDefault guards the database against a log whose index it
// would otherwise mirror. The CT logs witnessed here hold billions of entries.
func TestMaxAuditEntriesDefault(t *testing.T) {
	s := &Source{}
	if got := s.maxAuditEntries(); got != defaultMaxAuditEntries {
		t.Fatalf("default limit %d, want %d", got, defaultMaxAuditEntries)
	}
	if defaultMaxAuditEntries > 1<<24 {
		t.Fatalf("default limit %d is large enough to be a footgun", defaultMaxAuditEntries)
	}
	s2 := &Source{cfg: Config{MaxAuditEntries: 50}}
	if got := s2.maxAuditEntries(); got != 50 {
		t.Fatalf("explicit limit ignored: %d", got)
	}
}
