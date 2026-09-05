package c2sp

import (
	"context"
	"errors"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

type recorder struct {
	idx []int64
	// through/ok stand in for what the store already holds, so a test can place
	// the resume point wherever it needs it.
	through int64
	ok      bool
}

func (r *recorder) RecordConstructionAudit(_ string, i int64) error {
	r.idx = append(r.idx, i)
	return nil
}

func (r *recorder) ConstructionAuditedThrough(string) (int64, bool, error) {
	return r.through, r.ok, nil
}

// The recorder must satisfy the interface the source actually consumes.
// Asserted explicitly because this type was previously declared and never
// instantiated, so a change to the interface compiled cleanly while leaving the
// behaviour untested.
var _ source.AuditRecorder = (*recorder)(nil)

// TestBackfillRefusedWithoutEntryVerification: declaring a construction history
// we have no intention of checking would make the coverage denominator real and
// the numerator permanently zero — a stalled audit rather than an absent one.
func TestBackfillRefusedWithoutEntryVerification(t *testing.T) {
	// Built directly rather than through New: the refusal under test happens
	// before any network or key handling, and a fixture key that fails to parse
	// would turn this into a skipped test that checks nothing.
	s := &Source{origin: "example.com/log", cfg: Config{VerifyEntries: false}}

	// The probe answers without doing any work, so the caller can skip before
	// announcing a pass.
	if s.BackfillApplicable() {
		t.Fatal("a log that does not verify entries has nothing to backfill")
	}
	_, err := s.Backfill(context.Background(), nil)
	if !errors.Is(err, source.ErrNotBackfillable) {
		t.Fatalf("want ErrNotBackfillable so the caller can skip quietly, got %v", err)
	}

	// And it is applicable once entry verification is on.
	s2 := &Source{origin: "example.com/log", cfg: Config{VerifyEntries: true}}
	if !s2.BackfillApplicable() {
		t.Fatal("an entry-verifying log does have a construction history")
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
