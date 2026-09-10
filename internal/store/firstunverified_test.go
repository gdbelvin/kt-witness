package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func put(t *testing.T, s *Store, origin string, epoch int64, verified bool) {
	t.Helper()
	if err := s.RecordAudit(&Audit{Origin: origin, Epoch: epoch, Verified: verified,
		Sampled: true, DecidedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// TestFirstUnverified covers the three shapes the work feed has to distinguish,
// and the third is the one that cost 7,880 epochs: an epoch nobody has recorded
// a decision about is unverified, not absent.
func TestFirstUnverified(t *testing.T) {
	const o = "whatsapp.kt/v2"
	s := openTemp(t)

	// Nothing recorded at all: the range starts where it starts.
	if at, found, err := s.FirstUnverified(o, 10, 20); err != nil || !found || at != 10 {
		t.Errorf("empty store: (%d, %v, %v), want (10, true, nil)", at, found, err)
	}

	// A contiguous run of verified epochs, then a hole recorded as failed.
	for e := int64(1); e <= 10; e++ {
		put(t, s, o, e, true)
	}
	put(t, s, o, 11, false)
	if at, found, _ := s.FirstUnverified(o, 1, 20); !found || at != 11 {
		t.Errorf("recorded failure: (%d, %v), want (11, true)", at, found)
	}

	// A GAP — epochs 12..20 have no record at all. Absent is unverified, which
	// is the whole point: an epoch nobody has decided about is the work.
	for e := int64(11); e <= 15; e++ {
		put(t, s, o, e, true)
	}
	if at, found, _ := s.FirstUnverified(o, 1, 20); !found || at != 16 {
		t.Errorf("gap after 15: (%d, %v), want (16, true)", at, found)
	}

	// Fully verified: nothing to do, and it must say so rather than looping.
	for e := int64(16); e <= 20; e++ {
		put(t, s, o, e, true)
	}
	if at, found, _ := s.FirstUnverified(o, 1, 20); found {
		t.Errorf("fully verified range still reported work at %d", at)
	}

	// Another origin's records must not answer this one's question.
	put(t, s, "meta.messenger.kt/v1", 5, false)
	if _, found, _ := s.FirstUnverified(o, 1, 20); found {
		t.Error("another origin's unverified epoch leaked into this range")
	}

	// An inverted range is empty, not an error and not a scan of everything.
	if _, found, err := s.FirstUnverified(o, 20, 1); found || err != nil {
		t.Errorf("inverted range: found=%v err=%v", found, err)
	}
}
