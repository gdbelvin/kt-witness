package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Retracting a fork finding.
//
// # Why this is awkward on purpose
//
// A fork is meant to be permanent. Poisoning a log is the strongest thing this
// witness does, and a retraction path that felt routine would erode exactly the
// property that makes the finding worth anything.
//
// But a witness that cannot retract is worse. Findings come from code, code has
// bugs, and the first fork this project ever recorded was one of them: the
// witness accused the Go checksum database of forking because a CDN replica
// served an older — validly signed, perfectly consistent — checkpoint, and the
// logic inferred equivocation from ordering alone. Without a retraction the
// only remedies are editing the database by hand or discarding the witness's
// whole history, and both are worse than an explicit, recorded reversal.
//
// So: retraction is deliberate, names a reason, and leaves the original
// evidence in place. What is withdrawn is the *accusation*, not the record that
// it was made.

// Retraction records that a fork finding was withdrawn.
type Retraction struct {
	Origin      string    `json:"origin"`
	Reason      string    `json:"reason"`
	RetractedAt time.Time `json:"retracted_at"`

	// Fork is the finding that was withdrawn, kept verbatim so the reversal can
	// be audited as readily as the accusation.
	Fork *Fork `json:"fork"`
}

// RetractFork un-poisons a log, recording why.
//
// The original fork evidence is retained under bucketForks and the retraction
// is stored alongside it. Anyone reading the witness's history sees both the
// claim and its withdrawal, which is the only honest way to take back a public
// accusation.
func (s *Store) RetractFork(origin, reason string) error {
	if reason == "" {
		return fmt.Errorf("store: retracting %s: a reason is required", origin)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		poisoned := tx.Bucket(bucketPoisoned)
		if poisoned.Get([]byte(origin)) == nil {
			return fmt.Errorf("store: %s is not marked forked", origin)
		}

		// Fork evidence is keyed "origin|detectedAtNanos", not by origin alone,
		// so the finding is found by scanning that prefix rather than by a
		// direct Get. Missing it silently would produce a retraction that names
		// no finding, which is exactly the unauditable reversal this avoids.
		var f *Fork
		prefix := []byte(origin + "|")
		c := tx.Bucket(bucketForks).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			cand := new(Fork)
			if err := json.Unmarshal(v, cand); err != nil {
				return err
			}
			// Keep the earliest, which is the finding that poisoned the log.
			if f == nil || cand.DetectedAt.Before(f.DetectedAt) {
				f = cand
			}
		}
		if f == nil {
			return fmt.Errorf("store: %s is marked forked but carries no evidence; refusing to retract a finding that cannot be shown", origin)
		}
		r := &Retraction{
			Origin: origin, Reason: reason,
			RetractedAt: time.Now().UTC(), Fork: f,
		}
		enc, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b, err := tx.CreateBucketIfNotExists(bucketRetractions)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(origin), enc); err != nil {
			return err
		}
		// Lift the poison so witnessing resumes. The evidence stays.
		return poisoned.Delete([]byte(origin))
	})
}

// Retractions returns every withdrawn fork finding.
func (s *Store) Retractions() ([]*Retraction, error) {
	var out []*Retraction
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRetractions)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, raw []byte) error {
			r := new(Retraction)
			if err := json.Unmarshal(raw, r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: retractions: %w", err)
	}
	return out, nil
}
