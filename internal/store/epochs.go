package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Epoch commitments, recorded so a second one for the same epoch is a
// contradiction rather than a surprise.
//
// # Why this exists
//
// Proton's design assigns an external auditor a specific duty: check that there
// is *exactly one* (epochID, chainHash, issuanceTime) per epoch. That is the
// non-equivocation check for the whole scheme — Proton commits each epoch into a
// WebPKI certificate logged in CT, and serving two different commitments for one
// epoch is precisely how a split view would be built.
//
// Proton's white paper says clients "trust that some External Auditor somewhere
// is scanning CT logs for equivocation". At last public review the auditor was
// work-in-progress and no public endpoint existed, so this is a duty the design
// names and, as far as can be shown, nobody performs.
//
// It has to be persistent. An in-memory check only catches an operator that
// equivocates twice while one process happens to be running; the interesting
// attack shows one commitment now and a different one after we restart.

// EpochCommitment is what Proton bound into an epoch's certificate.
type EpochCommitment struct {
	EpochID       int64  `json:"epoch_id"`
	ChainHash     string `json:"chain_hash"`
	IssuanceTime  int64  `json:"issuance_time"`
	FirstSeenUnix int64  `json:"first_seen_unix"`
}

// EpochConflict is two different commitments for one epoch.
//
// Unlike most disagreements this project handles, this one needs no
// interpretation: the operator committed an epoch into a publicly logged
// certificate, and then committed it differently. Both are non-repudiable.
type EpochConflict struct {
	Origin string
	Stored *EpochCommitment
	Seen   *EpochCommitment
}

func (c *EpochConflict) Error() string {
	return fmt.Sprintf(
		"%s epoch %d committed twice: chain hash %s at issuance %d, and %s at issuance %d",
		c.Origin, c.Seen.EpochID, c.Stored.ChainHash, c.Stored.IssuanceTime,
		c.Seen.ChainHash, c.Seen.IssuanceTime)
}

func epochKey(origin string, id int64) []byte {
	k := make([]byte, 0, len(origin)+9)
	k = append(k, origin...)
	k = append(k, '|')
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return append(k, b[:]...)
}

// RecordEpochCommitment stores an epoch's commitment, or returns *EpochConflict
// if a different one is already recorded for that epoch.
//
// Re-recording an identical commitment is a no-op, which is the common case:
// the same epoch is re-observed on every pass.
func (s *Store) RecordEpochCommitment(origin string, epochID int64, chainHash string, issuanceTime int64) error {
	c := &EpochCommitment{
		EpochID: epochID, ChainHash: chainHash, IssuanceTime: issuanceTime,
		FirstSeenUnix: time.Now().Unix(),
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketEpochs)
		if err != nil {
			return err
		}
		k := epochKey(origin, c.EpochID)
		if raw := b.Get(k); raw != nil {
			var prev EpochCommitment
			if err := json.Unmarshal(raw, &prev); err != nil {
				return err
			}
			if prev.ChainHash == c.ChainHash && prev.IssuanceTime == c.IssuanceTime {
				return nil
			}
			return &EpochConflict{Origin: origin, Stored: &prev, Seen: c}
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		return b.Put(k, raw)
	})
}

// EpochCommitments returns every commitment recorded for an origin, ordered by
// epoch, so the issuance-time ordering rule can be checked across the record
// rather than only against the previous observation.
func (s *Store) EpochCommitments(origin string) ([]EpochCommitment, error) {
	var out []EpochCommitment
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEpochs)
		if b == nil {
			return nil
		}
		prefix := append([]byte(origin), '|')
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) > len(prefix) &&
			string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			var e EpochCommitment
			if json.Unmarshal(v, &e) != nil {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}
