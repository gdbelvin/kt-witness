package store

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// bucketSearches holds the most recent verified search proof per origin.
//
// A search result is otherwise only in the source's memory, which means a
// restart would publish nothing until the next successful poll, and the export
// layer would have to reach into internal/source/signal to read it — the wrong
// direction entirely. Persisting the summary keeps the mirror derived from the
// database like everything else.
//
// The bucket is created lazily rather than in Open, so that a database written
// by an older build stays readable and is upgraded on the first write.
var bucketSearches = []byte("searches")

// SearchRecord summarises one verified search proof. It deliberately holds only
// plain types: the store must no more know what a Signal search is than the
// exporter does, and every field here is a number or a hash that any reader can
// check for themselves.
type SearchRecord struct {
	// Key is the identifier that was searched for, as the source names it.
	Key string `json:"key"`
	// Index is the VRF output — the key's position in the prefix tree.
	Index [32]byte `json:"index"`
	// Pos is where the identifier first appears in the log.
	Pos uint64 `json:"first_position"`
	// Version is the version counter of the entry the search landed on.
	Version uint32 `json:"version"`
	// Value is the committed value: for KT, a serialized public key.
	Value []byte `json:"value"`
	// Entries is how many log entries the search had to open.
	Entries int `json:"entries_opened"`
	// Root is the log root the proof implies, which the source has already
	// compared against a root authenticated some other way.
	Root [32]byte `json:"root"`
	// VerifiedAt is when the source accepted this proof, in Unix seconds. A
	// bare integer rather than a formatted time, so the encoding cannot drift.
	VerifiedAt int64 `json:"verified_at"`
}

// PutSearch records the most recent verified search for an origin, replacing
// any earlier one. Only the latest is kept: the durable, cumulative part of the
// evidence is the entry ledger, and a history of search summaries would grow
// without bound while saying nothing the ledger does not already say.
func (s *Store) PutSearch(origin string, r *SearchRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: put search for %s: %w", origin, err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketSearches)
		if err != nil {
			return err
		}
		return b.Put([]byte(origin), data)
	})
	if err != nil {
		return fmt.Errorf("store: put search for %s: %w", origin, err)
	}
	return nil
}

// Searches returns the latest verified search per origin. A database that has
// never recorded one simply has no bucket yet, which is not an error.
func (s *Store) Searches() (map[string]SearchRecord, error) {
	out := make(map[string]SearchRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSearches)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var r SearchRecord
			if err := json.Unmarshal(v, &r); err != nil {
				// A record we cannot decode is a bug in a past version, not a
				// reason to refuse to publish everything else.
				return nil
			}
			out[string(k)] = r
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: searches: %w", err)
	}
	return out, nil
}
