package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Logs discovered from witness-network.org log lists.
//
// The network's rule is blunt: a witness "must not remove or update an already
// configured log as a result of a changed list." A list is a way to learn about
// a log, never a way to re-key one. If a list could swap a log's verifier key,
// whoever controls the list — or the HTTPS path to it — could hand us a key of
// their choosing for a log we already witness, and we would cosign whatever
// that key signed. So this file offers an add and a read, and deliberately
// nothing else: no update, no delete. The first key we learn for an origin is
// the key we keep.

// PushLog is one log learned from a list, as first seen.
type PushLog struct {
	Origin  string `json:"origin"`
	VKey    string `json:"vkey"`
	QPD     int64  `json:"qpd"`
	Contact string `json:"contact"`
	// List is the URL of the list that introduced the log.
	List    string    `json:"list"`
	AddedAt time.Time `json:"added_at"`
}

// AddPushLog records l if its origin has never been recorded, and reports
// whether it did. An origin already present is left exactly as it was, even if
// l carries a different key: that is the add-only guarantee, not an error.
//
// The existence check and the write share one transaction, so two fetches
// racing to introduce the same origin cannot both win.
func (s *Store) AddPushLog(l *PushLog) (added bool, err error) {
	if l.Origin == "" {
		return false, fmt.Errorf("store: add push log: empty origin")
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPushLogs)
		if b.Get([]byte(l.Origin)) != nil {
			return nil
		}
		enc, err := json.Marshal(l)
		if err != nil {
			return err
		}
		added = true
		return b.Put([]byte(l.Origin), enc)
	})
	if err != nil {
		return false, fmt.Errorf("store: add push log %s: %w", l.Origin, err)
	}
	return added, nil
}

// PushLogs returns every discovered log, ordered by origin.
func (s *Store) PushLogs() ([]*PushLog, error) {
	var out []*PushLog
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPushLogs).ForEach(func(_, raw []byte) error {
			l := new(PushLog)
			if err := json.Unmarshal(raw, l); err != nil {
				return err
			}
			out = append(out, l)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: push logs: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out, nil
}
