package store

import (
	"bytes"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// SourceState returns the opaque state a source last saved for an origin, or
// nil if it never saved any.
//
// Some protocols cannot prove consistency from a bare (size, root) pair.
// IETF Key Transparency proves a new head against the full subtree hashes and
// frontier entries the verifier kept from the old one, so a witness that
// forgets them on restart can never prove anything again for that log. The
// head alone is not enough memory; this is the rest of it.
func (s *Store) SourceState(origin string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket(bucketSourceState).Get([]byte(origin)))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: source state for %s: %w", origin, err)
	}
	return out, nil
}

// PutSourceState replaces a source's saved state.
func (s *Store) PutSourceState(origin string, state []byte) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSourceState).Put([]byte(origin), state)
	})
	if err != nil {
		return fmt.Errorf("store: saving source state for %s: %w", origin, err)
	}
	return nil
}
