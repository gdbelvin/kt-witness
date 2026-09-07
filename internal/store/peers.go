package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Other witnesses' attestations, and the disagreements they reveal.
//
// A witness comparing a log only against its own earlier observations cannot
// see the attack the system exists to detect: a log serving one history to one
// party and another to another, consistently. From where we stand nothing is
// inconsistent. Two witnesses see it at once — and both attestations are
// signed, so neither party has to be taken at its word.

var bucketPeers = []byte("peer_attestations")

// bucketSeenWitnesses holds names observed on checkpoint signature lines that
// this witness cannot verify, because it holds no key for them.
//
// Kept in a SEPARATE bucket from peer_attestations, and that separation is the
// point. An attestation is evidence: a signature that verified under a key we
// hold, which can contradict a log. A seen name is not evidence at all —
// anyone can append a line claiming any name — it is a lead, a note that
// somebody may be witnessing beside us and that their key is worth going to
// find. Mixing the two would let an unsigned string inflate the count of
// parties that could catch a fork, which is the one number here that must
// never be flattered.
var bucketSeenWitnesses = []byte("seen_witnesses")

// PeerAttestation is what another witness said about a log at a given size.
type PeerAttestation struct {
	Origin    string `json:"origin"`
	Witness   string `json:"witness"`
	Size      int64  `json:"size"`
	Root      string `json:"root"`
	Timestamp uint64 `json:"timestamp"`
}

func peerKey(origin string, size int64, witness string) []byte {
	k := make([]byte, 0, len(origin)+len(witness)+10)
	k = append(k, origin...)
	k = append(k, 0)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(size))
	k = append(k, b[:]...)
	k = append(k, 0)
	return append(k, witness...)
}

// RecordPeer stores one attestation and reports any DISAGREEMENT it creates:
// another attestation, at the same size, with a different root.
//
// That is conclusive. A log cannot have two roots at one size, so two signed
// statements saying otherwise mean it served different histories to different
// parties. The evidence does not say which party was lied to — only that
// somebody was — which is why the caller decides what to do rather than this.
func (s *Store) RecordPeer(a *PeerAttestation) (conflicts []PeerAttestation, err error) {
	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketPeers)
		if err != nil {
			return err
		}
		prefix := append([]byte(a.Origin), 0)
		var sz [8]byte
		binary.BigEndian.PutUint64(sz[:], uint64(a.Size))
		prefix = append(prefix, sz[:]...)

		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var other PeerAttestation
			if json.Unmarshal(v, &other) != nil {
				continue
			}
			if other.Root != a.Root {
				conflicts = append(conflicts, other)
			}
		}

		enc, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put(peerKey(a.Origin, a.Size, a.Witness), enc)
	})
	if err != nil {
		return nil, fmt.Errorf("store: record peer attestation: %w", err)
	}
	return conflicts, nil
}

// PeerAttestations returns every recorded attestation for an origin.
func (s *Store) PeerAttestations(origin string) ([]PeerAttestation, error) {
	var out []PeerAttestation
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPeers)
		if b == nil {
			return nil
		}
		prefix := append([]byte(origin), 0)
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var a PeerAttestation
			if json.Unmarshal(v, &a) != nil {
				continue
			}
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: peer attestations for %s: %w", origin, err)
	}
	return out, nil
}

// SeenWitness is a name observed cosigning a checkpoint, whose key we lack.
type SeenWitness struct {
	Name    string    `json:"name"`
	Origins []string  `json:"origins"`
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
}

// RecordSeenWitness notes that a name appeared on a checkpoint we could not
// check it against. Idempotent; accumulates the logs it was seen on.
func (s *Store) RecordSeenWitness(name, origin string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketSeenWitnesses)
		if err != nil {
			return err
		}
		sw := SeenWitness{Name: name, First: now}
		if raw := b.Get([]byte(name)); raw != nil {
			_ = json.Unmarshal(raw, &sw)
		}
		sw.Name, sw.Last = name, now
		if sw.First.IsZero() {
			sw.First = now
		}
		found := false
		for _, o := range sw.Origins {
			if o == origin {
				found = true
				break
			}
		}
		if !found {
			sw.Origins = append(sw.Origins, origin)
			sort.Strings(sw.Origins)
		}
		enc, err := json.Marshal(&sw)
		if err != nil {
			return err
		}
		return b.Put([]byte(name), enc)
	})
}

// SeenWitnesses lists the names observed but unverifiable, most logs first.
func (s *Store) SeenWitnesses() ([]SeenWitness, error) {
	var out []SeenWitness
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSeenWitnesses)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, raw []byte) error {
			var sw SeenWitness
			if json.Unmarshal(raw, &sw) == nil {
				out = append(out, sw)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return len(out[i].Origins) > len(out[j].Origins) })
	return out, err
}
