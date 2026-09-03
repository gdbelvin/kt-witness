// Package store persists the witness's view of each log.
//
// The critical property is atomicity: the C2SP tlog-witness spec calls out a
// race where two conflicting checkpoints of the same size are both accepted.
// Every write therefore goes through CompareAndSet inside a single transaction.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/mod/sumdb/tlog"
)

var (
	bucketHeads = []byte("heads")
	bucketForks = []byte("forks")

	// bucketPoisoned records which logs have ever forked. A fork is permanent:
	// a log that equivocates and then reverts to a consistent view must not
	// quietly regain our cosignature.
	bucketPoisoned = []byte("poisoned")

	// bucketAudits holds tier-B sampling decisions and verification results;
	// bucketProgress tracks how far auditing has advanced per origin.
	bucketAudits   = []byte("audits")
	bucketProgress = []byte("audit_progress")

	// bucketHistory holds the result of backfilling a log's published history.
	bucketHistory = []byte("history")

	// bucketAppHeads holds heads of OTHER logs observed inside a log we witness.
	// Observations, not attestations: we cannot verify their signatures.
	bucketAppHeads = []byte("app_heads")

	// bucketLogEntries records individual log entries a source has opened and
	// verified, so between-snapshot checks survive a restart. Without it the
	// comparison only ever covers one process lifetime, and a container restart
	// silently resets the coverage to nothing.
	bucketLogEntries = []byte("log_entries")
)

// ErrRaced means the stored head changed between verification and persistence,
// so the cosignature we were about to issue may no longer be sound. The caller
// must discard it and retry from a fresh read.
var ErrRaced = errors.New("store: concurrent update, cosignature discarded")

// Record is the witness's last cosigned view of a log.
type Record struct {
	Origin string    `json:"origin"`
	Size   int64     `json:"size"`
	Hash   tlog.Hash `json:"hash"`

	// Cosigned is the signed note including our own cosignature, served
	// verbatim from the monitoring endpoint.
	Cosigned    []byte    `json:"cosigned"`
	WitnessedAt time.Time `json:"witnessed_at"`
}

type Store struct{ db *bolt.DB }

func Open(path string) (*Store, error) {
	// bbolt takes an exclusive flock on the file, so a second writer cannot
	// corrupt the database — it blocks. Without a timeout it would block
	// forever, and with one it reports a bare "timeout", which is a miserable
	// thing to debug at 3am. Name the actual cause.
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("store: %s is already open by another kt-witness process; "+
			"only one writer may use a database at a time (a second one would sign "+
			"conflicting checkpoints for the same log)", path)
	}
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketHeads, bucketForks, bucketPoisoned, bucketAudits, bucketProgress, bucketHistory, bucketAppHeads, bucketLogEntries} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store: init buckets: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Get returns the stored record for origin, or nil if the log has never been
// witnessed.
func (s *Store) Get(origin string) (*Record, error) {
	var rec *Record
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketHeads).Get([]byte(origin))
		if raw == nil {
			return nil
		}
		rec = new(Record)
		return json.Unmarshal(raw, rec)
	})
	if err != nil {
		return nil, fmt.Errorf("store: get %s: %w", origin, err)
	}
	return rec, nil
}

// List returns every witnessed log, for the monitoring endpoint.
func (s *Store) List() ([]*Record, error) {
	var out []*Record
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHeads).ForEach(func(_, raw []byte) error {
			rec := new(Record)
			if err := json.Unmarshal(raw, rec); err != nil {
				return err
			}
			out = append(out, rec)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	return out, nil
}

// CompareAndSet writes next only if the currently stored head still matches
// expect (nil meaning "no record yet"). This is the atomic size check the
// tlog-witness spec requires: without it, two concurrent submissions could each
// verify against the same old head and both be cosigned.
func (s *Store) CompareAndSet(expect, next *Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHeads)
		raw := b.Get([]byte(next.Origin))

		var cur *Record
		if raw != nil {
			cur = new(Record)
			if err := json.Unmarshal(raw, cur); err != nil {
				return err
			}
		}

		switch {
		case cur == nil && expect != nil:
			return ErrRaced
		case cur != nil && expect == nil:
			return ErrRaced
		case cur != nil && (cur.Size != expect.Size || cur.Hash != expect.Hash):
			return ErrRaced
		}

		enc, err := json.Marshal(next)
		if err != nil {
			return err
		}
		return b.Put([]byte(next.Origin), enc)
	})
}

// Fork is persisted evidence of a log violating its append-only promise. It is
// written so that an out-of-band disclosure is reproducible by a third party.
type Fork struct {
	Origin     string    `json:"origin"`
	Reason     string    `json:"reason"`
	DetectedAt time.Time `json:"detected_at"`
	PrevSigned []byte    `json:"prev_signed"`
	NextSigned []byte    `json:"next_signed"`
}

// RecordFork persists fork evidence and permanently poisons the log.
//
// Evidence is written once: the first observation is the one that matters, and
// re-recording it every poll would bury it in noise. The poison marker is what
// makes the refusal permanent, so a log cannot clear its record by reverting to
// a consistent view.
func (s *Store) RecordFork(f *Fork) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		poisoned := tx.Bucket(bucketPoisoned)
		if poisoned.Get([]byte(f.Origin)) != nil {
			return nil // already recorded; keep the original evidence
		}
		enc, err := json.Marshal(f)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s|%d", f.Origin, f.DetectedAt.UnixNano())
		if err := tx.Bucket(bucketForks).Put([]byte(key), enc); err != nil {
			return err
		}
		return poisoned.Put([]byte(f.Origin), []byte(f.DetectedAt.Format(time.RFC3339)))
	})
}

// IsForked reports whether a log has ever been observed forking. Such a log is
// never cosigned again without human intervention.
func (s *Store) IsForked(origin string) (bool, error) {
	var forked bool
	err := s.db.View(func(tx *bolt.Tx) error {
		forked = tx.Bucket(bucketPoisoned).Get([]byte(origin)) != nil
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("store: is-forked %s: %w", origin, err)
	}
	return forked, nil
}

// Forks returns all recorded fork evidence.
func (s *Store) Forks() ([]*Fork, error) {
	var out []*Fork
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketForks).ForEach(func(_, raw []byte) error {
			f := new(Fork)
			if err := json.Unmarshal(raw, f); err != nil {
				return err
			}
			out = append(out, f)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: forks: %w", err)
	}
	return out, nil
}

// Audit is one epoch's sampling decision and, if selected, its verification
// result.
//
// Declined epochs are recorded too: a published coverage claim is only checkable
// if the record shows what was skipped and the beacon value that decided it.
type Audit struct {
	Origin  string  `json:"origin"`
	Epoch   int64   `json:"epoch"`
	Sampled bool    `json:"sampled"`
	Rate    float64 `json:"rate"`

	// Beacon evidence, so a third party can recompute the selection.
	BeaconRound  uint64 `json:"beacon_round"`
	BeaconSig    string `json:"beacon_signature"`
	BeaconRandom string `json:"beacon_randomness"`

	Verified bool `json:"verified"`

	// Attempts counts how many times we tried to verify a sampled epoch. An
	// epoch we could never fetch is eventually recorded as unavailable rather
	// than retried forever, so coverage accounting stays honest and one dead
	// blob cannot stall auditing for good.
	Attempts int `json:"attempts,omitempty"`

	Kind       string `json:"kind,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`

	DecidedAt time.Time `json:"decided_at"`
}

func auditKey(origin string, epoch int64) []byte {
	// Zero-padded so keys sort numerically within an origin.
	return []byte(fmt.Sprintf("%s|%020d", origin, epoch))
}

// maxAuditsPerOrigin bounds retained sampling decisions per origin.
//
// The audit trail is what makes coverage auditable rather than asserted, so it
// cannot simply be discarded — but it also cannot grow forever, and bbolt does
// not return freed pages to the filesystem. The oldest decisions are dropped
// first: recent coverage is what anyone checking would ask about, and the file
// mirror in internal/export keeps a copy outside the database anyway.
const maxAuditsPerOrigin = 200_000

func (s *Store) RecordAudit(a *Audit) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAudits)
		enc, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if err := b.Put(auditKey(a.Origin, a.Epoch), enc); err != nil {
			return err
		}
		return trimAudits(b, a.Origin)
	})
}

// trimAudits drops the oldest decisions for one origin once the cap is passed.
func trimAudits(b *bolt.Bucket, origin string) error {
	prefix := []byte(origin + "|")
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	// Keys embed a zero-padded epoch, so this is oldest-first.
	for i := 0; i+maxAuditsPerOrigin < len(keys); i++ {
		if err := b.Delete(keys[i]); err != nil {
			return err
		}
	}
	return nil
}

// Audits returns recorded audit decisions for an origin, most recent first,
// capped at limit.
func (s *Store) Audits(origin string, limit int) ([]*Audit, error) {
	var out []*Audit
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		// Seek past the origin's range, then walk backwards for recency.
		k, v := c.Seek(append(prefix, 0xff))
		if k == nil {
			k, v = c.Last()
		}
		for ; k != nil && len(out) < limit; k, v = c.Prev() {
			if !bytes.HasPrefix(k, prefix) {
				continue
			}
			a := new(Audit)
			if err := json.Unmarshal(v, a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: audits %s: %w", origin, err)
	}
	return out, nil
}

// AuditProgress is the highest epoch whose sampling decision has been settled.
func (s *Store) AuditProgress(origin string) (int64, error) {
	var n int64
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketProgress).Get([]byte(origin))
		if raw != nil {
			n, _ = strconv.ParseInt(string(raw), 10, 64)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: audit progress %s: %w", origin, err)
	}
	return n, nil
}

func (s *Store) SetAuditProgress(origin string, epoch int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProgress).Put([]byte(origin), []byte(strconv.FormatInt(epoch, 10)))
	})
}

// GetAudit returns the recorded decision for one epoch, or nil.
func (s *Store) GetAudit(origin string, epoch int64) (*Audit, error) {
	var a *Audit
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketAudits).Get(auditKey(origin, epoch))
		if raw == nil {
			return nil
		}
		a = new(Audit)
		return json.Unmarshal(raw, a)
	})
	if err != nil {
		return nil, fmt.Errorf("store: get audit %s/%d: %w", origin, epoch, err)
	}
	return a, nil
}

// History records a verified historical range, so a backfill's result survives
// restarts and can be published.
type History struct {
	Origin     string    `json:"origin"`
	From       int64     `json:"from"`
	To         int64     `json:"to"`
	Epochs     int       `json:"epochs"`
	Gaps       []string  `json:"gaps,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
}

func (s *Store) RecordHistory(h *History) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		enc, err := json.Marshal(h)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketHistory).Put([]byte(h.Origin), enc)
	})
}

func (s *Store) Histories() ([]*History, error) {
	var out []*History
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHistory).ForEach(func(_, raw []byte) error {
			h := new(History)
			if err := json.Unmarshal(raw, h); err != nil {
				return err
			}
			out = append(out, h)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: histories: %w", err)
	}
	return out, nil
}

// AppHead is what we have observed about another log's head, seen inside a log
// we witness.
//
// Deliberately separate from Record: these are observations, not attestations.
// We never cosign them, because we cannot verify their signatures.
type AppHead struct {
	Origin      string `json:"origin"`
	TreeID      uint64 `json:"tree_id"`
	Application uint64 `json:"application"`
	Name        string `json:"name"`

	LogSize  uint64 `json:"log_size"`
	Revision uint64 `json:"revision"`
	RootHash string `json:"root_hash"`

	SigningKeyHash string `json:"signing_key_hash"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Conflicts records contradictions: a revision reappearing with a different
	// root, a size going backwards, or the signing key changing.
	Conflicts []string `json:"conflicts,omitempty"`
}

func appHeadKey(origin string, treeID uint64) []byte {
	return []byte(fmt.Sprintf("%s|%020d", origin, treeID))
}

// ObserveAppHead merges a new observation, recording any contradiction against
// what we saw before.
// maxAppHeadConflicts bounds the recorded contradictions per observed tree.
const maxAppHeadConflicts = 32

// ObserveAppHead records an observed per-application head and returns the merged
// record together with any contradictions seen *for the first time*.
func (s *Store) ObserveAppHead(now time.Time, obs *AppHead) (*AppHead, []string, error) {
	var out *AppHead
	var newConflicts []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAppHeads)
		key := appHeadKey(obs.Origin, obs.TreeID)

		cur := new(AppHead)
		if raw := b.Get(key); raw != nil {
			if err := json.Unmarshal(raw, cur); err != nil {
				return err
			}
		} else {
			*cur = *obs
			cur.FirstSeen = now
		}

		// Contradictions are recorded rather than acted on: these heads are not
		// signature-verified, so they are evidence to look at, not grounds to
		// refuse anything.
		var found []string
		if obs.Revision == cur.Revision && obs.RootHash != cur.RootHash {
			found = append(found, fmt.Sprintf(
				"revision %d seen with two roots: %s then %s", obs.Revision, cur.RootHash, obs.RootHash))
		}
		if obs.LogSize < cur.LogSize {
			found = append(found, fmt.Sprintf(
				"log size went backwards: %d then %d", cur.LogSize, obs.LogSize))
		}
		if cur.SigningKeyHash != "" && obs.SigningKeyHash != cur.SigningKeyHash {
			found = append(found, fmt.Sprintf(
				"signing key changed: %s then %s", cur.SigningKeyHash, obs.SigningKeyHash))
		}

		// Only conflicts not already recorded are new. Without this the same
		// historical contradiction is reported on every scan for the life of the
		// record, which trains an operator to ignore the one log line that is
		// supposed to demand attention.
		for _, c := range found {
			if !slices.Contains(cur.Conflicts, c) {
				newConflicts = append(newConflicts, c)
			}
		}
		cur.Conflicts = append(cur.Conflicts, newConflicts...)
		// Bounded: an unbounded list is a memory and storage leak, and the first
		// occurrences are the informative ones.
		if len(cur.Conflicts) > maxAppHeadConflicts {
			cur.Conflicts = cur.Conflicts[:maxAppHeadConflicts]
		}

		if obs.LogSize >= cur.LogSize {
			cur.LogSize, cur.Revision, cur.RootHash = obs.LogSize, obs.Revision, obs.RootHash
			cur.SigningKeyHash = obs.SigningKeyHash
		}
		cur.Name, cur.Application, cur.TreeID, cur.Origin = obs.Name, obs.Application, obs.TreeID, obs.Origin
		cur.LastSeen = now

		enc, err := json.Marshal(cur)
		if err != nil {
			return err
		}
		out = cur
		return b.Put(key, enc)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("store: observe app head: %w", err)
	}
	return out, newConflicts, nil
}

func (s *Store) AppHeads() ([]*AppHead, error) {
	var out []*AppHead
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAppHeads).ForEach(func(_, raw []byte) error {
			a := new(AppHead)
			if err := json.Unmarshal(raw, a); err != nil {
				return err
			}
			out = append(out, a)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: app heads: %w", err)
	}
	return out, nil
}

// --- verified log entries ----------------------------------------------------

// maxLogEntriesPerOrigin bounds the retained entries per origin. The lowest ids
// are kept: they are the ones a search revisits, while entries near the frontier
// churn and are never seen again.
const maxLogEntriesPerOrigin = 1 << 16

func logEntryKey(origin string, id uint64) []byte {
	k := make([]byte, 0, len(origin)+9)
	k = append(k, origin...)
	k = append(k, 0)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	return append(k, b[:]...)
}

// LogEntries returns every verified entry recorded for an origin.
func (s *Store) LogEntries(origin string) (map[uint64][32]byte, error) {
	out := make(map[uint64][32]byte)
	prefix := append([]byte(origin), 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLogEntries).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(v) != 32 || len(k) != len(prefix)+8 {
				continue
			}
			var h [32]byte
			copy(h[:], v)
			out[binary.BigEndian.Uint64(k[len(prefix):])] = h
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: log entries for %s: %w", origin, err)
	}
	return out, nil
}

// PutLogEntries records verified entries for an origin.
//
// It does not check for contradictions: that is the source's job, because only
// the source knows what a contradiction means for its own log. This just makes
// the observation durable.
func (s *Store) PutLogEntries(origin string, entries map[uint64][32]byte) error {
	if len(entries) == 0 {
		return nil
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLogEntries)
		for id, h := range entries {
			if err := b.Put(logEntryKey(origin, id), h[:]); err != nil {
				return err
			}
		}

		// Trim from the high end. Collect first, then delete: mutating a bucket
		// while a cursor walks it is asking for trouble.
		prefix := append([]byte(origin), 0)
		var keys [][]byte
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		// Keys are byte-ordered, and the id is a big-endian suffix, so this
		// slice is already in ascending id order. The tail is the frontier.
		for i := maxLogEntriesPerOrigin; i < len(keys); i++ {
			if err := b.Delete(keys[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: put log entries for %s: %w", origin, err)
	}
	return nil
}

// --- historical audit progress ------------------------------------------------

// backProgressKey namespaces the backwards sweep so it cannot collide with the
// forward one, which uses the bare origin.
func backProgressKey(origin string) []byte { return []byte("back|" + origin) }

// BackAuditProgress is the LOWEST epoch the historical sweep has reached, or 0
// if it has not started.
//
// The forward auditor only ever moves from where witnessing began, so "tier B"
// otherwise means "epochs since we showed up" rather than "this log's published
// history is construction audited". Sweeping backwards is what closes that gap,
// and it needs its own high-water mark because it moves the other way.
func (s *Store) BackAuditProgress(origin string) (int64, error) {
	var out int64
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketProgress).Get(backProgressKey(origin)); v != nil {
			out, _ = strconv.ParseInt(string(v), 10, 64)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: back audit progress for %s: %w", origin, err)
	}
	return out, nil
}

func (s *Store) SetBackAuditProgress(origin string, epoch int64) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProgress).Put(backProgressKey(origin),
			[]byte(strconv.FormatInt(epoch, 10)))
	})
	if err != nil {
		return fmt.Errorf("store: set back audit progress for %s: %w", origin, err)
	}
	return nil
}

// AuditCoverage counts how many epochs in [from, to] have a settled decision,
// and how many of those were actually verified.
//
// This is what turns "tier B" into a measured claim rather than an asserted
// one: a log is only construction-audited across its published history if the
// record says every epoch in that range was considered.
func (s *Store) AuditCoverage(origin string, from, to int64) (settled, verified int64, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var a Audit
			if json.Unmarshal(v, &a) != nil {
				continue
			}
			if a.Epoch < from || a.Epoch > to {
				continue
			}
			settled++
			if a.Verified {
				verified++
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("store: audit coverage for %s: %w", origin, err)
	}
	return settled, verified, nil
}
