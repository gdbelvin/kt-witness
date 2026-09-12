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
	"sync"
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

	// bucketEpochs records what an operator committed for each epoch, so that a
	// second, different commitment for the same epoch is caught across restarts
	// rather than only within one process lifetime.
	bucketEpochs = []byte("epoch_commitments")

	// bucketRetractions records fork findings that were withdrawn, alongside
	// the original evidence, so a reversal is as auditable as the accusation.
	bucketRetractions = []byte("retractions")
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

type Store struct {
	db *bolt.DB

	// Retained-audit population per origin, so the retention cap can be
	// enforced without counting the bucket on every write. Counted once per
	// origin on first use and maintained from there.
	auditMu sync.Mutex
	auditN  map[string]int
}

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
		for _, b := range [][]byte{bucketHeads, bucketForks, bucketPoisoned, bucketAudits, bucketProgress, bucketHistory, bucketAppHeads, bucketLogEntries, bucketEpochs, bucketRetractions} {
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

	// Strategy names the rule that chose this epoch: live, backlog or history.
	// Published so the record says which regime applied, since the sampling
	// rate alone no longer identifies it.
	Strategy string `json:"strategy,omitempty"`

	Verified bool `json:"verified"`

	// Attempts counts how many times we tried to verify a sampled epoch. An
	// epoch we could never fetch is eventually recorded as unavailable rather
	// than retried forever, so coverage accounting stays honest and one dead
	// blob cannot stall auditing for good.
	Attempts int `json:"attempts,omitempty"`

	// RetryAfter is when an exhausted epoch becomes eligible to be tried again.
	//
	// Giving up permanently was wrong. The reasons an epoch cannot be fetched
	// are mostly temporary — a CDN serving a stale negative listing, a 403 that
	// clears a minute later, a diff that lags its epoch — and a permanent
	// verdict on temporary evidence leaves a hole that never heals. Worse, it is
	// a hole in the very claim tier B+ makes, so the cheapest way to lose the
	// strongest assertion this witness publishes is to be briefly unlucky.
	//
	// So exhausting the attempts stops the sweep spending every pass on the
	// epoch — which is what the stall fix was for — without ever declaring it
	// beyond hope. The backoff grows so a genuinely dead blob costs a handful of
	// requests a week rather than a burst on every round.
	//
	// Zero means "not exhausted, retry whenever the sweep reaches it".
	RetryAfter time.Time `json:"retry_after,omitempty"`

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
//
// # Why this is 750,000 and not 200,000
//
// It has to exceed the largest published history we audit, or the cap silently
// becomes a ceiling on the strongest claim we make. Meta publishes ~538,000
// epochs and WhatsApp ~502,000. At a 200,000 cap the trim drops the LOWEST
// epochs — which is exactly what the backwards sweep has just written, since it
// walks downward — so coverage would stall at 200,000, B+ would be permanently
// unreachable for both large logs, and nothing would look wrong: the sweep
// would keep verifying, the counter would keep rising, and the coverage figure
// would sit still. At ~190 epochs an hour that was about six weeks away.
//
// The cost is disk. A record is roughly 300 bytes of JSON, so 750,000 is around
// 225 MB per origin and under 500 MB for the two large logs together — small
// beside the proof cache, and the retention window is now bounded by the logs'
// own published history rather than by an arbitrary number.
const maxAuditsPerOrigin = 750_000

func (s *Store) RecordAudit(a *Audit) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAudits)
		enc, err := json.Marshal(a)
		if err != nil {
			return err
		}
		key := auditKey(a.Origin, a.Epoch)
		// Whether this Put grows the population, decided before writing. An
		// overwrite — which is most writes, since epochs are re-recorded as
		// their attempts change — cannot push the origin over the cap.
		grew := b.Get(key) == nil
		if err := b.Put(key, enc); err != nil {
			return err
		}
		if !grew {
			return nil
		}
		n := s.auditCount(b, a.Origin)
		if n <= maxAuditsPerOrigin {
			return nil
		}
		if err := trimAudits(b, a.Origin, n-maxAuditsPerOrigin); err != nil {
			return err
		}
		s.setAuditCount(a.Origin, maxAuditsPerOrigin)
		return nil
	})
}

// auditCount returns the retained decisions for an origin, counting the bucket
// once and then maintaining the number in memory.
//
// The count used to be recomputed by scanning every key for the origin on EVERY
// write — hundreds of thousands of key copies per audit, growing linearly with
// coverage, on the hot path of the thing whose throughput we care about most.
func (s *Store) auditCount(b *bolt.Bucket, origin string) int {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditN == nil {
		s.auditN = make(map[string]int)
	}
	n, known := s.auditN[origin]
	if !known {
		prefix := []byte(origin + "|")
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			n++
		}
	}
	n++ // the key just written
	s.auditN[origin] = n
	return n
}

// AuditPopulation returns how many audit records are retained for an origin.
//
// Cheap after the first call: the number is maintained in memory. Exposed so a
// caller caching a derived figure can tell whether the underlying record has
// actually changed, rather than relying on elapsed time alone — a coverage
// figure that lags a write by a full TTL would let a log sit at the wrong tier
// for no reason other than a clock.
func (s *Store) AuditPopulation(origin string) (int, error) {
	s.auditMu.Lock()
	if n, ok := s.auditN[origin]; ok {
		s.auditMu.Unlock()
		return n, nil
	}
	s.auditMu.Unlock()

	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: audit population for %s: %w", origin, err)
	}
	s.setAuditCount(origin, n)
	return n, nil
}

func (s *Store) setAuditCount(origin string, n int) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditN == nil {
		s.auditN = make(map[string]int)
	}
	s.auditN[origin] = n
}

// trimAudits drops the `excess` oldest decisions for one origin.
func trimAudits(b *bolt.Bucket, origin string, excess int) error {
	prefix := []byte(origin + "|")
	c := b.Cursor()
	// Keys embed a zero-padded epoch, so the cursor walks oldest-first and only
	// the keys actually being deleted are touched.
	var doomed [][]byte
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix) && len(doomed) < excess; k, _ = c.Next() {
		doomed = append(doomed, append([]byte(nil), k...))
	}
	for _, k := range doomed {
		if err := b.Delete(k); err != nil {
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

	// EverFrom is the lowest From ever recorded for this origin, and FirstSeen
	// is when we first recorded any history for it.
	//
	// They exist because From MOVES. An operator with a retention window drops
	// its oldest epochs as it publishes new ones, and RecordHistory overwrites,
	// so without a watermark the witness forgets that the older epochs were
	// ever offered. That forgetting hides the most consequential thing this
	// project has found: an epoch whose diff has aged out cannot be
	// reconstructed by anyone, ever again, and a witness that only reports the
	// CURRENT window reports a shrinking archive as though it were a stable
	// one.
	EverFrom  int64     `json:"ever_from,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Expired reports how many epochs have aged out of the published window since
// this witness first looked. Zero for an operator that retains everything.
func (h *History) Expired() int64 {
	if h.EverFrom == 0 || h.From <= h.EverFrom {
		return 0
	}
	return h.From - h.EverFrom
}

func (s *Store) RecordHistory(h *History) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistory)
		// Carry the watermark forward. The incoming record describes what is
		// published NOW; only the stored one remembers what once was, and a
		// backfill that simply overwrote it destroyed the evidence that an
		// operator's window had moved.
		h.EverFrom, h.FirstSeen = h.From, h.VerifiedAt
		if raw := b.Get([]byte(h.Origin)); raw != nil {
			var prev History
			if json.Unmarshal(raw, &prev) == nil {
				low := prev.EverFrom
				if low == 0 {
					low = prev.From // recorded before the watermark existed
				}
				if low > 0 && low < h.EverFrom {
					h.EverFrom = low
				}
				if !prev.FirstSeen.IsZero() {
					h.FirstSeen = prev.FirstSeen
				}
			}
		}
		enc, err := json.Marshal(h)
		if err != nil {
			return err
		}
		return b.Put([]byte(h.Origin), enc)
	})
}

// LowerHistoryWatermark records that an origin once published history reaching
// further back than this witness ever saw.
//
// The watermark set by RecordHistory can only remember what we observed, which
// means a witness that started watching last week reports nothing lost — even
// when the operator's own published metadata says otherwise. Proton stamps each
// epoch with the retention floor in force when it was published, so the oldest
// epoch still served is direct evidence of how much has already aged out.
//
// Only ever lowers. Evidence that the window was once wider is additive; a
// later, higher figure is not evidence it has narrowed back.
func (s *Store) LowerHistoryWatermark(origin string, everFrom int64) (bool, error) {
	if everFrom <= 0 {
		return false, nil
	}
	changed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistory)
		raw := b.Get([]byte(origin))
		if raw == nil {
			return nil // nothing to attach it to yet
		}
		var h History
		if err := json.Unmarshal(raw, &h); err != nil {
			return err
		}
		cur := h.EverFrom
		if cur == 0 {
			cur = h.From
		}
		if cur <= everFrom {
			return nil
		}
		h.EverFrom = everFrom
		enc, err := json.Marshal(&h)
		if err != nil {
			return err
		}
		changed = true
		return b.Put([]byte(origin), enc)
	})
	return changed, err
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

// BackAuditProgress is the LOWEST epoch the historical sweep has reached. The
// bool reports whether the sweep has started at all.
//
// The forward auditor only ever moves from where witnessing began, so "tier B"
// otherwise means "epochs since we showed up" rather than "this log's published
// history is construction audited". Sweeping backwards is what closes that gap,
// and it needs its own high-water mark because it moves the other way.
//
// The bool is not decoration. Returning a bare 0 makes "has not started" and
// "swept all the way down to epoch 0" the same value, so a log whose history
// begins at zero would be read as unstarted the moment it finished and swept
// from the top again, forever. Two bugs in this codebase have already come from
// exactly this conflation, so the ambiguity is removed rather than documented.
func (s *Store) BackAuditProgress(origin string) (int64, bool, error) {
	var out int64
	var set bool
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketProgress).Get(backProgressKey(origin)); v != nil {
			out, _ = strconv.ParseInt(string(v), 10, 64)
			set = true
		}
		return nil
	})
	if err != nil {
		return 0, false, fmt.Errorf("store: back audit progress for %s: %w", origin, err)
	}
	return out, set, nil
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

// HolesDue lists epochs that were settled without being verified and whose
// retry backoff has elapsed, soonest-eligible first.
//
// These are the gaps in the swept range. The backwards cursor cannot find them
// again — it only ever walks down, so anything it has already passed is behind
// it forever — which is why they need their own pass.
func (s *Store) HolesDue(origin string, from, to int64, now time.Time, limit int) ([]int64, error) {
	var out []int64
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(out) >= limit {
				return nil
			}
			var a Audit
			if json.Unmarshal(v, &a) != nil {
				continue
			}
			if a.Verified || a.Epoch < from || a.Epoch > to {
				continue
			}
			// Attempts decide ownership, not the timestamp.
			//
			// This used to skip any record with a zero RetryAfter, reasoning
			// that an unexhausted epoch still belongs to the ordinary sweep and
			// this pass must not race it. The reasoning is right; reading it off
			// RetryAfter was wrong, because a zero there means only that nobody
			// scheduled a retry — which is exactly the state of every hole
			// written while the field had no writer at all.
			//
			// Measured: 436 Meta epochs stuck at attempts=5 with
			// 0001-01-01T00:00:00Z, invisible to this function forever. They
			// failed on "No space left on device" during a tmpfs misconfiguration
			// days earlier, and every one of them fetches fine now.
			if a.Attempts < MaxFetchAttempts {
				continue // the ordinary sweep still owns it
			}
			if !a.RetryAfter.IsZero() && now.Before(a.RetryAfter) {
				continue // exhausted, but still inside its backoff
			}
			out = append(out, a.Epoch)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: holes due for %s: %w", origin, err)
	}
	return out, nil
}

// Coverage is everything the tier calculation and the coverage metrics need
// about one origin, gathered in a single pass.
type Coverage struct {
	Settled  int64 // epochs in range with any decision
	Verified int64 // epochs in range actually replayed and checked
	Holes    int64 // settled but not verified: gaps inside the range
	// The largest unbroken run of verified epochs.
	From, To, Run int64
}

// CoverageOf gathers coverage for one origin in one scan.
//
// AuditCoverage and VerifiedRegion each walked every audit record for the
// origin and JSON-decoded it, and both ran per origin on every metrics scrape
// AND every page load. That is two full decodes of a bucket that grows toward
// the retention cap, several times a minute, to answer questions that share all
// of their work. One scan answers both.
func (s *Store) CoverageOf(origin string, from, to int64) (Coverage, error) {
	var cov Coverage
	verified := make(map[int64]bool)
	err := s.db.View(func(tx *bolt.Tx) error {
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
			cov.Settled++
			if a.Verified {
				cov.Verified++
				verified[a.Epoch] = true
			} else {
				cov.Holes++
			}
		}
		return nil
	})
	if err != nil {
		return cov, fmt.Errorf("store: coverage for %s: %w", origin, err)
	}
	cov.From, cov.To, cov.Run = longestRun(verified)
	return cov, nil
}

// longestRun finds the longest consecutive span in a set of epochs.
func longestRun(verified map[int64]bool) (lo, hi, run int64) {
	for epoch := range verified {
		if verified[epoch-1] {
			continue // not the start of a run
		}
		end := epoch
		for verified[end+1] {
			end++
		}
		if n := end - epoch + 1; n > run {
			run, lo, hi = n, epoch, end
		}
	}
	return lo, hi, run
}

// VerifiedRegion returns the largest unbroken run of verified epochs in range,
// and how many epochs in that range are settled but unverified.
//
// The contiguous region is the honest form of the coverage claim. A count of
// audited epochs says how much work was done; it says nothing about whether the
// result is a solid range or a sieve, and only a solid range supports "this
// log's history is construction audited". Two logs with identical audited
// counts can differ entirely in what they actually establish.
// The run length is returned explicitly rather than left to the caller to
// compute from lo and hi. Deriving it invites a guard like `lo > 0` to mean "no
// run found", which is wrong for any log whose history starts at epoch 0 —
// thelemail.com/keys does, and reported a verified run of zero across a fully
// audited log because of exactly that.
func (s *Store) VerifiedRegion(origin string, from, to int64) (lo, hi, run, holes int64, err error) {
	verified := make(map[int64]bool)
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
			if a.Verified {
				verified[a.Epoch] = true
			} else {
				holes++
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("store: verified region for %s: %w", origin, err)
	}

	// Longest run of consecutive verified epochs. Walked over the keys we hold
	// rather than the whole range, so an unswept log costs nothing here.
	var bestLo, bestHi, bestLen int64
	for epoch := range verified {
		if verified[epoch-1] {
			continue // not the start of a run
		}
		end := epoch
		for verified[end+1] {
			end++
		}
		if n := end - epoch + 1; n > bestLen {
			bestLen, bestLo, bestHi = n, epoch, end
		}
	}
	return bestLo, bestHi, bestLen, holes, nil
}

// FirstUnverified returns the lowest epoch in [from, to] that this witness has
// not recorded as verified, and whether there is one.
//
// It exists because the work feed was guessing. Probing one epoch per
// twenty-five and treating a hit as "that whole chunk is done" is cheap and
// wrong in the case that actually occurs: a range is handed out as two
// interleaved assignments, so when one half succeeds and the other fails, some
// epochs in the chunk are verified and some are not. Whichever epochs the probe
// happened to look at decided the fate of the other twenty-three, and the ones
// it skipped were never offered again. That left 7,880 unverified WhatsApp
// epochs behind a work queue reporting nothing to do.
//
// One read transaction and a cursor, not one transaction per epoch. Audit keys
// are "origin|%020d", so they sort numerically within an origin and the whole
// range is a single ordered walk — the same scan the old version did per chunk,
// done once and exactly. A missing key counts as unverified, which is the
// point: an epoch nobody has recorded a decision about is precisely the work.
func (s *Store) FirstUnverified(origin string, from, to int64) (int64, bool, error) {
	if from > to {
		return 0, false, nil
	}
	var (
		found bool
		at    int64
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudits).Cursor()
		prefix := []byte(origin + "|")
		want := from
		k, v := c.Seek(auditKey(origin, from))
		for ; k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var a Audit
			if err := json.Unmarshal(v, &a); err != nil {
				continue
			}
			if a.Epoch > to {
				break
			}
			if a.Epoch > want {
				// A gap: nothing recorded for `want`, so that is the answer.
				at, found = want, true
				return nil
			}
			if a.Epoch == want {
				if !a.Verified {
					at, found = want, true
					return nil
				}
				want++
			}
		}
		if want <= to {
			at, found = want, true
		}
		return nil
	})
	return at, found, err
}
