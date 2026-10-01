package loglist

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

// FromConfig is the push.Log.From value of a statically configured log.
const FromConfig = "config"

// Registry is the set of logs allowed to push to this witness: the ones the
// operator configured, plus the ones discovered from lists.
//
// Configured logs always win. The operator wrote that key down deliberately; a
// list is a third party's suggestion, and letting it shadow the operator's
// choice would be exactly the "update an already configured log" the network
// forbids.
//
// Discovered logs are add-only here as well as in the store: once an origin is
// present, nothing replaces it for the life of the process.
type Registry struct {
	// static is fixed at construction and never written again, so it needs
	// no lock.
	static map[string]*push.Log

	mu         sync.RWMutex
	discovered map[string]*push.Log

	// mentions records which lists name an origin, in the order they were
	// first seen doing so. It is an index for display only — /graph uses it to
	// say "this log is also on list X" — and never a source of keys: an origin
	// listed after it was configured or discovered is still verified under the
	// key it was first known by. Like everything else here it only grows.
	mentions map[string][]string
}

var _ push.Registry = (*Registry)(nil)

// NewRegistry returns a registry holding the configured logs. A log with an
// empty From is marked FromConfig.
func NewRegistry(static []*push.Log) *Registry {
	r := &Registry{
		static:     make(map[string]*push.Log, len(static)),
		discovered: make(map[string]*push.Log),
		mentions:   make(map[string][]string),
	}
	for _, l := range static {
		if l.From == "" {
			c := *l
			c.From = FromConfig
			l = &c
		}
		r.static[l.Origin] = l
	}
	return r
}

// Lookup implements push.Registry.
func (r *Registry) Lookup(origin string) (*push.Log, bool) {
	if l, ok := r.static[origin]; ok {
		return l, true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.discovered[origin]
	return l, ok
}

// IsStatic reports whether origin is statically configured.
func (r *Registry) IsStatic(origin string) bool {
	_, ok := r.static[origin]
	return ok
}

// Load adds every log the store has previously discovered, so a restart does
// not forget them until the next fetch — and, more importantly, so the key a
// log was first discovered with is the one in force, not whatever the list
// says today.
//
// A stored log whose key no longer builds a verifier is skipped and reported;
// the rest still load. Calling Load again is harmless: present origins are
// left alone.
func (r *Registry) Load(db *store.Store) error {
	logs, err := db.PushLogs()
	if err != nil {
		return err
	}
	var errs []error
	for _, pl := range logs {
		l, err := pushLog(pl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		r.add(l)
		r.mention(pl.Origin, pl.List)
	}
	return errors.Join(errs...)
}

// mention records that list names origin. Idempotent.
func (r *Registry) mention(origin, list string) {
	if origin == "" || list == "" || list == FromConfig {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.mentions[origin] {
		if l == list {
			return
		}
	}
	r.mentions[origin] = append(r.mentions[origin], list)
}

// ListsFor returns the URLs of the lists known to name origin, in the order
// they were first seen doing so; nil if none. For a statically configured log
// this is only known once a list naming it has been fetched in this process.
func (r *Registry) ListsFor(origin string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ls := r.mentions[origin]
	if len(ls) == 0 {
		return nil
	}
	return append([]string(nil), ls...)
}

// add inserts a discovered log unless its origin is already known, statically
// or otherwise, and reports whether it did.
func (r *Registry) add(l *push.Log) bool {
	if r.IsStatic(l.Origin) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.discovered[l.Origin]; ok {
		return false
	}
	r.discovered[l.Origin] = l
	return true
}

// Logs returns every log that may push, configured and discovered, ordered by
// origin. A discovered log shadowed by a configured one is not included.
func (r *Registry) Logs() []*push.Log {
	out := make([]*push.Log, 0, len(r.static))
	for _, l := range r.static {
		out = append(out, l)
	}
	r.mu.RLock()
	for o, l := range r.discovered {
		if _, ok := r.static[o]; !ok {
			out = append(out, l)
		}
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}

// Origins returns the origins of Logs, in the same order.
func (r *Registry) Origins() []string {
	logs := r.Logs()
	out := make([]string, len(logs))
	for i, l := range logs {
		out[i] = l.Origin
	}
	return out
}

// pushLog turns a stored discovery into a push.Log with a live verifier.
func pushLog(pl *store.PushLog) (*push.Log, error) {
	v, err := note.NewVerifier(pl.VKey)
	if err != nil {
		return nil, fmt.Errorf("loglist: stored log %s: %w", pl.Origin, err)
	}
	return &push.Log{
		Origin:   pl.Origin,
		VKey:     pl.VKey,
		Verifier: v,
		QPD:      pl.QPD,
		Contact:  pl.Contact,
		From:     pl.List,
	}, nil
}
