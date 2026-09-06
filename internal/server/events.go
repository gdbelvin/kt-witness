package server

import (
	"fmt"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A readable record of what the witness has been saying.
//
// # Why this exists
//
// Every diagnosis in this project has ended at `docker compose logs | grep`,
// which means every diagnosis has needed a shell on the host. That is a bad
// dependency for something whose whole product is published evidence: when the
// SSH agent locked four times in one session, four investigations stopped dead
// while the witness carried on knowing the answer and having no way to say it.
//
// So the interesting log lines are kept in memory and served. Not a replacement
// for the container log — that remains the complete record — but the last few
// hundred WARN and ERROR lines are what a question is almost always about, and
// they should not require credentials to a machine.
//
// # Why only WARN and above, and why a ring
//
// INFO is the bulk of the volume and almost never the thing being looked for;
// keeping it would trade a useful buffer for a large one. The ring is bounded
// because an unbounded in-memory log is a slow leak that eventually becomes an
// OOM, and this process already runs close to its memory limit.
//
// Counts are kept separately from the ring and are NOT bounded, so "how many
// times has this happened" survives eviction. A ring alone would answer "what
// happened recently" while quietly losing "this has happened four thousand
// times", which is usually the more important half.

const eventRingSize = 500

type event struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// EventLog keeps recent notable log records and a running tally by message.
type EventLog struct {
	mu    sync.Mutex
	ring  []event
	next  int
	full  bool
	count map[string]int
	first map[string]time.Time
	last  map[string]time.Time
}

func NewEventLog() *EventLog {
	return &EventLog{
		ring:  make([]event, eventRingSize),
		count: map[string]int{},
		first: map[string]time.Time{},
		last:  map[string]time.Time{},
	}
}

func (e *EventLog) add(ev event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ring[e.next] = ev
	e.next = (e.next + 1) % len(e.ring)
	if e.next == 0 {
		e.full = true
	}
	key := ev.Level + " " + ev.Message
	e.count[key]++
	if _, ok := e.first[key]; !ok {
		e.first[key] = ev.Time
	}
	e.last[key] = ev.Time
}

// Recent returns the buffered events, newest first.
func (e *EventLog) Recent(limit int) []event {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := len(e.ring)
	if !e.full {
		n = e.next
	}
	out := make([]event, 0, n)
	for i := 0; i < n; i++ {
		idx := (e.next - 1 - i + len(e.ring)*2) % len(e.ring)
		if e.ring[idx].Time.IsZero() {
			continue
		}
		out = append(out, e.ring[idx])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

type tally struct {
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Count   int       `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// Tallies returns how often each distinct message has been seen, most frequent
// first. Unbounded by design: the ring forgets, this does not.
func (e *EventLog) Tallies() []tally {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]tally, 0, len(e.count))
	for k, n := range e.count {
		lvl, msg, _ := strings.Cut(k, " ")
		out = append(out, tally{Level: lvl, Message: msg, Count: n,
			First: e.first[k], Last: e.last[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// Handler is a slog.Handler that records notable events and passes everything
// through to the real handler underneath.
type eventHandler struct {
	slog.Handler
	log   *EventLog
	attrs []slog.Attr
}

// NewEventHandler wraps h so that WARN and above are also kept in memory.
func NewEventHandler(h slog.Handler, log *EventLog) slog.Handler {
	return &eventHandler{Handler: h, log: log}
}

func (h *eventHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		ev := event{Time: r.Time, Level: r.Level.String(), Message: r.Message,
			Attrs: map[string]any{}}
		for _, a := range h.attrs {
			ev.Attrs[a.Key] = renderable(a.Value.Any())
		}
		r.Attrs(func(a slog.Attr) bool {
			ev.Attrs[a.Key] = renderable(a.Value.Any())
			return true
		})
		h.log.add(ev)
	}
	return h.Handler.Handle(ctx, r)
}

func (h *eventHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &eventHandler{Handler: h.Handler.WithAttrs(as), log: h.log,
		attrs: append(append([]slog.Attr{}, h.attrs...), as...)}
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	return &eventHandler{Handler: h.Handler.WithGroup(name), log: h.log, attrs: h.attrs}
}

// events serves the recent notable log records.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if s.Events == nil {
		http.Error(w, "event log not enabled", http.StatusNotFound)
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= eventRingSize {
			limit = n
		}
	}
	body := struct {
		Recent   []event `json:"recent"`
		Tallies  []tally `json:"tallies"`
		RingSize int     `json:"ring_size"`
		Note     string  `json:"note"`
	}{
		Recent:   s.Events.Recent(limit),
		Tallies:  s.Events.Tallies(),
		RingSize: eventRingSize,
		Note: "WARN and above only, newest first. `tallies` counts every occurrence " +
			"since start and is not evicted, so a message missing from `recent` may " +
			"still have happened many times.",
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// renderable converts a value into something that survives JSON encoding.
//
// An error is the case that matters. Most error types are structs with no
// exported fields, so encoding/json renders them as `{}` — which is how
// /events came to report every withheld cosignature with an empty `err`,
// dropping the single field that says WHY it was withheld. The message is the
// whole content of an error; keep it as a string.
func renderable(v any) any {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return v
}
