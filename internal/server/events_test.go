package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// The event log has to actually capture warnings, or it becomes another thing
// that looks fine and reports nothing — which is the failure it was built to
// stop, and which this project has now reintroduced twice while refactoring.
func TestEventLogCapturesWarningsAndCounts(t *testing.T) {
	el := NewEventLog()
	log := slog.New(NewEventHandler(slog.NewTextHandler(io.Discard, nil), el))

	log.Info("routine thing", "n", 1)
	log.Warn("epoch could not be checked", "origin", "meta.test/v1", "epoch", 42)
	log.Warn("epoch could not be checked", "origin", "meta.test/v1", "epoch", 43)
	log.Error("construction audit failed", "origin", "meta.test/v1")

	recent := el.Recent(0)
	if len(recent) != 3 {
		t.Fatalf("captured %d events, want 3 (INFO must not be kept, WARN and "+
			"ERROR must be)", len(recent))
	}
	// Newest first, so a reader sees what just happened without paging.
	if recent[0].Message != "construction audit failed" {
		t.Errorf("newest event is %q; the ring must read newest-first",
			recent[0].Message)
	}
	// Attributes are the diagnosis. An event without them says something
	// happened and not which epoch, which is not worth keeping.
	if got := recent[1].Attrs["epoch"]; got == nil {
		t.Error("attributes dropped; the epoch is the whole point of the record")
	}

	tallies := el.Tallies()
	var found bool
	for _, tl := range tallies {
		if tl.Message == "epoch could not be checked" {
			found = true
			if tl.Count != 2 {
				t.Errorf("tally %d for a message seen twice", tl.Count)
			}
		}
	}
	if !found {
		t.Error("no tally for a repeated message")
	}
}

// Eviction must not lose the counts. "What happened recently" and "how many
// times has this happened" are different questions, and the second one is
// usually the more important half.
func TestTalliesSurviveRingEviction(t *testing.T) {
	el := NewEventLog()
	log := slog.New(NewEventHandler(slog.NewTextHandler(io.Discard, nil), el))

	for i := 0; i < eventRingSize+50; i++ {
		log.Warn("recurring problem", "i", i)
	}
	if n := len(el.Recent(0)); n > eventRingSize {
		t.Fatalf("ring held %d events, above its %d bound; an unbounded log is "+
			"a slow leak in a process already near its memory limit", n, eventRingSize)
	}
	for _, tl := range el.Tallies() {
		if tl.Message == "recurring problem" && tl.Count != eventRingSize+50 {
			t.Errorf("tally %d after eviction, want %d — counts must outlive the ring",
				tl.Count, eventRingSize+50)
		}
	}
}

// WithAttrs is how sub-loggers are built (log.With("origin", ...)), and those
// attributes must reach the record or grouped loggers lose their identity.
func TestEventLogKeepsHandlerAttrs(t *testing.T) {
	el := NewEventLog()
	base := slog.New(NewEventHandler(slog.NewTextHandler(io.Discard, nil), el))
	sub := base.With("replay", "history")
	sub.WarnContext(context.Background(), "stalled")

	r := el.Recent(0)
	if len(r) != 1 {
		t.Fatalf("got %d events", len(r))
	}
	if r[0].Attrs["replay"] != "history" {
		t.Errorf("attrs from With() lost: %v", r[0].Attrs)
	}
	if time.Since(r[0].Time) > time.Minute {
		t.Error("event timestamp not set")
	}
}
