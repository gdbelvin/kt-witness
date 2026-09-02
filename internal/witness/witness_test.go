package witness

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// stubSource lets us drive the core's gates directly, without needing a real
// log to misbehave on demand.
type stubSource struct {
	origin  string
	head    *source.Head
	derived bool
	// consistencyErr is what VerifyConsistency returns; nil means "proven".
	consistencyErr error
	verifyCalled   bool
	// fetchErr, when set, is returned by Fetch instead of a head.
	fetchErr error
}

func (s *stubSource) Origin() string    { return s.origin }
func (s *stubSource) Tier() source.Tier { return source.TierA }
func (s *stubSource) DerivedHead() bool { return s.derived }
func (s *stubSource) Fetch(context.Context, *source.Head) (*source.Head, error) {
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	return s.head, nil
}
func (s *stubSource) VerifyConsistency(_ context.Context, _, _ *source.Head) error {
	s.verifyCalled = true
	return s.consistencyErr
}

func newTestWitness(t *testing.T) (*Witness, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := torchwood.NewCosignatureSigner("witness.test", priv)
	if err != nil {
		t.Fatal(err)
	}
	return &Witness{
		Signer: signer,
		Store:  db,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, db
}

func hashOf(b byte) tlog.Hash {
	var h tlog.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// head builds a signed note for the given tree so the core has something real
// to cosign.
func head(t *testing.T, origin string, size int64, h tlog.Hash) *source.Head {
	t.Helper()
	cp := torchwood.Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: h}}
	text := cp.String()
	return &source.Head{
		Origin:    origin,
		Size:      size,
		Hash:      h,
		Signed:    []byte(text),
		Note:      &note.Note{Text: text},
		FetchedAt: time.Now(),
	}
}

func TestCosignsFirstObservation(t *testing.T) {
	w, db := newTestWitness(t)
	src := &stubSource{origin: "example.com/log", head: head(t, "example.com/log", 10, hashOf(1))}

	out, err := w.Process(context.Background(), src)
	if err != nil {
		t.Fatalf("first observation should be cosigned: %v", err)
	}
	if !out.Cosigned {
		t.Fatal("expected Cosigned")
	}
	rec, _ := db.Get("example.com/log")
	if rec == nil || rec.Size != 10 {
		t.Fatalf("head not persisted: %+v", rec)
	}
}

// A log that serves a different root at a size we already witnessed is
// equivocating. This needs no proof to be conclusive, and must be permanent.
func TestSplitViewAtSameSizeIsFork(t *testing.T) {
	w, db := newTestWitness(t)
	origin := "example.com/log"

	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}
	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	// Same size, different root.
	src.verifyCalled = false // the first-use round legitimately called it
	src.head = head(t, origin, 10, hashOf(2))
	_, err := w.Process(context.Background(), src)

	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError, got %v", err)
	}
	if src.verifyCalled {
		t.Error("consistency proof should not be requested once equivocation is already conclusive")
	}

	forks, _ := db.Forks()
	if len(forks) != 1 {
		t.Fatalf("want 1 persisted fork as evidence, got %d", len(forks))
	}
	if len(forks[0].PrevSigned) == 0 || len(forks[0].NextSigned) == 0 {
		t.Error("both conflicting views must be retained so disclosure is reproducible")
	}

	// The attack this guards against: equivocate briefly, then revert to a
	// consistent view and hope the witness resumes cosigning.
	src.head = head(t, origin, 11, hashOf(1))
	if _, err := w.Process(context.Background(), src); !errors.As(err, &fe) {
		t.Fatal("a forked log must stay refused even once it serves a consistent view again")
	}
	if forks, _ = db.Forks(); len(forks) != 1 {
		t.Fatalf("evidence must be recorded once, not re-appended every round; got %d", len(forks))
	}
}

// A shrinking tree is a rollback: entries shown to users have been removed.
func TestSizeRegressionIsFork(t *testing.T) {
	w, _ := newTestWitness(t)
	origin := "example.com/log"

	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}
	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	src.head = head(t, origin, 9, hashOf(3))
	var fe *source.ForkError
	if _, err := w.Process(context.Background(), src); !errors.As(err, &fe) {
		t.Fatalf("want ForkError for rollback, got %v", err)
	}
}

// An unchanged log is not re-cosigned and, critically, is not an error.
func TestUnchangedIsNotAnError(t *testing.T) {
	w, _ := newTestWitness(t)
	origin := "example.com/log"
	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}

	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	out, err := w.Process(context.Background(), src)
	if err != nil {
		t.Fatalf("unchanged log should not error: %v", err)
	}
	if !out.Unchanged || out.Cosigned {
		t.Fatalf("want Unchanged and not Cosigned, got %+v", out)
	}
}

// A quiet log is re-cosigned once the refresh interval elapses, so our
// published timestamp stays a liveness signal rather than ageing indefinitely.
func TestUnchangedLogIsRefreshedAfterInterval(t *testing.T) {
	w, db := newTestWitness(t)
	w.RefreshInterval = time.Hour
	origin := "example.com/log"
	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}

	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	first, _ := db.Get(origin)

	// Not yet due: no new cosignature.
	out, err := w.Process(context.Background(), src)
	if err != nil || !out.Unchanged {
		t.Fatalf("want Unchanged before the interval elapses, got %+v (%v)", out, err)
	}

	// Backdate our stored view so the refresh is due.
	stale := *first
	stale.WitnessedAt = time.Now().Add(-2 * time.Hour)
	if err := db.CompareAndSet(first, &stale); err != nil {
		t.Fatal(err)
	}

	src.verifyCalled = false
	out, err = w.Process(context.Background(), src)
	if err != nil {
		t.Fatalf("refresh should succeed: %v", err)
	}
	if !out.Cosigned || !out.Refreshed {
		t.Fatalf("want a refreshed cosignature, got %+v", out)
	}
	if src.verifyCalled {
		t.Error("a refresh re-signs an already-proven tree; no consistency proof should be fetched")
	}

	got, _ := db.Get(origin)
	if !got.WitnessedAt.After(stale.WitnessedAt) {
		t.Error("refresh must advance the witnessed-at timestamp")
	}
	if got.Size != 10 || got.Hash != hashOf(1) {
		t.Error("refresh must not alter the attested tree")
	}
}

// Failing to obtain a proof is NOT evidence of a fork, but must still withhold.
func TestUnprovenConsistencyWithholdsWithoutRecordingFork(t *testing.T) {
	w, db := newTestWitness(t)
	origin := "example.com/log"

	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}
	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	src.head = head(t, origin, 20, hashOf(4))
	src.consistencyErr = errors.New("tile fetch failed")

	_, err := w.Process(context.Background(), src)
	if err == nil {
		t.Fatal("must withhold when consistency is unproven")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("a transient proof failure must not be recorded as a fork")
	}
	if forks, _ := db.Forks(); len(forks) != 0 {
		t.Fatalf("no fork evidence should be recorded, got %d", len(forks))
	}
	// And our stored view must be unchanged.
	rec, _ := db.Get(origin)
	if rec.Size != 10 {
		t.Fatalf("stored head must not advance on a withheld round, got %d", rec.Size)
	}
}

// A source must not be able to authenticate a head for a different origin.
func TestOriginMismatchRejected(t *testing.T) {
	w, _ := newTestWitness(t)
	src := &stubSource{origin: "example.com/log", head: head(t, "evil.com/log", 10, hashOf(1))}
	if _, err := w.Process(context.Background(), src); err == nil {
		t.Fatal("must reject a head whose origin differs from the configured log")
	}
}

// A stale view must not be signed: the cosignature carries a timestamp that
// would assert freshness we did not observe.
func TestStaleViewWithheld(t *testing.T) {
	w, _ := newTestWitness(t)
	w.MaxSignDelay = time.Millisecond

	h := head(t, "example.com/log", 10, hashOf(1))
	h.FetchedAt = time.Now().Add(-time.Hour)
	src := &stubSource{origin: "example.com/log", head: h}

	if _, err := w.Process(context.Background(), src); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}
}

// A source whose head is derived from observation rather than carried by a
// signature must never trigger a fork on regression: a transient bad read looks
// identical to a rollback, and the accusation is permanent and public.
func TestDerivedHeadRegressionWithholdsWithoutAccusing(t *testing.T) {
	w, db := newTestWitness(t)
	origin := "example.com/log"
	src := &stubSource{origin: origin, derived: true, head: head(t, origin, 10, hashOf(1))}

	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		head *source.Head
	}{
		{"regression", head(t, origin, 5, hashOf(2))},
		{"same size, different root", head(t, origin, 10, hashOf(9))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src.head = tc.head
			_, err := w.Process(context.Background(), src)
			if err == nil {
				t.Fatal("must withhold")
			}
			var fe *source.ForkError
			if errors.As(err, &fe) {
				t.Fatal("a derived head must not produce a permanent fork accusation")
			}
			if forks, _ := db.Forks(); len(forks) != 0 {
				t.Fatalf("no fork evidence should be recorded, got %d", len(forks))
			}
		})
	}
}

// A Source can reach a conclusive contradiction while fetching — Signal's
// auditors disagreeing on the derived service root, for instance. That evidence
// must be recorded and the log poisoned, exactly as for the other gates.
func TestForkRaisedDuringFetchIsRecorded(t *testing.T) {
	w, db := newTestWitness(t)
	origin := "example.com/log"

	src := &stubSource{origin: origin, head: head(t, origin, 10, hashOf(1))}
	if _, err := w.Process(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	src.fetchErr = &source.ForkError{
		Origin: origin,
		Reason: "auditors disagree on the derived root",
		Next:   &source.Head{Origin: origin, Size: 11, Signed: []byte("raw evidence")},
	}

	_, err := w.Process(context.Background(), src)
	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError, got %v", err)
	}

	forks, _ := db.Forks()
	if len(forks) != 1 {
		t.Fatalf("a fork raised during Fetch must be persisted, got %d records", len(forks))
	}
	if string(forks[0].NextSigned) != "raw evidence" {
		t.Errorf("verbatim evidence must be retained, got %q", forks[0].NextSigned)
	}
	if forked, _ := db.IsForked(origin); !forked {
		t.Fatal("the log must be poisoned")
	}

	// And it must stay refused even if the source starts behaving.
	src.fetchErr = nil
	if _, err := w.Process(context.Background(), src); !errors.As(err, &fe) {
		t.Fatal("a poisoned log must stay refused")
	}
}
