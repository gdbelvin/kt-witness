package akd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/tlog"
)

// fakeStore serves S3-style listings for a synthetic epoch chain, so we can
// induce misbehaviour Meta will not perform on demand.
type fakeStore struct {
	// links maps epoch -> (prevHex, currHex).
	links map[int64][2]string
}

func (f *fakeStore) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Query().Get("prefix")
		if prefix == "" {
			// Bulk listing, as used by Backfill. One page is enough for tests.
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0"?><ListBucketResult>`)
			epochs := make([]int64, 0, len(f.links))
			for e := range f.links {
				epochs = append(epochs, e)
			}
			slices.Sort(epochs)
			for _, e := range epochs {
				l := f.links[e]
				fmt.Fprintf(w, `<Contents><Key>%d/%s/%s</Key></Contents>`, e, l[0], l[1])
			}
			fmt.Fprint(w, `<IsTruncated>false</IsTruncated></ListBucketResult>`)
			return
		}
		epoch, err := strconv.ParseInt(strings.TrimSuffix(prefix, "/"), 10, 64)
		if err != nil {
			http.Error(w, "bad prefix", http.StatusBadRequest)
			return
		}
		l, ok := f.links[epoch]
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0"?><ListBucketResult>`)
		if ok {
			fmt.Fprintf(w, `<Contents><Key>%d/%s/%s</Key></Contents>`, epoch, l[0], l[1])
		}
		fmt.Fprint(w, `<IsTruncated>false</IsTruncated></ListBucketResult>`)
	})
}

func h(b byte) string {
	var raw [32]byte
	for i := range raw {
		raw[i] = b
	}
	return hex.EncodeToString(raw[:])
}

func hash(t *testing.T, s string) tlog.Hash {
	t.Helper()
	out, err := parseHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// chain builds epochs [start, end] where epoch n links root n-1 -> n.
func chain(start, end int64) map[int64][2]string {
	m := map[int64][2]string{}
	for e := start; e <= end; e++ {
		m[e] = [2]string{h(byte(e - 1)), h(byte(e))}
	}
	return m
}

func newTestSource(t *testing.T, links map[int64][2]string) *Source {
	t.Helper()
	srv := httptest.NewServer((&fakeStore{links: links}).handler())
	t.Cleanup(srv.Close)
	s, err := New(Config{Origin: "test.kt/v1", LogDirectory: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func head(t *testing.T, epoch int64, rootHex string) *source.Head {
	t.Helper()
	return &source.Head{Origin: "test.kt/v1", Size: epoch, Hash: hash(t, rootHex)}
}

func TestChainWalkAcceptsContinuousHistory(t *testing.T) {
	s := newTestSource(t, chain(1, 10))
	err := s.VerifyConsistency(context.Background(),
		head(t, 3, h(3)), head(t, 8, h(8)))
	if err != nil {
		t.Fatalf("continuous chain should verify: %v", err)
	}
}

// The core property: an epoch whose declared previous root does not match the
// preceding epoch's published current root means two incompatible histories.
func TestBrokenLinkIsFork(t *testing.T) {
	links := chain(1, 10)
	links[6] = [2]string{h(99), h(6)} // epoch 6 no longer follows epoch 5
	s := newTestSource(t, links)

	err := s.VerifyConsistency(context.Background(),
		head(t, 3, h(3)), head(t, 8, h(8)))

	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError for broken chain link, got %v", err)
	}
	if !strings.Contains(fe.Reason, "epoch 6") {
		t.Errorf("fork reason should identify the epoch, got %q", fe.Reason)
	}
}

// A missing epoch must NOT be treated as a fork. Absence is the one observation
// we cannot trust: CDN edges serve stale negative listings (observed in
// production), and writes can land out of order. Accusing a log of forking is
// permanent and public, so it must never rest on absence alone.
func TestGapInHistoryWithholdsButIsNotAFork(t *testing.T) {
	links := chain(1, 10)
	delete(links, 6)
	s := newTestSource(t, links)

	err := s.VerifyConsistency(context.Background(),
		head(t, 3, h(3)), head(t, 8, h(8)))
	if err == nil {
		t.Fatal("a hole in history must withhold the cosignature")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("absence must not be recorded as a fork: a stale CDN negative would permanently and wrongly brand the log")
	}
}

// Walking the chain must actually arrive at the root the tip claims.
func TestTipDisagreeingWithChainIsFork(t *testing.T) {
	s := newTestSource(t, chain(1, 10))
	err := s.VerifyConsistency(context.Background(),
		head(t, 3, h(3)), head(t, 8, h(200))) // claims a root the chain doesn't reach

	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError when the tip disagrees with the walk, got %v", err)
	}
}

// Falling far behind is a workload problem, not misbehaviour.
func TestExcessiveGapIsNotAFork(t *testing.T) {
	s := newTestSource(t, chain(1, 10))
	s.cfg.MaxEpochsPerRound = 2

	err := s.VerifyConsistency(context.Background(), head(t, 1, h(1)), head(t, 9, h(9)))
	if err == nil {
		t.Fatal("should withhold when too far behind")
	}
	var fe *source.ForkError
	if errors.As(err, &fe) {
		t.Fatal("being behind must not be recorded as a fork")
	}
}

func TestFindTipLocatesHighestEpoch(t *testing.T) {
	s := newTestSource(t, chain(1, 777))

	for _, hint := range []int64{1, 100, 777, 5000} {
		l, err := s.findTip(context.Background(), hint)
		if err != nil {
			t.Fatalf("hint %d: %v", hint, err)
		}
		if l.epoch != 777 {
			t.Errorf("hint %d: want tip 777, got %d", hint, l.epoch)
		}
	}
}

func TestFirstObservationPinsWithoutHistory(t *testing.T) {
	s := newTestSource(t, chain(1, 10))
	if err := s.VerifyConsistency(context.Background(), nil, head(t, 8, h(8))); err != nil {
		t.Fatalf("first observation should pin, got %v", err)
	}
}

// Catch-up after downtime must converge. Reporting the true tip when it is
// thousands of epochs ahead would make every round attempt a walk too long to
// finish before the head goes stale — and, failing, never advance the stored
// head, so the next round faces the same walk against a larger gap. Fetch
// therefore steps forward at most MaxEpochsPerRound at a time.
func TestFetchStepsForwardWhenFarBehind(t *testing.T) {
	s := newTestSource(t, chain(1, 1000))
	s.cfg.MaxEpochsPerRound = 10

	prev := head(t, 100, h(100))
	got, err := s.Fetch(context.Background(), prev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 110 {
		t.Fatalf("want an intermediate head at 110, got %d", got.Size)
	}
	// And the step must be provable, or stepping bought us nothing.
	if err := s.VerifyConsistency(context.Background(), prev, got); err != nil {
		t.Fatalf("the intermediate step must verify: %v", err)
	}

	// Successive rounds converge on the tip rather than repeating.
	for range 200 {
		if prev.Size == 1000 {
			break
		}
		if prev, err = s.Fetch(context.Background(), prev); err != nil {
			t.Fatal(err)
		}
	}
	if prev.Size != 1000 {
		t.Fatalf("catch-up failed to converge: stalled at %d", prev.Size)
	}
}

// When already current, Fetch reports the tip itself.
func TestFetchReportsTipWhenClose(t *testing.T) {
	s := newTestSource(t, chain(1, 50))
	got, err := s.Fetch(context.Background(), head(t, 48, h(48)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 50 {
		t.Fatalf("want tip 50, got %d", got.Size)
	}
}

// Backfill exists because trust-on-first-use leaves the whole past unattested.
// It must verify a continuous chain across everything published.
func TestBackfillVerifiesWholeHistory(t *testing.T) {
	s := newTestSource(t, chain(1, 500))

	res, err := s.Backfill(context.Background(), nil)
	if err != nil {
		t.Fatalf("a continuous history should verify: %v", err)
	}
	if res.From != 1 || res.To != 500 || res.Epochs != 500 {
		t.Fatalf("want 1..500 over 500 epochs, got %d..%d over %d", res.From, res.To, res.Epochs)
	}
	if len(res.Gaps) != 0 {
		t.Fatalf("unexpected gaps: %v", res.Gaps)
	}
}

// A break between two epochs that both exist cannot be absence or a stale read:
// their names disagree, which is conclusive.
func TestBackfillBrokenLinkIsFork(t *testing.T) {
	links := chain(1, 100)
	links[60] = [2]string{h(200), h(60)} // no longer follows epoch 59
	s := newTestSource(t, links)

	_, err := s.Backfill(context.Background(), nil)
	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForkError, got %v", err)
	}
	if !strings.Contains(fe.Reason, "epoch 60") {
		t.Errorf("reason should name the epoch, got %q", fe.Reason)
	}
}

// A hole is recorded, not accused: retention limits and partial writes both
// produce one, and linkage simply cannot be checked across it.
func TestBackfillGapIsRecordedNotAccused(t *testing.T) {
	links := chain(1, 100)
	for e := int64(40); e <= 45; e++ {
		delete(links, e)
	}
	s := newTestSource(t, links)

	res, err := s.Backfill(context.Background(), nil)
	if err != nil {
		t.Fatalf("a gap must not fail the backfill: %v", err)
	}
	if len(res.Gaps) != 1 || !strings.Contains(res.Gaps[0], "40..45") {
		t.Fatalf("want the gap recorded, got %v", res.Gaps)
	}
	if res.Epochs != 94 {
		t.Fatalf("want 94 epochs examined, got %d", res.Epochs)
	}
}
