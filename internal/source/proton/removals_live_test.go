package proton

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
)

// Live: judge a published epoch's removals against that epoch's own retention
// window, using Proton's real diff.
//
// The diff alone is used here rather than a merged tree, because the tree dump
// is ~13.6 GB and out of reach of a test. That costs one thing and only one: the
// values are the diff's copies rather than the tree's, so the check that the two
// agree (DiffStats.ValueMismatches) cannot be exercised live. The dating rule
// itself is exactly the one kt-proton-audit applies.
func TestLiveJudgeRemovals(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	ctx := context.Background()
	s, err := New(Config{Origin: "proton.me/kt/v1"})
	if err != nil {
		t.Fatal(err)
	}

	var resp struct {
		Epochs []epoch `json:"Epochs"`
	}
	if err := s.get(ctx, "/kt/v1/epochs", &resp); err != nil {
		t.Fatal(err)
	}
	tip := resp.Epochs[0]
	for _, c := range resp.Epochs {
		if c.EpochID > tip.EpochID {
			tip = c
		}
	}
	if tip.StartEpochID <= 0 {
		t.Fatalf("epoch %d publishes no StartEpochID; the window rule has nothing to judge against", tip.EpochID)
	}

	// The tip's diff is uploaded a little after the epoch is published, so a 404
	// here means "not yet", not "missing". Falling back one epoch keeps the test
	// about the judgement rather than about upload timing.
	judged := tip
	diff, err := fetchDiff(ctx, judged.EpochID)
	if err != nil {
		t.Logf("tip diff not available yet (%v); judging epoch %d instead", err, tip.EpochID-1)
		prev, perr := s.epochAt(ctx, tip.EpochID-1)
		if perr != nil {
			t.Fatal(perr)
		}
		judged = *prev
		if diff, err = fetchDiff(ctx, judged.EpochID); err != nil {
			t.Fatal(err)
		}
	}
	if judged.StartEpochID <= 0 {
		t.Fatalf("epoch %d publishes no StartEpochID", judged.EpochID)
	}
	if len(diff)%diffEntrySize != 0 {
		t.Fatalf("diff is %d bytes, not a whole number of %d-byte records", len(diff), diffEntrySize)
	}

	stats := &DiffStats{}
	for i := 0; i+diffEntrySize <= len(diff); i += diffEntrySize {
		label := diff[i+1 : i+1+labelSize]
		value := diff[i+1+labelSize : i+diffEntrySize]
		switch diff[i] {
		case OpAdd:
			stats.Added++
			// The canary for the whole dating premise: an addition's minEpochID
			// is the epoch making it. If that ever stops holding, the field is
			// not what we believe it is and no removal may be judged by it.
			min, err := MinEpochID(value)
			if err != nil {
				t.Fatal(err)
			}
			if min != judged.EpochID {
				t.Fatalf("an entry added in epoch %d carries minEpochID %d; the value layout has changed",
					judged.EpochID, min)
			}
		case OpRemove:
			stats.Removed++
			stats.Removals = append(stats.Removals, Removal{
				Label: append([]byte(nil), label...),
				Value: append([]byte(nil), value...),
			})
		default:
			t.Fatalf("unknown diff operation %d", diff[i])
		}
	}

	rep := JudgeRemovals(stats, judged.EpochID, judged.StartEpochID)
	t.Logf("%d added, %d removed", stats.Added, stats.Removed)
	t.Logf("%s", rep.Summary())
	if !rep.Judged() {
		t.Fatal("the epoch published a window; the report must have used it")
	}
	for _, v := range rep.Unexplained {
		t.Logf("  not explained: %s", v.Describe())
	}
	// Not a hard failure: an unexplained removal is Proton doing something this
	// witness cannot account for, which is worth reporting loudly and is not
	// grounds for calling the run broken.
	if len(rep.Unexplained) > 0 {
		t.Errorf("epoch %d removed %d entries from inside its own retention window",
			judged.EpochID, len(rep.Unexplained))
	}
}

func fetchDiff(ctx context.Context, epochID int64) ([]byte, error) {
	url := fmt.Sprintf("https://proton.me/kt/epoch.1.%d.diff", epochID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<30))
}
