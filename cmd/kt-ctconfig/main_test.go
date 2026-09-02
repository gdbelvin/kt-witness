package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// fixture mirrors the shapes actually present in Google's v3 list: a usable
// log, a rejected one, a stateless test shard, a shard whose interval has
// ended, and a pending shard whose interval has not started.
const fixture = `{
  "operators": [
    {
      "name": "Example",
      "tiled_logs": [
        {
          "description": "usable",
          "key": "AAAA",
          "submission_url": "https://sub.example/2027h1/",
          "monitoring_url": "https://mon.example/2027h1",
          "state": {"usable": {"timestamp": "2026-01-01T00:00:00Z"}},
          "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}
        },
        {
          "description": "rejected",
          "key": "AAAA",
          "submission_url": "https://sub.example/rejected/",
          "monitoring_url": "https://mon.example/rejected/",
          "state": {"rejected": {"timestamp": "2026-01-01T00:00:00Z"}},
          "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}
        },
        {
          "description": "stateless test shard",
          "key": "AAAA",
          "submission_url": "https://sub.example/test/",
          "monitoring_url": "https://mon.example/test/",
          "log_type": "test",
          "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}
        },
        {
          "description": "window passed",
          "key": "AAAA",
          "submission_url": "https://sub.example/old/",
          "monitoring_url": "https://mon.example/old/",
          "state": {"usable": {"timestamp": "2025-01-01T00:00:00Z"}},
          "temporal_interval": {"start_inclusive": "2025-01-01T00:00:00Z", "end_exclusive": "2025-07-01T00:00:00Z"}
        },
        {
          "description": "pending, not yet started",
          "key": "AAAA",
          "submission_url": "https://sub.example/2028h1/",
          "monitoring_url": "https://mon.example/2028h1/",
          "state": {"pending": {"timestamp": "2026-01-01T00:00:00Z"}},
          "temporal_interval": {"start_inclusive": "2028-01-01T00:00:00Z", "end_exclusive": "2028-07-01T00:00:00Z"}
        },
        {
          "description": "retired",
          "key": "AAAA",
          "submission_url": "https://sub.example/retired/",
          "monitoring_url": "https://mon.example/retired/",
          "state": {"retired": {"timestamp": "2026-01-01T00:00:00Z"}},
          "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}
        },
        {
          "description": "unusable key",
          "key": "not base64!!",
          "submission_url": "https://sub.example/badkey/",
          "monitoring_url": "https://mon.example/badkey/",
          "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}
        }
      ]
    }
  ]
}`

func TestSelectLogs(t *testing.T) {
	var list logList
	if err := json.Unmarshal([]byte(fixture), &list); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	entries, skips, total := selectLogs(&list, now)
	if total != 7 {
		t.Errorf("total = %d, want 7", total)
	}

	// Positive: usable, stateless test and not-yet-started pending survive.
	got := map[string]entry{}
	for _, e := range entries {
		got[e.Origin] = e
	}
	for _, want := range []string{"sub.example/2027h1", "sub.example/test", "sub.example/2028h1"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s was dropped, want kept", want)
		}
	}

	// Negative control: the states and windows that must never be witnessed.
	// Without this the filter could be a no-op and the positives still pass.
	for _, bad := range []string{"sub.example/rejected", "sub.example/retired", "sub.example/old", "sub.example/badkey"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s was kept, want excluded", bad)
		}
	}
	if len(entries) != 3 || len(skips) != 4 {
		t.Fatalf("kept %d skipped %d, want 3 and 4", len(entries), len(skips))
	}

	// The origin must come from submission_url, not monitoring_url: they differ
	// for Google's logs and the wrong one yields a key hash matching nothing.
	e := got["sub.example/2027h1"]
	if e.Type != "staticct" {
		t.Errorf("type = %q", e.Type)
	}
	if e.BaseURL != "https://mon.example/2027h1/" {
		t.Errorf("base_url = %q, want the monitoring URL with a trailing slash", e.BaseURL)
	}
	if e.LogKey != "AAAA" {
		t.Errorf("log_key = %q, want the list's key verbatim", e.LogKey)
	}
}

// TestSelectLogsOrder pins output order to the log list's own order, so that
// regenerating the config produces a reviewable diff rather than a reshuffle.
func TestSelectLogsOrder(t *testing.T) {
	var list logList
	if err := json.Unmarshal([]byte(fixture), &list); err != nil {
		t.Fatal(err)
	}
	entries, _, _ := selectLogs(&list, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	want := []string{"sub.example/2027h1", "sub.example/test", "sub.example/2028h1"}
	for i, w := range want {
		if entries[i].Origin != w {
			t.Errorf("entry %d = %q, want %q", i, entries[i].Origin, w)
		}
	}
}

// TestLiveVerifyNegativeControl proves -verify has teeth. Every one of the 69
// candidates passed on the first run, which is only reassuring if a wrong key
// or a wrong origin would actually have been rejected — so check both against a
// live log. The wrong-origin case is the specific trap internal/staticct warns
// about: monitoring_url instead of submission_url yields a key hash matching
// nothing, which note.Open reports as an unsigned note rather than a bad one.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveVerifyNegativeControl(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	raw, err := os.ReadFile("../../deploy/ct-logs.json")
	if err != nil {
		t.Skip("deploy/ct-logs.json not generated yet")
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	good := entries[0]

	if err := verifyOne(good); err != nil {
		t.Fatalf("%s: %v", good.Origin, err)
	}

	wrongOrigin := good
	wrongOrigin.Origin = strings.TrimSuffix(strings.TrimPrefix(good.BaseURL, "https://"), "/")
	if err := verifyOne(wrongOrigin); err == nil {
		t.Error("checkpoint verified under the monitoring-derived origin, want failure")
	}

	wrongKey := good
	for _, other := range entries[1:] {
		if other.LogKey != good.LogKey {
			wrongKey.LogKey = other.LogKey
			break
		}
	}
	if err := verifyOne(wrongKey); err == nil {
		t.Error("checkpoint verified under another log's key, want failure")
	}
}
