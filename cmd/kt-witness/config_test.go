package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The shipped configs must actually build. This has failed twice in this
// project's history — both times because a .gitignore pattern hid the file
// rather than because it was wrong — so the guard is cheap insurance that the
// config and the binary have not drifted apart.
func TestShippedConfigsBuild(t *testing.T) {
	for _, path := range []string{"../../deploy/witness.json", "../../witness.example.json"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var cfg config
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields() // a typo'd key must not be silently ignored
			if err := dec.Decode(&cfg); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(cfg.Logs) == 0 {
				t.Fatal("config lists no logs")
			}
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			seen := map[string]bool{}
			for _, l := range cfg.Logs {
				if l.Origin == "" {
					t.Error("a log has no origin")
				}
				if seen[l.Origin] {
					// Two sources for one origin would race each other in the
					// store and produce alternating cosignatures.
					t.Errorf("origin %q appears twice", l.Origin)
				}
				seen[l.Origin] = true
				if _, err := l.build(log, nil, nil, nil, nil); err != nil {
					t.Errorf("%s (%s): %v", l.Origin, l.Type, err)
				}
			}
			t.Logf("%d logs build", len(cfg.Logs))
		})
	}
}

// TestWorkOriginsCannotSilentlyNarrowCoverage.
//
// work.origins used to narrow only the work channel: anything left out was
// still swept by the auditor, so the setting cost dispatch and not coverage. As
// verification moves onto the queue that stops being true — a log left out
// would go unaudited while the witness went on publishing a coverage figure
// that did not mention it.
//
// A silent hole in coverage is the one error this witness must not make, so the
// ambiguous configuration is refused rather than interpreted.
func TestWorkOriginsCannotSilentlyNarrowCoverage(t *testing.T) {
	cfg := &config{}
	cfg.Logs = []logConfig{
		{Origin: "meta.messenger.kt/v1", Type: "akd"},
		{Origin: "whatsapp.kt/v2", Type: "akd"},
		{Origin: "some.ct.log", Type: "sumdb"},
	}

	// Unset: covers every auditable log.
	if got := queueOrigins(cfg); len(got) != 2 {
		t.Errorf("unset work.origins covers %v, want both AKD logs", got)
	}
	// Naming all of them is fine.
	cfg.Work.Origins = []string{"meta.messenger.kt/v1", "whatsapp.kt/v2"}
	if err := checkQueueCoverage(cfg); err != nil {
		t.Errorf("naming every auditable log was refused: %v", err)
	}
	// Naming a subset is refused, and says which log would be dropped.
	cfg.Work.Origins = []string{"whatsapp.kt/v2"}
	err := checkQueueCoverage(cfg)
	if err == nil {
		t.Fatal("work.origins omitting an auditable log was accepted; that log " +
			"would go unaudited while coverage was published for it")
	}
	if !strings.Contains(err.Error(), "meta.messenger.kt/v1") {
		t.Errorf("the refusal does not name the dropped log: %v", err)
	}
}
