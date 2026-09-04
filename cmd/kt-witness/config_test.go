package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
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
				if _, err := l.build(log, nil, nil, nil); err != nil {
					t.Errorf("%s (%s): %v", l.Origin, l.Type, err)
				}
			}
			t.Logf("%d logs build", len(cfg.Logs))
		})
	}
}
