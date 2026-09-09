package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gdbsecurity/kt-witness/internal/source/akd"
)

// akdSourcesFromConfig reads the witness's own config, so this harness checks
// against the same proof directories the witness does. A verifier validated
// against a different log than the one it will run on has been validated
// against nothing.
func akdSourcesFromConfig(path string) (map[string]*akd.Source, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Logs []struct {
			Type         string `json:"type"`
			Origin       string `json:"origin"`
			LogDirectory string `json:"log_directory"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string]*akd.Source{}
	for _, l := range cfg.Logs {
		if l.Type != "akd" || l.LogDirectory == "" {
			continue
		}
		s, err := akd.New(akd.Config{Origin: l.Origin, LogDirectory: l.LogDirectory})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", l.Origin, err)
		}
		out[l.Origin] = s
	}
	return out, nil
}
