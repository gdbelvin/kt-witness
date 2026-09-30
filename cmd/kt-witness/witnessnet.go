package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/loglist"
	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/server"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
)

// startWitnessNetwork builds the push endpoint and, when lists are configured,
// starts discovering logs from witness-network.org.
//
// It returns a nil handler when push is not enabled, which leaves
// /add-checkpoint unregistered; /about is served either way and says so.
func startWitnessNetwork(ctx context.Context, cfg *config, w *witness.Witness, db *store.Store, log *slog.Logger) (http.Handler, server.AboutInfo, error) {
	wn := cfg.WitnessNetwork
	about := server.AboutInfo{
		PublicURL: wn.PublicURL,
		Operator:  wn.Operator,
		Contact:   wn.Contact,
		Lists:     wn.Lists,
	}
	if !wn.Push && len(wn.Lists) == 0 {
		return nil, about, nil
	}

	interval := loglist.DefaultInterval
	if wn.Refresh != "" {
		d, err := time.ParseDuration(wn.Refresh)
		if err != nil {
			return nil, about, fmt.Errorf("witness_network.refresh: %w", err)
		}
		// Refused rather than clamped: the network's rule is at most weekly,
		// and /about must state the interval actually in force.
		if d <= 0 || d > loglist.MaxInterval {
			return nil, about, fmt.Errorf("witness_network.refresh %s: must be positive and at most %s", d, loglist.MaxInterval)
		}
		interval = d
	}
	if len(wn.Lists) > 0 {
		about.ListRefresh = interval.String()
	}

	// Every statically configured C2SP log accepts pushes too. Those are the
	// logs whose checkpoints are signed notes under a vkey we already hold, so
	// a push is verified exactly as a poll would be. They take precedence over
	// any list entry for the same origin.
	var static []*push.Log
	for _, l := range cfg.Logs {
		if (l.Type != "" && l.Type != "c2sp") || l.VKey == "" {
			continue
		}
		v, err := note.NewVerifier(l.VKey)
		if err != nil {
			return nil, about, fmt.Errorf("log %s: vkey: %w", l.Origin, err)
		}
		static = append(static, &push.Log{
			Origin: l.Origin, VKey: l.VKey, Verifier: v, From: loglist.FromConfig,
		})
	}

	reg := loglist.NewRegistry(static)
	// Before serving, so a log discovered in an earlier run can push at once
	// rather than after the first list fetch completes.
	if err := reg.Load(db); err != nil {
		log.Warn("witness-network: some stored logs could not be loaded", "err", err)
	}
	if len(wn.Lists) > 0 {
		f := &loglist.Fetcher{
			URLs: wn.Lists, Interval: interval,
			Store: db, Registry: reg, Log: log,
		}
		go f.Run(ctx)
	}
	log.Info("witness-network: push enabled",
		"static_logs", len(static), "lists", len(wn.Lists), "refresh", interval.String())

	h := push.New(push.Config{Witness: w, Store: db, Registry: reg, Log: log})
	return h, about, nil
}
