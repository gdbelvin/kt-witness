package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/cosig"
	"github.com/gdbsecurity/kt-witness/internal/loglist"
	"github.com/gdbsecurity/kt-witness/internal/push"
	"github.com/gdbsecurity/kt-witness/internal/server"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
)

// staticPushQPD bounds pushes from statically configured logs, which state no
// budget of their own. Every accepted push is a signature on the HSM, which
// the poller shares; unlimited would let one misbehaving log operator starve
// every other log of cosignatures. One a minute is well above anything a
// polled log needs, since we fetch those ourselves.
const staticPushQPD = 1440

// startWitnessNetwork builds the push endpoint and, when lists are configured,
// starts discovering logs from witness-network.org.
//
// It returns a nil handler when push is not enabled, which leaves
// /add-checkpoint unregistered; /about is served either way and says so. The
// returned network func feeds /graph; it is nil when nothing about the network
// is configured, which leaves the map exactly as it was.
func startWitnessNetwork(ctx context.Context, cfg *config, w *witness.Witness, db *store.Store, log *slog.Logger) (http.Handler, server.AboutInfo, func() server.NetworkView, error) {
	wn := cfg.WitnessNetwork
	about := server.AboutInfo{
		PublicURL: wn.PublicURL,
		Operator:  wn.Operator,
		Contact:   wn.Contact,
		Lists:     wn.Lists,
	}
	if !wn.Push && len(wn.Lists) == 0 {
		return nil, about, networkView(nil, nil, wn.Witnesses), nil
	}

	interval, intervalText := loglist.DefaultInterval, "24h"
	if wn.Refresh != "" {
		intervalText = wn.Refresh
		d, err := time.ParseDuration(wn.Refresh)
		if err != nil {
			return nil, about, nil, fmt.Errorf("witness_network.refresh: %w", err)
		}
		// Refused rather than clamped: the network's rule is at most weekly,
		// and /about must state the interval actually in force.
		if d <= 0 || d > loglist.MaxInterval {
			return nil, about, nil, fmt.Errorf("witness_network.refresh %s: must be positive and at most %s", d, loglist.MaxInterval)
		}
		interval = d
	}
	if len(wn.Lists) > 0 {
		// As the operator wrote it: "24h", not time.Duration's "24h0m0s".
		about.ListRefresh = intervalText
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
			return nil, about, nil, fmt.Errorf("log %s: vkey: %w", l.Origin, err)
		}
		static = append(static, &push.Log{
			Origin: l.Origin, VKey: l.VKey, Verifier: v, From: loglist.FromConfig,
			QPD: staticPushQPD,
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
	return h, about, networkView(reg, wn.Lists, wn.Witnesses), nil
}

// networkView returns what /graph draws of the network: every log a list
// names that is in the registry (discovered ones, and configured ones a list
// also names), and the configured witness table. Nil when there is neither a
// list nor a witness to show.
//
// A func rather than a value because the fetcher adds logs while we run. Each
// call reads the registry afresh; it is a few dozen map reads per page load.
func networkView(reg *loglist.Registry, lists []string, ws []server.NetworkWitness) func() server.NetworkView {
	if reg == nil && len(lists) == 0 && len(ws) == 0 {
		return nil
	}
	short := make([]string, len(lists))
	for i, l := range lists {
		short[i] = server.ShortListName(l)
	}
	ws = append([]server.NetworkWitness(nil), ws...)
	return func() server.NetworkView {
		v := server.NetworkView{Lists: short, Witnesses: ws}
		if reg == nil {
			return v
		}
		for _, l := range reg.Logs() {
			static := reg.IsStatic(l.Origin)
			urls := reg.ListsFor(l.Origin)
			if len(urls) == 0 && !static && l.From != "" && l.From != loglist.FromConfig {
				urls = []string{l.From}
			}
			if len(urls) == 0 {
				// Configured and on no list we have read: not a network log.
				continue
			}
			names := make([]string, len(urls))
			for i, u := range urls {
				names[i] = server.ShortListName(u)
			}
			v.Logs = append(v.Logs, server.NetworkLog{
				Origin: l.Origin, List: names[0], Lists: names,
				QPD: l.QPD, Contact: l.Contact, Static: static,
			})
		}
		return v
	}
}

// networkPeerKeys merges the network table's witness keys into the configured
// peer keys, and returns the table with any key it could not use blanked.
//
// Only cosignature/v1 keys (algorithm byte 0x04) are accepted: that is what the
// cosignature verifier reads, and one bad key would otherwise fail the whole
// set at startup. A skipped key is logged and blanked rather than fatal — the
// table is somebody else's document and a witness advertising a key type we
// cannot check is not our misconfiguration. Duplicates are dropped, and a name
// already configured in peer_witnesses keeps that key: the operator wrote that
// one down deliberately.
func networkPeerKeys(peers []string, ws []server.NetworkWitness, log *slog.Logger) ([]string, []server.NetworkWitness) {
	out := append([]string(nil), peers...)
	byName := map[string]string{}
	for _, k := range peers {
		if n, _, ok := strings.Cut(k, "+"); ok {
			byName[n] = k
		}
	}
	ws = append([]server.NetworkWitness(nil), ws...)
	for i := range ws {
		k := strings.TrimSpace(ws[i].VKey)
		ws[i].VKey = k
		if k == "" {
			continue
		}
		name, ok := cosignatureKeyName(k)
		if ok {
			// The shape is right; now make sure the verifier will actually
			// take it (the key hash is checked there), so it cannot fail the
			// whole set below.
			_, err := cosig.NewVerifier([]string{k})
			ok = err == nil
		}
		if !ok {
			log.Warn("witness-network: ignoring witness key that is not a cosignature/v1 (0x04) key",
				"operator", ws[i].Operator, "vkey", k)
			ws[i].VKey = ""
			continue
		}
		if have, dup := byName[name]; dup {
			if have != k {
				log.Warn("witness-network: witness key differs from the configured peer key of the same name; keeping the configured one",
					"operator", ws[i].Operator, "name", name)
				ws[i].VKey = have
			}
			continue
		}
		byName[name] = k
		out = append(out, k)
	}
	return out, ws
}

// cosignatureKeyName checks that k is a well-formed cosignature/v1 verifier
// key — name+hash+base64(0x04 || 32-byte Ed25519 key) — and returns its name.
func cosignatureKeyName(k string) (string, bool) {
	parts := strings.SplitN(k, "+", 3)
	if len(parts) != 3 || parts[0] == "" || len(parts[1]) != 8 {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 33 || raw[0] != 0x04 {
		return "", false
	}
	return parts[0], true
}
