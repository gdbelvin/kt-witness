// Command kt-ctconfig turns Google's CT log list into witness configuration.
//
// Static CT logs are by far the largest population a witness can serve — ~80
// against 42 remaining RFC 6962 logs — and they rotate every six months, so
// hand-maintaining the list in deploy/witness.json is a standing source of
// staleness. This regenerates it from the authoritative list.
//
// The origin comes from submission_url, never monitoring_url. Google submits to
// <log>.prod.certificate.transparency.goog while serving tiles from a
// storage.googleapis.com bucket; using the monitoring host would produce a note
// key hash matching nothing, which presents as an unsigned checkpoint rather
// than an error. See internal/staticct.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/staticct"
	"golang.org/x/mod/sumdb/note"
)

const defaultListURL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

// logList is the subset of the v3 log list schema this tool needs. Only
// tiled_logs are relevant: the RFC 6962 logs in the same document serve
// get-sth, not a tlog-checkpoint, and are not witnessable by this witness.
type logList struct {
	Operators []struct {
		Name  string     `json:"name"`
		Tiled []tiledLog `json:"tiled_logs"`
	} `json:"operators"`
}

type tiledLog struct {
	Description   string `json:"description"`
	Key           string `json:"key"`
	SubmissionURL string `json:"submission_url"`
	MonitoringURL string `json:"monitoring_url"`

	// State is absent for logs no root program has ruled on yet — test and
	// monitoring_only shards. Present states are single-keyed: usable,
	// pending, qualified, rejected, retired or readonly.
	State map[string]struct {
		Timestamp string `json:"timestamp"`
	} `json:"state"`

	TemporalInterval struct {
		StartInclusive string `json:"start_inclusive"`
		EndExclusive   string `json:"end_exclusive"`
	} `json:"temporal_interval"`
}

// entry is the witness config shape for a static CT log, matching logConfig in
// cmd/kt-witness.
type entry struct {
	Type    string `json:"type"`
	Origin  string `json:"origin"`
	BaseURL string `json:"base_url"`
	LogKey  string `json:"log_key"`
}

// skipped records why a log was left out, so the exclusions can be reviewed
// rather than silently trusted.
type skipped struct {
	Description string
	Reason      string
}

func main() {
	var (
		listURL = flag.String("list", defaultListURL, "CT log list URL")
		verify  = flag.Bool("verify", false, "fetch each log's checkpoint and check its signature, excluding those that fail")
		out     = flag.String("o", "", "write the entry array here instead of stdout")
	)
	flag.Parse()

	if err := run(*listURL, *verify, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(listURL string, verify bool, out string) error {
	body, err := fetch(listURL, 30*time.Second)
	if err != nil {
		return fmt.Errorf("fetch log list: %w", err)
	}
	var list logList
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Errorf("parse log list: %w", err)
	}

	entries, skips, total := selectLogs(&list, time.Now())

	if verify {
		entries, skips = verifyAll(entries, skips)
	}

	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if out == "" {
		os.Stdout.Write(encoded)
	} else if err := os.WriteFile(out, encoded, 0o644); err != nil {
		return err
	}

	for _, s := range skips {
		fmt.Fprintf(os.Stderr, "skip %-44s %s\n", s.Description, s.Reason)
	}
	fmt.Fprintf(os.Stderr, "\n%d tiled logs in list, %d kept, %d skipped\n", total, len(entries), len(skips))
	return nil
}

// selectLogs applies the witnessing filter and shapes the surviving logs into
// config entries, preserving log-list order so reruns produce a reviewable diff.
//
// What is excluded, and why:
//
//   - rejected, retired and readonly logs. A retired or rejected log's tree is
//     no longer growing under any root program's supervision, and a readonly
//     log has stopped accepting submissions; a cosignature on a frozen tree
//     asserts nothing anyone needs. As of this writing no tiled log carries
//     those states — only "rejected" occurs — but the check is written for all
//     three so a later list refresh cannot quietly reintroduce them.
//   - shards whose temporal interval has already ended. Those shards cannot
//     accept new certificates, so their heads are fixed and witnessing them
//     costs polling for no assertion.
//
// What is kept: usable, qualified and pending logs, and logs with no state at
// all. The stateless ones are the test and monitoring_only shards, which are
// genuine servable static CT logs — the witness already carries one by hand
// (Let's Encrypt Twig) — and a shard whose interval has not started yet is kept
// because it usually already serves a signed checkpoint. Whether it really does
// is not guessable from the list, which is what -verify is for.
func selectLogs(list *logList, now time.Time) (entries []entry, skips []skipped, total int) {
	for _, op := range list.Operators {
		for _, l := range op.Tiled {
			total++
			if reason := excludeReason(&l, now); reason != "" {
				skips = append(skips, skipped{l.Description, reason})
				continue
			}
			entries = append(entries, entry{
				Type:   "staticct",
				Origin: staticct.OriginFromSubmissionURL(l.SubmissionURL),
				// The adapter joins tile paths onto this, so the trailing
				// slash is load-bearing; the list is not consistent about it.
				BaseURL: strings.TrimSuffix(l.MonitoringURL, "/") + "/",
				LogKey:  l.Key,
			})
		}
	}
	return entries, skips, total
}

// excludeReason returns why a log must not be witnessed, or "" to keep it.
func excludeReason(l *tiledLog, now time.Time) string {
	if l.SubmissionURL == "" || l.MonitoringURL == "" || l.Key == "" {
		return "incomplete entry"
	}
	if _, err := base64.StdEncoding.DecodeString(l.Key); err != nil {
		return "undecodable key"
	}
	// States are mutually exclusive in the schema, but iterate rather than
	// assume a single key: an unexpected second state must not be ignored.
	for _, s := range sortedKeys(l.State) {
		switch s {
		case "rejected", "retired", "readonly":
			return "state " + s
		}
	}
	if end := l.TemporalInterval.EndExclusive; end != "" {
		t, err := time.Parse(time.RFC3339, end)
		if err != nil {
			return "unparseable temporal_interval end " + end
		}
		if !t.After(now) {
			return "temporal interval ended " + end
		}
	}
	return ""
}

func sortedKeys(m map[string]struct {
	Timestamp string `json:"timestamp"`
}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// verifyAll fetches each candidate's checkpoint and opens it with the log's own
// key, dropping any log that fails.
//
// This is not belt-and-braces. A config entry for a log we cannot verify would
// have the witness poll it forever and refuse to sign, which is indistinguishable
// on the metrics from a log genuinely withholding — the one signal that is
// supposed to mean something.
func verifyAll(candidates []entry, skips []skipped) ([]entry, []skipped) {
	type result struct {
		e   entry
		err error
	}
	results := make([]result, len(candidates))

	// Eight, and deliberately not derived from the core count. Every one of
	// these spends its time waiting on a CT log to answer, not on this
	// machine's CPU — a thirty-two core box would gain nothing from
	// thirty-two of them and would only look like a scraper to the operators
	// being asked. This is a politeness limit, so it is a number.
	const workers = 8
	var wg sync.WaitGroup
	ch := make(chan int)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range ch {
				results[idx] = result{candidates[idx], verifyOne(candidates[idx])}
			}
		}()
	}
	for i := range candidates {
		ch <- i
	}
	close(ch)
	wg.Wait()

	var kept []entry
	for _, r := range results {
		if r.err != nil {
			skips = append(skips, skipped{r.e.Origin, "verify: " + r.err.Error()})
			continue
		}
		kept = append(kept, r.e)
	}
	return kept, skips
}

// verifyOne opens the log's checkpoint through note.Open with a verifier built
// the same way the witness builds it, so a pass here means the witness will
// accept the log's checkpoints too.
func verifyOne(e entry) error {
	spki, err := base64.StdEncoding.DecodeString(e.LogKey)
	if err != nil {
		return err
	}
	v, err := staticct.NewVerifier(e.Origin, spki)
	if err != nil {
		return err
	}
	body, err := fetch(e.BaseURL+"checkpoint", 15*time.Second)
	if err != nil {
		return err
	}
	if _, err := note.Open(body, note.VerifierList(v)); err != nil {
		return err
	}
	return nil
}

func fetch(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
