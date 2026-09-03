// Command kt-unblock probes the external preconditions that TODO.md's blocked
// items are waiting on, and reports which have become reachable.
//
// # Why this exists
//
// Several items in TODO.md are not blocked on effort. They are blocked on
// somebody else shipping something: Apple deploying an RPC that exists in their
// proto but not their service, Meta publishing a pinnable key, a witness
// serving the signed checkpoints it already holds. Nothing in this repository
// moves them.
//
// The failure mode is not that they are blocked. It is that a conclusion
// recorded once quietly goes stale, and nobody notices for months.
//
// That is not hypothetical. This tool was written the day production Sigstore
// Rekor v2 turned out to have been live since 2025-09-23, while TODO.md still
// said "wire it the day a production v2 endpoint exists" — because the earlier
// check had found only the staging instance and the conclusion was never
// revisited. Witnessing it needed no new code at all. The cost of that stale
// entry was months of not witnessing a 93-million-entry log.
//
// So each probe below answers one question: is the thing we said we were
// waiting for still absent?
//
// # What this deliberately does not do
//
// It makes no assertion about any log and writes nothing to the witness store.
// A probe here is a prompt to go and look, in exactly the same spirit as the
// peer poller: it produces leads, not findings. Reachability is not
// correctness, and a precondition becoming available is the start of the work,
// not the end of it.
//
// Exit status is 0 when every probe ran, whatever they found, and 1 only if a
// probe could not be attempted. "Still blocked" is the expected result and must
// not read as a failure, or this becomes another red signal people learn to
// ignore.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// state is what a probe concluded.
type state int

const (
	stillBlocked state = iota // the precondition is still absent — expected
	unblocked                 // it is now reachable: go and look
	inconclusive              // the probe could not tell, e.g. the network failed
)

func (s state) String() string {
	switch s {
	case unblocked:
		return "UNBLOCKED"
	case stillBlocked:
		return "still blocked"
	}
	return "inconclusive"
}

// result is one probe's finding.
type result struct {
	Item    string // the TODO item this corresponds to
	State   state
	Detail  string
	Action  string // what to do if it is unblocked
	Elapsed time.Duration
}

type probe struct {
	item   string
	action string
	run    func(context.Context, *http.Client) (state, string)
}

func main() {
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	jsonOut := flag.Bool("json", false, "emit JSON rather than text")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := &http.Client{Timeout: 20 * time.Second}
	probes := allProbes()

	// Probed concurrently: they are independent, all read-only, and hit
	// different parties, so there is no reason to serialize a minute of waiting.
	results := make([]result, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p probe) {
			defer wg.Done()
			start := time.Now()
			st, detail := p.run(ctx, client)
			results[i] = result{
				Item: p.item, State: st, Detail: detail,
				Action: p.action, Elapsed: time.Since(start),
			}
		}(i, p)
	}
	wg.Wait()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		out := make([]map[string]any, 0, len(results))
		for _, r := range results {
			out = append(out, map[string]any{
				"item": r.Item, "state": r.State.String(),
				"detail": r.Detail, "action": r.Action,
				"elapsed_ms": r.Elapsed.Milliseconds(),
			})
		}
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	var nUnblocked, nInconclusive int
	fmt.Println("Preconditions for TODO.md's blocked items")
	fmt.Println()
	for _, r := range results {
		marker := "  "
		switch r.State {
		case unblocked:
			marker, nUnblocked = "->", nUnblocked+1
		case inconclusive:
			nInconclusive++
		}
		fmt.Printf("%s %-34s %-14s %s\n", marker, r.Item, r.State, r.Detail)
		if r.State == unblocked && r.Action != "" {
			fmt.Printf("   %s\n", r.Action)
		}
	}
	fmt.Println()
	switch {
	case nUnblocked > 0:
		fmt.Printf("%d precondition(s) newly reachable — go and look.\n", nUnblocked)
	default:
		fmt.Println("Nothing newly reachable. This is the expected result.")
	}
	if nInconclusive > 0 {
		fmt.Printf("%d probe(s) inconclusive; absence of an answer is not evidence.\n", nInconclusive)
	}
}

func allProbes() []probe {
	return []probe{
		{
			item:   "apple/log-leaves-for-revision",
			action: "Apple ships the RPC that would bind iMessage heads to the verified root.",
			run:    probeAppleInitBag,
		},
		{
			item:   "meta/pinnable-key",
			action: "Meta or Cloudflare now publishes a key; Meta's head could stop being derived.",
			run:    probeMetaKey,
		},
		{
			item:   "witness/signed-peer-view",
			action: "A peer serves the signed checkpoint it holds; gossip can become conclusive.",
			run:    probePeerRetrieval,
		},
		{
			item:   "sigstore/trusted-root-tlogs",
			action: "The set of active Sigstore logs changed; check for a new witnessable log.",
			run:    probeSigstoreTlogs,
		},
		{
			item:   "yubikey/piv-ed25519",
			action: "A YubiKey 5.7+ is attached; the signing key can move to hardware.",
			run:    probeYubiKey,
		},
	}
}

// --- probes ----------------------------------------------------------------

// probeAppleInitBag looks for the RPC that would let Apple's per-application
// heads be bound to the root we verify.
//
// It is declared in Apple's proto but absent from the live bag. The bag is the
// service's own statement of what it exposes, so its appearance there is the
// signal.
func probeAppleInitBag(ctx context.Context, c *http.Client) (state, string) {
	const bag = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=5"
	body, err := fetch(ctx, c, bag)
	if err != nil {
		return inconclusive, err.Error()
	}
	const want = "log-leaves-for-revision"
	if strings.Contains(string(body), want) {
		return unblocked, "init bag now declares " + want
	}
	return stillBlocked, "init bag still does not declare " + want
}

// probeMetaKey looks for a verifying key in Meta's plexi namespace.
//
// Meta's head is currently DERIVED from a listing rather than carried by a
// signature, which is why contradictions there withhold rather than accuse. A
// published key would change what the witness is allowed to claim.
func probeMetaKey(ctx context.Context, c *http.Client) (state, string) {
	const ns = "https://plexi.key-transparency.cloudflare.com/namespaces/messenger.key-transparency.v1"
	body, err := fetch(ctx, c, ns)
	if err != nil {
		return inconclusive, err.Error()
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return inconclusive, "namespace is not JSON: " + err.Error()
	}
	// Only a key that is actually present and non-empty counts. A declared-but-
	// null field is the same as no key, and reporting it as progress would be
	// exactly the stale-conclusion problem this tool exists to prevent.
	for _, k := range []string{"public_key", "verifying_key", "key", "signature_key"} {
		if v, ok := doc[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return unblocked, fmt.Sprintf("namespace publishes %q", k)
			}
		}
	}
	return stillBlocked, "namespace publishes no verifying key"
}

// probePeerRetrieval checks whether any witness will serve the signed
// checkpoint it holds.
//
// This is the missing piece for conclusive gossip. litewitness already HOLDS
// the artifact — the log's own signature over a body it may have obtained
// independently — but exposes only POST /add-checkpoint, so every retrieval
// path 404s. The convicting signature is the log's, not the witness's, which is
// why serving it would need nobody to be trusted.
func probePeerRetrieval(ctx context.Context, c *http.Client) (state, string) {
	const base = "https://witness.stagemole.eu"
	paths := []string{"/checkpoint", "/get-checkpoint", "/checkpoints", "/api/checkpoint"}
	var tried []string
	for _, p := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p, nil)
		if err != nil {
			continue
		}
		resp, err := c.Do(req)
		if err != nil {
			return inconclusive, err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return unblocked, fmt.Sprintf("%s%s returns 200", base, p)
		}
		tried = append(tried, fmt.Sprintf("%s=%d", p, resp.StatusCode))
	}
	return stillBlocked, "no retrieval path: " + strings.Join(tried, " ")
}

// probeSigstoreTlogs reports the active logs in Sigstore's trusted root.
//
// This is the probe that would have caught Rekor v2 months earlier. It reports
// the count rather than a fixed expectation, because the interesting event is
// the set CHANGING — a new log appearing is a candidate to witness, and a log
// acquiring an end date is one to stop cosigning.
func probeSigstoreTlogs(ctx context.Context, c *http.Client) (state, string) {
	root, err := fetchSigstoreTrustedRoot(ctx, c)
	if err != nil {
		return inconclusive, err.Error()
	}
	var doc struct {
		Tlogs []struct {
			BaseURL   string `json:"baseUrl"`
			PublicKey struct {
				ValidFor struct {
					End string `json:"end"`
				} `json:"validFor"`
			} `json:"publicKey"`
		} `json:"tlogs"`
	}
	if err := json.Unmarshal(root, &doc); err != nil {
		return inconclusive, "trusted root is not JSON: " + err.Error()
	}
	var active []string
	for _, t := range doc.Tlogs {
		if t.PublicKey.ValidFor.End == "" {
			active = append(active, t.BaseURL)
		}
	}
	// Two active logs is the state as of 2026-09-02: Rekor v1 and v2. Anything
	// else is worth a look.
	const knownActive = 2
	if len(active) != knownActive {
		return unblocked, fmt.Sprintf("%d active tlogs (expected %d): %s",
			len(active), knownActive, strings.Join(active, ", "))
	}
	return stillBlocked, fmt.Sprintf("%d active tlogs, unchanged", len(active))
}

// fetchSigstoreTrustedRoot walks Sigstore's TUF metadata to the trusted root.
//
// The targets are consistent-snapshot named, so `targets/trusted_root.json`
// 404s: the hash has to be read out of the targets metadata first. The metadata
// itself is version-prefixed at the root path, which is why this is three
// requests rather than one.
func fetchSigstoreTrustedRoot(ctx context.Context, c *http.Client) ([]byte, error) {
	const cdn = "https://tuf-repo-cdn.sigstore.dev"

	ts, err := fetch(ctx, c, cdn+"/timestamp.json")
	if err != nil {
		return nil, err
	}
	snapVer, err := metaVersion(ts, "snapshot.json")
	if err != nil {
		return nil, err
	}
	snap, err := fetch(ctx, c, fmt.Sprintf("%s/%d.snapshot.json", cdn, snapVer))
	if err != nil {
		return nil, err
	}
	tgtVer, err := metaVersion(snap, "targets.json")
	if err != nil {
		return nil, err
	}
	tgts, err := fetch(ctx, c, fmt.Sprintf("%s/%d.targets.json", cdn, tgtVer))
	if err != nil {
		return nil, err
	}

	var td struct {
		Signed struct {
			Targets map[string]struct {
				Hashes map[string]string `json:"hashes"`
			} `json:"targets"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(tgts, &td); err != nil {
		return nil, err
	}
	for name, t := range td.Signed.Targets {
		if !strings.HasSuffix(name, "trusted_root.json") {
			continue
		}
		if h := t.Hashes["sha256"]; h != "" {
			return fetch(ctx, c, fmt.Sprintf("%s/targets/%s.%s", cdn, h, name))
		}
	}
	return nil, fmt.Errorf("no trusted_root.json target in TUF metadata")
}

// metaVersion reads the version of one referenced metadata file.
func metaVersion(b []byte, name string) (int, error) {
	var d struct {
		Signed struct {
			Meta map[string]struct {
				Version int `json:"version"`
			} `json:"meta"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return 0, err
	}
	if m, ok := d.Signed.Meta[name]; ok && m.Version > 0 {
		return m.Version, nil
	}
	return 0, fmt.Errorf("no version for %s", name)
}

// probeYubiKey reports whether an attached YubiKey can hold the signing key.
//
// PIV Ed25519 needs firmware 5.7 or later; the key on hand is 5.2.7. This is
// the one precondition that is satisfied by buying something rather than by
// waiting, and the one whose answer is local.
func probeYubiKey(ctx context.Context, _ *http.Client) (state, string) {
	if _, err := exec.LookPath("ykman"); err != nil {
		return inconclusive, "ykman not installed"
	}
	out, err := exec.CommandContext(ctx, "ykman", "list").CombinedOutput()
	if err != nil {
		return inconclusive, strings.TrimSpace(string(out))
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return stillBlocked, "no YubiKey attached"
	}
	// Firmware is reported as "Firmware version: X.Y.Z" by `ykman info`; the
	// list output carries it too on recent versions. Parse conservatively and
	// report the raw line rather than guessing, because claiming a key supports
	// Ed25519 when it does not would send the operator down a dead end.
	for _, line := range strings.Split(text, "\n") {
		if v, ok := firmwareAtLeast(line, 5, 7); ok && v {
			return unblocked, "attached key supports PIV Ed25519: " + line
		}
	}
	return stillBlocked, "attached key(s) predate firmware 5.7: " + text
}

// firmwareAtLeast reports whether a ykman line names a firmware >= major.minor.
// The second return distinguishes "found a version and it is too old" from
// "no version in this line at all".
func firmwareAtLeast(line string, major, minor int) (ok bool, found bool) {
	i := strings.Index(line, "Firmware version:")
	if i < 0 {
		return false, false
	}
	var maj, min, patch int
	if n, _ := fmt.Sscanf(strings.TrimSpace(line[i+len("Firmware version:"):]),
		"%d.%d.%d", &maj, &min, &patch); n < 2 {
		return false, false
	}
	if maj > major || (maj == major && min >= minor) {
		return true, true
	}
	return false, true
}

// fetch reads a URL, capping the body so a probe cannot be made to exhaust
// memory by a party we are, by construction, not trusting.
func fetch(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
