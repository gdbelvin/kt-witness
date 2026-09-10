package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/gdbsecurity/kt-witness/internal/source/akd"
)

// A verifier turns one epoch into a verdict, on whatever hardware this worker
// happens to be.
//
// The point of the interface is that the GPU box and a laptop are the same kind
// of participant. Before this, Proton's rebuild ran from a cron job writing a
// results file that was scp'd to the witness and imported from disk, while AKD
// verification ran inside the witness itself — two mechanisms, two failure
// modes, and one of them silently stopped for two days because nobody had
// scheduled it. One channel, and the witness knows what is outstanding because
// it handed it out.
type verifier interface {
	// verify returns the root it computed and the root the operator signed.
	// Deciding what a disagreement means is the witness's job, not this one's.
	verify(ctx context.Context, origin string, epoch int64, proofURL string) (root, signed string, err error)
}

// akdVerifier replays a Meta or WhatsApp audit proof with the Rust sidecar.
//
// Stateless: any worker can verify any epoch, in any order, without holding
// anything from a previous one. That is what makes AKD work well here — a
// laptop can be handed epochs 400,000 to 400,100 and needs nothing else from
// the witness but the numbers.
//
// # It resolves the epoch itself
//
// The sidecar cannot verify an epoch from its number. It needs the log
// directory and the two roots the transition runs between, and those come from
// the operator's own object listing — the roots are in the object key. The
// first version of this sent {origin, epoch} and would have had every
// assignment refused as malformed.
//
// The worker does that lookup itself rather than being told the answer, which
// is also the more honest arrangement: it checks the proof against roots it
// fetched from the operator, not against roots the witness asserted. The
// witness is asking for a second opinion, and an opinion formed from the
// asker's own evidence is worth less.
type akdVerifier struct {
	bin string
	src map[string]*akd.Source // by origin
	// threads caps the sidecar's runtime. Without it the sidecar sizes itself
	// from the machine's core count and ignores this worker's budget entirely
	// — one epoch took 3.7 cores on a laptop that had promised to use eight in
	// total across four of them.
	threads int
}

func (v akdVerifier) verify(ctx context.Context, origin string, epoch int64, proofURL string) (string, string, error) {
	s := v.src[origin]
	if s == nil {
		return "", "", fmt.Errorf("no log directory configured for %s", origin)
	}
	// The roots always come from the operator's own listing, never from the
	// assignment — including when the witness supplies the proof. That is what
	// makes this worker's verdict worth having, and it is what makes a canary
	// work: a proof the witness corrupted cannot rebuild roots the operator
	// published, so the only way to "pass" one is to not be verifying.
	ref, err := s.ResolveEpoch(ctx, epoch)
	if err != nil {
		return "", "", fmt.Errorf("resolving %s epoch %d: %w", origin, epoch, err)
	}

	fields := map[string]any{
		"log_directory": ref.LogDirectory,
		"epoch":         epoch,
		"prev_root":     ref.PrevRoot,
		"curr_root":     ref.CurrRoot,
	}
	if proofURL != "" {
		path, err := fetchProof(ctx, proofURL)
		if err != nil {
			return "", "", fmt.Errorf("fetching the supplied proof: %w", err)
		}
		defer os.Remove(path)
		fields["proof_path"] = path
	}
	req, _ := json.Marshal(fields)
	cmd := exec.CommandContext(ctx, v.bin)
	cmd.Stdin = strings.NewReader(string(req))
	if v.threads > 0 {
		cmd.Env = append(os.Environ(), fmt.Sprintf("KT_AKD_THREADS=%d", v.threads))
	}
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", v.bin, err)
	}
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", fmt.Errorf("sidecar output was not JSON: %s", strings.TrimSpace(string(out)))
	}
	if !r.OK {
		if r.Error != "" {
			return "", "", fmt.Errorf("%s", r.Error)
		}
		// The proof did not rebuild the root the operator published. Reported
		// as a disagreement, never as a finding: an empty computed root against
		// a published one. What that means is the witness's to decide, and this
		// worker does not get to accuse anybody.
		return "", ref.CurrRoot, nil
	}
	return ref.CurrRoot, ref.CurrRoot, nil
}

// akdSourcesFromConfig builds a resolver per AKD log named in the witness's
// config file.
//
// The same file the witness runs from, so a worker cannot be checking a
// different log directory than the one it is reporting about — the failure that
// would produce is a confident verdict on the wrong data.
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
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no akd logs", path)
	}
	return out, nil
}

// protonGPUVerifier rebuilds a Proton tree on the GPU.
//
// STATEFUL, and that is the one place this architecture does not simply
// generalise. An epoch is verified by applying its diff to the tree for the
// epoch before it, so this worker can only do epoch N if it already holds the
// tree for N-1. Ranges must therefore be contiguous, in order, and pinned to
// the worker that holds the tree — a laptop cannot pick up where the GPU box
// left off without first downloading 13 GB.
//
// The queue does not model that affinity yet. Until it does, Proton ranges must
// only be offered to this worker, which the origins filter achieves by
// convention rather than by construction.
type protonGPUVerifier struct {
	bin string // kt-proton-gpu
	dir string // where the retained tree and diffs live
}

func (v protonGPUVerifier) verify(ctx context.Context, origin string, epoch int64, _ string) (string, string, error) {
	tree := fmt.Sprintf("%s/epoch_tree_%d.bin", v.dir, epoch)
	cmd := exec.CommandContext(ctx, v.bin, tree)
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", v.bin, err)
	}
	var r struct {
		Root   string `json:"root"`
		Signed string `json:"signed_root"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", fmt.Errorf("%s output was not JSON: %s", v.bin, strings.TrimSpace(string(out)))
	}
	return r.Root, r.Signed, nil
}

// fetchProof downloads a proof the witness supplied, to a temp file the caller
// deletes. Used only for canaries.
func fetchProof(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	f, err := os.CreateTemp("", "kt-supplied-proof-*.bin")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
