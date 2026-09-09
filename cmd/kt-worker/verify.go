package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
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
	verify(ctx context.Context, origin string, epoch int64) (root, signed string, err error)
}

// akdVerifier replays a Meta or WhatsApp audit proof with the Rust sidecar.
//
// Stateless: any worker can verify any epoch, in any order, without holding
// anything from a previous one. That is what makes AKD work well here — a
// laptop can be handed epochs 400,000 to 400,100 and needs nothing else.
type akdVerifier struct{ bin string }

func (v akdVerifier) verify(ctx context.Context, origin string, epoch int64) (string, string, error) {
	req, _ := json.Marshal(map[string]any{"origin": origin, "epoch": epoch})
	cmd := exec.CommandContext(ctx, v.bin)
	cmd.Stdin = strings.NewReader(string(req))
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", v.bin, err)
	}
	var r struct {
		OK     bool   `json:"ok"`
		Root   string `json:"root"`
		Signed string `json:"signed_root"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", fmt.Errorf("sidecar output was not JSON: %s", strings.TrimSpace(string(out)))
	}
	if !r.OK && r.Error != "" {
		return "", "", fmt.Errorf("%s", r.Error)
	}
	return r.Root, r.Signed, nil
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

func (v protonGPUVerifier) verify(ctx context.Context, origin string, epoch int64) (string, string, error) {
	tree := fmt.Sprintf("%s/epoch_tree_%d.bin", v.dir, epoch)
	cmd := exec.CommandContext(ctx, v.bin, tree)
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", v.bin, err)
	}
	var r struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", "", fmt.Errorf("rebuild output was not JSON: %s", strings.TrimSpace(string(out)))
	}
	signed, err := protonSignedRoot(ctx, v.dir, epoch)
	if err != nil {
		return r.Root, "", err
	}
	return r.Root, signed, nil
}

// protonSignedRoot reads the operator's signed tree hash from the manifest the
// fetch step wrote. Read locally rather than fetched, so a worker cannot be
// steered by whatever a network answers at the moment it asks.
func protonSignedRoot(_ context.Context, dir string, epoch int64) (string, error) {
	f, err := openManifest(dir)
	if err != nil {
		return "", err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		var m struct {
			Epoch    int64  `json:"epoch"`
			TreeHash string `json:"tree_hash"`
		}
		if err := dec.Decode(&m); err != nil {
			return "", fmt.Errorf("epoch %d is not in the manifest", epoch)
		}
		if m.Epoch == epoch {
			return m.TreeHash, nil
		}
	}
}

// timeout bounds one epoch. A rebuild is about a minute on the GPU and a proof
// replay tens of seconds; anything far past that has gone wrong in a way that
// waiting will not fix, and the lease is expiring meanwhile.
const epochTimeout = 15 * time.Minute
