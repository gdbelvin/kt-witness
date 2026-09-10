package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
)

// A verifier turns one epoch into two computed roots, on whatever hardware this
// worker happens to be.
//
// # What a worker is given, and what it is not
//
// It is given the proof — served by the witness — and the epoch. It is not
// given the roots the operator published, does not resolve them, and does not
// decide whether anything verified.
//
// That is the whole security argument for this channel. A worker that knows the
// expected answer can report it without doing the work: the operator's roots
// are public, so an idle machine can produce a correct-looking verdict forever,
// and no amount of cross-checking against valid proofs will show it. A worker
// that does NOT know the answer has only one way to produce it. Fabrication
// stops being something to sample for and becomes something that cannot happen.
//
// The consequence is that a worker needs no internet access at all. Everything
// it verifies arrives over the LAN from the witness, which is a smaller attack
// surface and a much simpler machine to lend somebody.
type verifier interface {
	// verify rebuilds the previous and current roots from the proof. It reports
	// no verdict, because it has nothing to compare against.
	verify(ctx context.Context, origin string, epoch int64, proofBase string) (computedPrev, computedCurr string, err error)

	// width is how many logical CPUs one verification occupies.
	//
	// Declared by the thing that does the work rather than guessed by the thing
	// that schedules it. The guess was four — measured against a Rust sidecar
	// this worker no longer runs — and it divided the CPU budget by that, so
	// every machine in the fleet ran at a quarter of its width for a day.
	width() int

	// memoryPerEpoch estimates the peak bytes one verification holds, given the
	// proof sizes seen so far. Zero means nothing has been observed yet and the
	// caller should not apply a memory cap.
	memoryPerEpoch() uint64
}

// akdVerifier replays a Meta or WhatsApp audit proof.
//
// In-process rather than through the Rust sidecar, and that follows from the
// above: the sidecar compares against roots it is handed and answers yes or no,
// which is exactly the shape this design is getting away from. Reporting
// computed roots means computing them, and internal/akdtree does — validated
// against 104 epochs of roots Meta and WhatsApp published, 1000 mutation trials
// and 8.2 million fuzz executions.
//
// The reference implementation still runs, on the witness, where the comparison
// happens and where being wrong would matter.
type akdVerifier struct {
	// largestProof is the biggest proof this verifier has decoded, per the
	// whole worker rather than per origin: the cap has to fit the worst case it
	// is actually being handed.
	largestProof atomic.Uint64
}

// width is one. internal/akdtree is single-threaded — Sort is slices.SortFunc
// and Root is plain recursion, with no goroutine anywhere in the package — so
// one epoch occupies one core. This is a fact about the code rather than a
// tuning constant, which is why it is stated here instead of configured.
func (*akdVerifier) width() int { return 1 }

// memoryPerEpoch derives the footprint from the largest proof seen and the
// sizes of the structures built from it, rather than from a number somebody
// measured once on one machine.
//
// A verification holds: the proof bytes, one Element per node, and the merged
// slice built from them. An Element is 68 bytes and a node occupies roughly 72
// bytes on the wire, so the elements come to about the proof's own size and the
// merge to about the same again — call it three times the proof, which is
// arithmetic from the data structure rather than a guess about hardware.
func (v *akdVerifier) memoryPerEpoch() uint64 {
	largest := v.largestProof.Load()
	if largest == 0 {
		return 0 // nothing seen yet; the caller applies no cap
	}
	return largest * 3
}

func (v *akdVerifier) verify(ctx context.Context, origin string, epoch int64, proofBase string) (string, string, error) {
	if proofBase == "" {
		return "", "", fmt.Errorf("no proof source: this worker does not fetch from the operator")
	}
	// The base already carries this session's token; the worker simply uses the
	// URL it was given.
	url := fmt.Sprintf("%s/%s/%d", strings.TrimSuffix(proofBase, "/"), origin, epoch)
	data, err := fetchProof(ctx, url)
	if err != nil {
		return "", "", fmt.Errorf("fetching the proof: %w", err)
	}

	// Remember the worst case, so the memory cap follows what this worker is
	// actually being asked to do rather than what it was told to expect.
	for {
		prev := v.largestProof.Load()
		if uint64(len(data)) <= prev || v.largestProof.CompareAndSwap(prev, uint64(len(data))) {
			break
		}
	}

	inserted, unchanged, err := akdtree.Decode(data)
	if err != nil {
		return "", "", fmt.Errorf("decoding the proof: %w", err)
	}

	// The previous root comes from the unchanged nodes alone; the current one
	// from those plus the inserted nodes, each committed to this epoch. Which
	// is what an append-only proof asserts.
	akdtree.Sort(unchanged)
	prev, err := akdtree.Root(unchanged)
	if err != nil {
		return "", "", fmt.Errorf("rebuilding the previous root: %w", err)
	}

	both := make([]akdtree.Element, 0, len(unchanged)+len(inserted))
	both = append(both, unchanged...)
	for _, e := range inserted {
		e.Value = akdtree.HashLeafWithCommitment(e.Value, uint64(epoch))
		both = append(both, e)
	}
	akdtree.Sort(both)
	curr, err := akdtree.Root(both)
	if err != nil {
		return "", "", fmt.Errorf("rebuilding the current root: %w", err)
	}

	return hexOf(prev), hexOf(curr), nil
}

func hexOf(d akdtree.Digest) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range d {
		out[2*i] = hexdigits[b>>4]
		out[2*i+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

// fetchProof reads a proof from the witness into memory.
//
// To memory rather than a temp file: nothing else needs the bytes, the decoder
// reads them once, and a worker writing hundreds of megabytes to disk per epoch
// wears out somebody's laptop for no reason.
func fetchProof(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// protonGPUVerifier rebuilds a Proton tree on the GPU.
//
// STATEFUL, and the one place this architecture does not simply generalise. An
// epoch is verified by applying its diff to the tree for the epoch before it,
// so this worker can only do epoch N if it already holds the tree for N-1.
// Ranges must be contiguous, in order, and pinned to the worker holding the
// tree — a laptop cannot pick up where the GPU box left off without first
// downloading 13 GB.
//
// The queue does not model that affinity yet. Until it does, Proton ranges must
// only be offered to this worker, which the origins filter achieves by
// convention rather than by construction.
type protonGPUVerifier struct {
	bin string // kt-proton-gpu
	dir string // where the retained tree and diffs live
}

// width and memoryPerEpoch for the GPU rebuild: the work happens on the card,
// so it occupies about one core of this machine to drive it, and its memory is
// the card's rather than the host's.
func (protonGPUVerifier) width() int             { return 1 }
func (protonGPUVerifier) memoryPerEpoch() uint64 { return 0 }

func (v protonGPUVerifier) verify(ctx context.Context, origin string, epoch int64, _ string) (string, string, error) {
	tree := fmt.Sprintf("%s/epoch_tree_%d.bin", v.dir, epoch)
	cmd := exec.CommandContext(ctx, v.bin, tree)
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", v.bin, err)
	}
	// Proton's rebuild produces one root, for the epoch it just built. There is
	// no previous root to report, so the current one is sent twice rather than
	// inventing a field the witness would have to special-case.
	root := strings.TrimSpace(string(out))
	return root, root, nil
}
