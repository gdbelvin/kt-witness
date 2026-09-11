package audit

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
)

// GoVerifier replays AKD proofs in this process.
//
// # Why the witness would run this
//
// It replaced a Rust subprocess built on facebook/akd — the reference
// implementation — which was slow for a structural
// reason: it builds the tree through a storage abstraction meant for a real
// database, so verifying one Meta epoch performs millions of async map writes
// and allocates a node object for each. Measured on identical epochs, this
// package costs about an eighth of the CPU and a fraction of the memory.
//
// The memory mattered as much as the speed. That pool was capped at eight
// because one Rust verification peaks near 3.7 GB, and that cap — not the
// machine's 32 cores — has been the binding constraint on this witness's
// throughput. A verification here holds the proof and a flat array of its
// nodes, so the ceiling moves from memory to cores, and then to bandwidth.
//
// # What justifies trusting it alone
//
// For most of this project's life the answer was "it does not run alone" — the
// Rust reference decided and this was only observed. That is no longer true, so
// the evidence has to carry the whole weight, and it is worth being explicit
// about what it is.
//
// The strongest part is not in the test suite. Every epoch this fleet verifies
// is a check on this code: a worker rebuilds both roots and is never told what
// they should be, and the witness compares them against what the operator
// published. An implementation that was wrong would disagree with Meta or
// WhatsApp on the first epoch it touched. That is continuous, unsampled, and
// against an independent party — which no second implementation of ours could
// be.
//
// Behind that: 104 epochs agreeing with published roots, 1000 mutation trials
// and 8.2 million fuzz executions requiring that a single flipped bit is
// rejected, and a period of running beside the reference and agreeing.
//
// A verifier wrong in the accepting direction approves a forged proof; one
// wrong in the rejecting direction accuses an honest operator of forking a key
// transparency log, publicly and permanently. Both are worse than being slow,
// which is why the speed was never the argument.
type GoVerifier struct {
	// Concurrent bounds how many verifications run at once. Zero derives it
	// from the machine.
	Concurrent int

	// Client fetches proofs the caller has not already cached. Nil uses a
	// default with a generous timeout: a Meta proof is ~280 MB.
	Client *http.Client

	once sync.Once
	sem  chan struct{}
}

func (g *GoVerifier) init() {
	g.once.Do(func() {
		n := g.Concurrent
		if n <= 0 {
			// One per core, less two. Unlike the old process pool this is a CPU
			// bound rather than a memory one: a verification here holds the
			// proof plus a flat node array — hundreds of megabytes, not
			// gigabytes — so cores run out first.
			n = runtime.NumCPU() - 2
			if n < 1 {
				n = 1
			}
		}
		g.sem = make(chan struct{}, n)
		if g.Client == nil {
			g.Client = &http.Client{Timeout: 20 * time.Minute}
		}
	})
}

// Size reports the concurrency limit, for the same logging the pool feeds.
func (g *GoVerifier) Size() int {
	g.init()
	return cap(g.sem)
}

func (g *GoVerifier) Verify(ctx context.Context, origin, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return g.VerifyCached(ctx, origin, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

func (g *GoVerifier) VerifyCached(ctx context.Context, origin, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	g.init()

	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := &Result{Epoch: epoch}

	// Read or fetch. A cached proof belongs to whoever cached it and is left
	// alone; a downloaded one is held only as long as this verification.
	t := time.Now()
	var data []byte
	var err error
	if proofPath != "" {
		data, err = os.ReadFile(proofPath)
		if err != nil {
			return fetchFailure(res, fmt.Sprintf("read cached proof %s: %v", proofPath, err)), nil
		}
	} else {
		url := fmt.Sprintf("%s/%d/%s/%s", strings.TrimSuffix(logDirectory, "/"), epoch, prevRoot, currRoot)
		data, err = g.fetch(ctx, origin, url)
		if err != nil {
			return fetchFailure(res, err.Error()), nil
		}
	}
	res.DownloadMS = time.Since(t).Milliseconds()
	res.Bytes = int64(len(data))

	t = time.Now()
	inserted, unchanged, err := akdtree.Decode(data)
	if err != nil {
		res.OK, res.Kind, res.Error = false, "decode", err.Error()
		return res, nil
	}
	res.DecodeMS = time.Since(t).Milliseconds()

	prev, err := akdtree.ParseDigest(prevRoot)
	if err != nil {
		return fetchFailure(res, "prev_root is not a 64-character hex digest"), nil
	}
	curr, err := akdtree.ParseDigest(currRoot)
	if err != nil {
		return fetchFailure(res, "curr_root is not a 64-character hex digest"), nil
	}

	t = time.Now()
	var v akdtree.Verifier
	ok, err := v.VerifyAppendOnly(unchanged, inserted, prev, curr, uint64(epoch))
	res.VerifyMS = time.Since(t).Milliseconds()
	if err != nil {
		// Could not reach a verdict — a malformed proof, not a misbehaving log.
		// The distinction is load-bearing: "verify" triggers a permanent public
		// accusation and this is not that.
		res.OK, res.Kind, res.Error = false, "decode", err.Error()
		return res, nil
	}
	if !ok {
		res.OK, res.Kind = false, "verify"
		res.Error = "the proof does not rebuild the roots the operator published"
		return res, nil
	}
	res.OK = true
	return res, nil
}

// ComputeRoots rebuilds both roots from the proof and reports them, without
// being told what to expect.
//
// This is what the distributed audit runs on, and the witness's own local
// worker needs it for the same reason every remote worker does: a machine that
// is handed the published roots and answers yes or no has been told the answer.
// The local worker used to call the Rust reference — whose whole API is that
// yes/no —
// and then report the PUBLISHED current root as both of its computed roots. Its
// every success therefore came back as a mismatch against the published
// previous root, was recorded unverified, and was re-queued.
//
// prevRoot and currRoot are still taken, but only to build the fetch URL when
// there is no cached proof: the operator's directory is addressed by them. They
// have no part in the answer.
func (g *GoVerifier) ComputeRoots(ctx context.Context, origin, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (computedPrev, computedCurr string, err error) {
	g.init()

	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	case <-ctx.Done():
		return "", "", ctx.Err()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var data []byte
	if proofPath != "" {
		data, err = os.ReadFile(proofPath)
		if err != nil {
			return "", "", fmt.Errorf("read cached proof %s: %w", proofPath, err)
		}
	} else {
		url := fmt.Sprintf("%s/%d/%s/%s", strings.TrimSuffix(logDirectory, "/"), epoch, prevRoot, currRoot)
		data, err = g.fetch(ctx, origin, url)
		if err != nil {
			return "", "", err
		}
	}

	inserted, unchanged, err := akdtree.Decode(data)
	if err != nil {
		return "", "", fmt.Errorf("decoding the proof: %w", err)
	}
	var v akdtree.Verifier
	prev, curr, err := v.Roots(unchanged, inserted, uint64(epoch))
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(prev[:]), hex.EncodeToString(curr[:]), nil
}

// fetchFailure marks a result as "we could not check", never as "the log
// misbehaved". Conflating those is how a network problem becomes a public
// accusation.
func fetchFailure(res *Result, msg string) *Result {
	res.OK, res.Kind, res.Error = false, "fetch", msg
	return res
}

func (g *GoVerifier) fetch(ctx context.Context, origin, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	data, err := io.ReadAll(netmeter.Reader(ctx, origin, resp.Body))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty proof body from %s", url)
	}
	return data, nil
}

// Close exists so this satisfies Verifier. There is no subprocess to stop,
// which is most of the point.
func (g *GoVerifier) Close() {}
