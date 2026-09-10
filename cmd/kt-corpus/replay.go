package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/source/signal"
)

// replayServer serves the corpus back to the real verifiers over loopback.
//
// This is the trick the whole tool rests on. Neither verifier can be handed a
// slice of bytes: the AKD verifier is a separate Rust process that fetches its
// own proof over HTTP, and Signal's response verification is an unexported step
// inside Source.Fetch. Rewriting either to accept bytes would mean maintaining a
// second copy of the code the corpus is supposed to be testing, at which point
// a passing replay would prove nothing about production.
//
// Serving the artifacts at the paths their providers use costs a few dozen
// lines and leaves the verification path completely untouched.
type replayServer struct {
	corpus *Corpus
	ln     net.Listener
	srv    *http.Server

	mu sync.Mutex
	// signalBlob is the absolute path of the response currently offered at
	// Signal's distinguished endpoint. Replays are sequential, so one slot is
	// enough and it keeps the URL identical to production's.
	signalBlob string
}

// signalPath is the endpoint internal/source/signal fetches. Query parameters
// are ignored on replay: a stored response already contains whatever
// consistency proof it was captured with, and the corpus replays each artifact
// standalone rather than as a continuation of a previous head.
const signalPath = "/v1/key-transparency/distinguished"

func newReplayServer(c *Corpus) (*replayServer, error) {
	// Loopback only. The corpus holds other people's proofs and there is no
	// reason for anything off-host to reach them.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	rs := &replayServer{corpus: c, ln: ln}
	rs.srv = &http.Server{Handler: http.HandlerFunc(rs.handle)}
	go rs.srv.Serve(ln)
	return rs, nil
}

func (rs *replayServer) URL() string { return "http://" + rs.ln.Addr().String() }

func (rs *replayServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return rs.srv.Shutdown(ctx)
}

func (rs *replayServer) setSignalBlob(p string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.signalBlob = p
}

func (rs *replayServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == signalPath {
		rs.mu.Lock()
		p := rs.signalBlob
		rs.mu.Unlock()
		if p == "" {
			http.Error(w, "no signal artifact selected", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, p)
		return
	}

	// Everything else is an AKD proof addressed exactly as CloudFront addresses
	// it. path.Clean plus the prefix check keeps a malformed key from escaping
	// the corpus directory; the verifier builds these keys itself, but a server
	// that trusts its input is a bad habit even on loopback.
	clean := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	full := filepath.Join(rs.corpus.Dir, filepath.FromSlash(clean))
	if !strings.HasPrefix(full, filepath.Clean(rs.corpus.Dir)+string(os.PathSeparator)) {
		http.Error(w, "outside corpus", http.StatusBadRequest)
		return
	}
	fi, err := os.Stat(full)
	if err != nil || fi.IsDir() {
		http.Error(w, "not in corpus", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, full)
}

// Replayer re-verifies stored artifacts using the production code paths.
type Replayer struct {
	corpus   *Corpus
	server   *replayServer
	verifier audit.Verifier
	timeout  time.Duration
}

// NewReplayer re-verifies stored artifacts through the production code path.
//
// It used to take the path to the Rust verifier binary and do nothing without
// one. The verifier is in this process now, so replay always works — which is
// what a corpus is for: an artifact that can only be checked when an external
// binary happens to be present is one nobody checks.
func NewReplayer(c *Corpus, timeout time.Duration) (*Replayer, error) {
	rs, err := newReplayServer(c)
	if err != nil {
		return nil, err
	}
	return &Replayer{corpus: c, server: rs, timeout: timeout,
		verifier: &audit.GoVerifier{}}, nil
}

func (r *Replayer) Close() {
	if r.verifier != nil {
		r.verifier.Close()
	}
	r.server.Close()
}

// Replay re-verifies one artifact and checks the result against the recorded
// expectation.
//
// The order matters. The blob's hash is checked first, so a bit-rotted or
// truncated artifact is reported as a storage problem rather than being blamed
// on the verifier; only then does the real code run, and only then is its
// output compared with what was recorded when the artifact was known good.
func (r *Replayer) Replay(ctx context.Context, m *Manifest) error {
	if err := r.corpus.checkBlob(m); err != nil {
		return fmt.Errorf("blob integrity: %w", err)
	}
	switch m.Kind {
	case KindAKD:
		return r.replayAKD(ctx, m)
	case KindSignal:
		return r.replaySignal(ctx, m)
	default:
		return fmt.Errorf("unknown artifact kind %q", m.Kind)
	}
}

func (r *Replayer) replayAKD(ctx context.Context, m *Manifest) error {
	// The verifier rebuilds the object key from epoch and roots, so pointing it
	// at the corpus's blobs directory makes it fetch exactly the artifact this
	// manifest describes — and a mismatch between the manifest's roots and the
	// stored blob's path shows up as a fetch failure rather than a false pass.
	dir := r.server.URL() + "/" + path.Join(string(KindAKD), slug(m.Origin), "blobs")
	res, err := r.verifier.Verify(ctx, dir, m.Seq, m.PrevRoot, m.CurrRoot, r.timeout)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("%s: %s", res.Kind, res.Error)
	}
	if res.Epoch != m.Seq {
		return fmt.Errorf("verified epoch %d, manifest records %d", res.Epoch, m.Seq)
	}
	return nil
}

func (r *Replayer) replaySignal(ctx context.Context, m *Manifest) error {
	r.server.setSignalBlob(filepath.Join(r.corpus.Dir, filepath.FromSlash(m.Blob)))
	src, err := signal.New(signal.Config{Origin: m.Origin, Endpoint: r.server.URL()})
	if err != nil {
		return err
	}
	// Fetch is the whole chain: auditor signatures, the derived service root,
	// the VRF, the prefix tree, the batch inclusion proof and the commitment.
	// The corpus keeps Signal artifacts precisely because that is the newest and
	// most intricate code in the project and it costs 490 KB to exercise.
	head, err := src.Fetch(ctx, nil)
	if err != nil {
		return err
	}
	if head.Size != m.Seq {
		return fmt.Errorf("verified tree size %d, manifest records %d", head.Size, m.Seq)
	}
	if got := hex.EncodeToString(head.Hash[:]); got != m.Root {
		return fmt.Errorf("verified root %s, manifest records %s", got, m.Root)
	}
	if s := src.LastSearch(); s == nil {
		return fmt.Errorf("no search proof was verified")
	}
	return nil
}
