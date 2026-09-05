package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Sidecar drives the Rust kt-akd-verify binary.
//
// AKD proof verification lives in Rust because that is where facebook/akd is;
// reimplementing it in Go would be a large project with its own bug surface,
// and a second implementation of a verifier is only valuable if it is correct.
// The process is long-running and reused across epochs, since startup is
// negligible next to a ~24 s verification but the contract is simpler than a
// pool.
type Sidecar struct {
	Path string

	mu     sync.Mutex // one verification at a time: each peaks ~3.7 GB RSS
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Reader
}

type request struct {
	LogDirectory string `json:"log_directory"`
	Epoch        int64  `json:"epoch"`
	PrevRoot     string `json:"prev_root"`
	CurrRoot     string `json:"curr_root"`

	// ProofPath, when set, is a proof already on local disk. The sidecar reads
	// it instead of downloading, which is what lets the link run ahead of the
	// CPU rather than taking turns with it.
	ProofPath string `json:"proof_path,omitempty"`
}

// Result is the sidecar's verdict.
//
// Kind is load-bearing: only "verify" means the log's proof was cryptographically
// wrong. "fetch" and "decode" mean we could not check, and must never escalate
// into a public accusation.
type Result struct {
	OK    bool   `json:"ok"`
	Epoch int64  `json:"epoch"`
	Error string `json:"error"`
	Kind  string `json:"kind"`

	DownloadMS int64 `json:"download_ms"`
	DecodeMS   int64 `json:"decode_ms"`
	VerifyMS   int64 `json:"verify_ms"`
	Bytes      int64 `json:"bytes"`
}

// VerificationFailed reports whether this result is evidence the log built its
// tree incorrectly, as opposed to us being unable to check.
func (r *Result) VerificationFailed() bool {
	return !r.OK && r.Kind == "verify"
}

func NewSidecar(path string) *Sidecar { return &Sidecar{Path: path} }

func (s *Sidecar) start() error {
	if s.cmd != nil && s.cmd.Process != nil {
		return nil
	}
	cmd := exec.Command(s.Path)
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sidecar: start %s: %w", s.Path, err)
	}
	s.cmd = cmd
	s.stdin = bufio.NewWriter(in)
	// Responses are small, but the reader must outlive large pauses.
	s.stdout = bufio.NewReaderSize(out, 1<<16)
	return nil
}

// stop tears down a sidecar that has become unusable, so the next call restarts
// it rather than writing into a dead pipe.
func (s *Sidecar) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}
	s.cmd, s.stdin, s.stdout = nil, nil, nil
}

func (s *Sidecar) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

// Verify replays one epoch's construction proof.
//
// timeout must comfortably exceed a real verification (~30 s end to end for
// Meta); on timeout the sidecar is killed rather than left mid-proof, because a
// half-consumed stdout stream would desynchronise every later request.
func (s *Sidecar) Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return s.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

// VerifyCached replays a proof, reading it from proofPath when that is set
// rather than downloading it.
func (s *Sidecar) VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.start(); err != nil {
		return nil, err
	}

	req, err := json.Marshal(request{
		LogDirectory: logDirectory, Epoch: epoch,
		PrevRoot: prevRoot, CurrRoot: currRoot, ProofPath: proofPath,
	})
	if err != nil {
		return nil, err
	}
	if _, err := s.stdin.Write(append(req, '\n')); err != nil {
		s.stop()
		return nil, fmt.Errorf("sidecar: write: %w", err)
	}
	if err := s.stdin.Flush(); err != nil {
		s.stop()
		return nil, fmt.Errorf("sidecar: flush: %w", err)
	}

	type reply struct {
		res *Result
		err error
	}
	ch := make(chan reply, 1)
	go func() {
		line, err := s.stdout.ReadBytes('\n')
		if err != nil {
			ch <- reply{nil, fmt.Errorf("sidecar: read: %w", err)}
			return
		}
		var r Result
		if err := json.Unmarshal(line, &r); err != nil {
			ch <- reply{nil, fmt.Errorf("sidecar: decode reply %q: %w", line, err)}
			return
		}
		ch <- reply{&r, nil}
	}()

	select {
	case <-ctx.Done():
		s.stop()
		return nil, ctx.Err()
	case <-time.After(timeout):
		s.stop()
		return nil, fmt.Errorf("sidecar: epoch %d timed out after %s", epoch, timeout)
	case r := <-ch:
		if r.err != nil {
			s.stop()
			return nil, r.err
		}
		return r.res, nil
	}
}

// Verifier is what the auditor needs from a sidecar: replay one epoch's proof.
//
// It exists so a single process and a pool of them are interchangeable. The
// auditor should not know or care how many verifications can run at once; that
// is a deployment question about how much memory the host has, not a property
// of auditing.
type Verifier interface {
	Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error)
	VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error)
	Close()
}

var (
	_ Verifier = (*Sidecar)(nil)
	_ Verifier = (*Pool)(nil)
)

// Pool runs several sidecar processes so verifications can overlap.
//
// # Why processes and not goroutines
//
// The sidecar speaks one request per line over a single stdin/stdout pair, so a
// process can only ever have one verification in flight — the mutex inside
// Sidecar is not a policy choice, it is the protocol. Concurrency therefore
// means more processes, and the pool is the smallest thing that provides them.
//
// # Why the size is a deployment decision
//
// Each verification peaks near 3.7 GB RSS for Meta. The right number is
// (available memory / peak) with headroom, and getting it wrong is not a
// slowdown but an OOM kill of the whole witness, taking equivocation detection
// down with it. So it is configured rather than inferred, defaults to 1, and
// the operator raises it having looked at the box.
type Pool struct {
	free chan *Sidecar

	// all is kept so Close can reach every worker, including any currently
	// checked out — those are returned to free before Close is reachable in
	// practice, but relying on that would make shutdown depend on timing.
	all []*Sidecar
}

// NewPool builds n sidecar workers. n < 1 is treated as 1: a pool of zero would
// deadlock on first use, and silently disabling auditing is never the behaviour
// a misconfiguration should produce.
func NewPool(path string, n int) *Pool {
	if n < 1 {
		n = 1
	}
	p := &Pool{free: make(chan *Sidecar, n)}
	for i := 0; i < n; i++ {
		s := NewSidecar(path)
		p.all = append(p.all, s)
		p.free <- s
	}
	return p
}

// Size reports how many verifications may run at once.
func (p *Pool) Size() int { return cap(p.free) }

// Verify checks out a worker, runs one verification, and returns the worker.
//
// A worker is returned even when the verification failed and the process was
// killed: Sidecar.start restarts a dead process on next use, so a crashed
// worker heals rather than permanently shrinking the pool. Losing capacity to
// transient failures would degrade the witness quietly over days.
func (p *Pool) Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error) {
	return p.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, "", timeout)
}

// VerifyCached checks out a worker and verifies, optionally from a cached file.
func (p *Pool) VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s := <-p.free:
		defer func() { p.free <- s }()
		return s.VerifyCached(ctx, logDirectory, epoch, prevRoot, currRoot, proofPath, timeout)
	}
}

func (p *Pool) Close() {
	for _, s := range p.all {
		s.Close()
	}
}
