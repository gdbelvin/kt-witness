package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
	// Threads caps the sidecar's runtime. Zero lets it size itself from the
	// machine, which is only correct when exactly one is running.
	Threads int

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

// NewSidecarWithThreads bounds one worker's runtime.
//
// Left unbounded, the sidecar sizes its thread pool from the machine's core
// count and ignores how many of itself are running. On the witness that meant
// three concurrent verifications asking for ninety-six threads on
// thirty-two cores: measured load average 55, and a box spending its time
// switching between threads instead of hashing. The pool is what decides how
// many run at once; this is what decides how wide each one is, and the two
// have to be set together or neither is a bound.
func NewSidecarWithThreads(path string, threads int) *Sidecar {
	return &Sidecar{Path: path, Threads: threads}
}

func (s *Sidecar) start() error {
	if s.cmd != nil && s.cmd.Process != nil {
		return nil
	}
	cmd := exec.Command(s.Path)
	if s.Threads > 0 {
		cmd.Env = append(os.Environ(), fmt.Sprintf("KT_AKD_THREADS=%d", s.Threads))
	}
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

	// threads is how wide each worker may be; reported so the operator can see
	// the two halves of the bound together.
	threads int

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
	// Divide the machine between the workers rather than giving each one all of
	// it. Unbounded, every sidecar sizes its runtime from the core count, so a
	// pool of eight asks for eight times the machine — measured on the witness:
	// three concurrent verifications, ninety-six threads, thirty-two cores, and
	// a load average of 55 spent switching between them rather than hashing.
	//
	// Two threads minimum: below that the runtime cannot overlap a download
	// with the hashing of what already arrived, which is most of what the
	// parallelism inside one epoch is for.
	threads := runtime.NumCPU() / n
	if threads < 2 {
		threads = 2
	}
	p := &Pool{free: make(chan *Sidecar, n), threads: threads}
	for i := 0; i < n; i++ {
		s := NewSidecarWithThreads(path, threads)
		p.all = append(p.all, s)
		p.free <- s
	}
	return p
}

// Size reports how many verifications may run at once.
func (p *Pool) Size() int { return cap(p.free) }

// Threads reports how wide each verification may be.
func (p *Pool) Threads() int { return p.threads }

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
