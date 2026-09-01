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
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.start(); err != nil {
		return nil, err
	}

	req, err := json.Marshal(request{
		LogDirectory: logDirectory, Epoch: epoch,
		PrevRoot: prevRoot, CurrRoot: currRoot,
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
