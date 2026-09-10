// Package audit verifies that a transparency log's published tree is
// append-only, epoch by epoch.
package audit

import (
	"context"
	"time"
)

// Result is one epoch's verdict.
//
// Kind is load-bearing: only "verify" means the log's proof was
// cryptographically wrong. "fetch" and "decode" mean we could not check, and
// must never escalate into a public accusation — the difference between a
// network problem and an accusation of forking a key transparency log.
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

// Verifier replays one epoch's append-only proof.
//
// It was an interface so that a single Rust subprocess and a pool of them were
// interchangeable. That subprocess is gone and the interface is not, because
// the auditor still should not know how many verifications can run at once —
// that is a property of the host, not of auditing.
//
// VerifyCached takes a proof already on local disk. That is what lets the link
// run ahead of the CPU: the prefetcher downloads while the verifier works,
// rather than the two taking turns.
type Verifier interface {
	Verify(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot string, timeout time.Duration) (*Result, error)
	VerifyCached(ctx context.Context, logDirectory string, epoch int64, prevRoot, currRoot, proofPath string, timeout time.Duration) (*Result, error)
	Close()
}

var _ Verifier = (*GoVerifier)(nil)
