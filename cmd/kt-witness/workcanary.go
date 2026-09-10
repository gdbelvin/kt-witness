package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/work"
	"github.com/gdbsecurity/kt-witness/internal/workrpc"
)

// The canary a remote worker gets, and where its bytes come from.
//
// Every other check on a worker's result establishes that it answers work we
// handed out. None of them can tell whether any verification happened, because
// the operator's signed root is public and a worker that did nothing can report
// it. This is the one test that asks a question a silent worker gets wrong: a
// proof with a bit flipped, offered as ordinary work, which it must refuse.
//
// The bytes are one this witness already fetched and verified. That matters for
// a reason beyond thrift — a canary built from a proof we have not checked
// ourselves could be rejected for a reason that has nothing to do with the bit
// we flipped, and a canary that might legitimately fail proves nothing when it
// does.

type canaryMinter struct {
	q       *work.Queue
	proofs  *workrpc.ProofServer
	host    string // what a worker should dial to reach the proof server
	log     *slog.Logger
	dir     string
	every   int
	pending int
}

// offerCanary corrupts a verified proof and queues it as a single-epoch
// assignment. Called by the audit path, which is the only place holding a proof
// that has just been checked.
func (m *canaryMinter) offerCanary(origin string, epoch int64, prevRoot, currRoot, proofPath string) {
	if m == nil || m.proofs == nil {
		return
	}
	data, err := os.ReadFile(proofPath)
	if err != nil || len(data) == 0 {
		return
	}

	// One bit, uniformly. Same rule as the in-process canary, for the same
	// reason: a verifier that checks structure but skips a hash catches a
	// mangled file and passes the forgery that matters.
	byteAt, err1 := rand.Int(rand.Reader, big.NewInt(int64(len(data))))
	bitAt, err2 := rand.Int(rand.Reader, big.NewInt(8))
	if err1 != nil || err2 != nil {
		return
	}
	data[byteAt.Int64()] ^= byte(1) << uint(bitAt.Int64())

	f, err := os.CreateTemp(m.dir, "kt-canary-serve-*.bin")
	if err != nil {
		return
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()

	url, err := m.proofs.Offer(f.Name(), m.host)
	if err != nil {
		os.Remove(f.Name())
		return
	}
	id := m.q.AddCanary(origin, epoch, url)
	metrics.Inc("kt_witness_worker_canary_sent_total", nil)
	m.log.Info("canary queued for a remote worker", "assignment", id,
		"origin", origin, "epoch", epoch,
		"corrupted", fmt.Sprintf("byte %d/%d bit %d", byteAt.Int64(), len(data), bitAt.Int64()))
}

// checkCanary is called for every result. It reports whether the result was a
// canary, so the caller knows not to record it as an audit: a canary's verdict
// is about the worker, not about the log, and writing "unverified" for an epoch
// that verifies fine would put a false hole in the coverage.
func checkCanary(q *work.Queue, r work.Result, log *slog.Logger) bool {
	isCanary, caught := q.CanaryVerdict(r)
	if !isCanary {
		return false
	}
	if caught {
		metrics.Inc("kt_witness_worker_canary_caught_total", map[string]string{"worker": r.Worker})
		log.Info("worker caught a canary", "worker", r.Worker,
			"origin", r.Origin, "epoch", r.Epoch, "reported", r.Err)
		return true
	}
	metrics.Inc("kt_witness_worker_canary_missed_total", map[string]string{"worker": r.Worker})
	log.Error("A WORKER PASSED A CORRUPTED PROOF AS VERIFIED — it is not verifying "+
		"anything, and every result it has reported must be treated as unproven. "+
		"Stop giving it work and re-audit what it claimed",
		"worker", r.Worker, "origin", r.Origin, "epoch", r.Epoch,
		"assignment", r.AssignmentID, "root_it_reported", r.Root)
	return true
}

// startCanaryFeed publishes how many canaries are outstanding.
//
// Minting happens elsewhere — one is offered each time the in-process canary
// fires, which is where a freshly verified proof is in hand. What this watches
// is the gap between sending one and hearing back: a worker that takes canaries
// and never answers is as much a problem as one that answers wrongly, and
// nothing else would show it.
func startCanaryFeed(ctx context.Context, m *canaryMinter) {
	if m == nil {
		return
	}
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			// Outstanding canaries are a signal in themselves: a worker that
			// takes them and never answers is as much a problem as one that
			// answers wrongly, and it should not be masked by piling on more.
			if n := m.q.PendingCanaries(); n > 3 {
				m.log.Warn("canaries outstanding; not queueing more", "pending", n)
				metrics.Set("kt_witness_worker_canary_pending", nil, float64(n))
				continue
			}
			metrics.Set("kt_witness_worker_canary_pending", nil, float64(m.q.PendingCanaries()))
		}
	}()
}
