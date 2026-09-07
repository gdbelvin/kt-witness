package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// Taking in construction audits performed somewhere else.
//
// # Why this exists at all
//
// A full Proton rebuild costs about 42 billion SHA-256. On the witness that is
// hours; on a GPU it is a minute. So the rebuild runs elsewhere — but a result
// that lives in a file on another machine changes nothing about what this
// witness claims. Coverage is counted from stored audit records, so until the
// results are in the database, five hundred verified epochs and zero verified
// epochs look exactly the same from outside.
//
// # Why a file and not an endpoint
//
// The obvious shape is an HTTP endpoint the GPU host posts to. That would be a
// mistake. Coverage is what this witness PUBLISHES — it is the basis of the
// tier claim — so an endpoint that accepts audit conclusions is an endpoint
// that lets anything able to reach the port inflate our claims about our own
// work. A file placed by the operator carries exactly the trust of the config
// file next to it, and no more.
//
// # What is checked, because "verified" is not a fact just because a file says so
//
// A record is only recorded as verified when the root it reports actually
// equals the signed root it reports. That single comparison is cheap and it
// means a truncated, corrupted or edited file cannot quietly raise coverage:
// the numbers have to agree with each other before anything is believed.
//
// A record claiming a FAILED construction is imported as a settled but
// unverified epoch and shouted about in the log. It is deliberately not turned
// into a misbehaviour finding here — the witness core owns that decision, and a
// line in a file is not the standard of evidence for accusing an operator.

// ImportedStrategy marks records that came from an offline rebuild rather than
// from this process. It is published in /audits, because a reader deserves to
// know that a conclusion was reached on other hardware.
const ImportedStrategy = "history-gpu"

// backfillResult is the subset of the offline tool's output that matters here.
// Deliberately not a shared type: this end must keep working if the other end
// adds fields.
type backfillResult struct {
	Epoch      int64  `json:"epoch"`
	Verified   bool   `json:"verified"`
	Root       string `json:"root"`
	SignedRoot string `json:"signed_root"`
	Source     string `json:"source"`
	GPUAgreed  bool   `json:"gpu_agreed"`
	Note       string `json:"note"`
}

// seedWatermark reads the epoch manifest beside a results file and tells the
// store how far back the operator's history once reached.
//
// Proton stamps every epoch with StartEpochID — the retention floor in force
// when that epoch was published. The oldest epoch still served therefore says,
// in the operator's own published metadata, how much has already aged out. That
// is a stronger claim than anything this witness could observe on its own: a
// witness that started watching last week has seen nothing expire and would
// otherwise report a shrinking archive as a stable one.
func seedWatermark(db *store.Store, origin, resultsPath string, log *slog.Logger) {
	mf := filepath.Join(filepath.Dir(resultsPath), "manifest.jsonl")
	f, err := os.Open(mf)
	if err != nil {
		return // no manifest beside the results; nothing to learn
	}
	defer f.Close()
	var lowest int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m struct {
			StartEpoch int64 `json:"start_epoch"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.StartEpoch <= 0 {
			continue
		}
		if lowest == 0 || m.StartEpoch < lowest {
			lowest = m.StartEpoch
		}
	}
	if lowest == 0 {
		return
	}
	changed, err := db.LowerHistoryWatermark(origin, lowest)
	if err != nil {
		log.Warn("recording how far the published window once reached", "err", err)
		return
	}
	if changed {
		log.Info("the operator's own metadata says its history once reached further back",
			"origin", origin, "ever_from", lowest,
			"note", "epochs below the current window can no longer be reconstructed by anyone")
	}
}

// ImportStats reports what one pass did.
type ImportStats struct {
	Read      int
	Imported  int
	Skipped   int // already recorded
	Rejected  int // internally inconsistent
	Failures  int // records claiming a construction failure
	Mismatch  int // GPU disagreed with the CPU on the far end
	LastEpoch int64
}

// ImportResults reads an offline backfill's JSONL and records what it can.
//
// Idempotent: a record already stored as verified is skipped, so this can run
// on a timer while the far end is still appending.
func ImportResults(db *store.Store, origin, path string, log *slog.Logger) (ImportStats, error) {
	var st ImportStats
	f, err := os.Open(path)
	if err != nil {
		return st, err
	}
	defer f.Close()

	seedWatermark(db, origin, path, log)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r backfillResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			st.Rejected++
			continue
		}
		st.Read++
		if r.Epoch > st.LastEpoch {
			st.LastEpoch = r.Epoch
		}

		// The record has to agree with itself before it is believed.
		if r.Verified && (r.Root == "" || r.Root != r.SignedRoot) {
			st.Rejected++
			log.Error("refusing an imported audit that claims verified while its own roots differ",
				"origin", origin, "epoch", r.Epoch, "root", r.Root, "signed", r.SignedRoot)
			continue
		}

		if existing, err := db.GetAudit(origin, r.Epoch); err == nil && existing != nil && existing.Verified {
			st.Skipped++
			continue
		}

		if !r.Verified {
			st.Failures++
			log.Error("IMPORTED RECORD REPORTS A FAILED CONSTRUCTION AUDIT — a human must look at this; "+
				"it is recorded as settled-but-unverified and is NOT treated as a fork finding",
				"origin", origin, "epoch", r.Epoch, "note", r.Note)
		}
		if !r.GPUAgreed {
			// The far end already fell back to its CPU and used that answer.
			// Worth surfacing: it means the GPU path produced a wrong root.
			st.Mismatch++
			log.Error("imported record notes the GPU disagreed with the CPU; the CPU result was used",
				"origin", origin, "epoch", r.Epoch, "source", r.Source)
		}

		a := &store.Audit{
			Origin:    origin,
			Epoch:     r.Epoch,
			Sampled:   true,
			Rate:      1,
			Strategy:  ImportedStrategy,
			Verified:  r.Verified,
			Attempts:  1,
			DecidedAt: time.Now().UTC(),
		}
		if err := db.RecordAudit(a); err != nil {
			return st, fmt.Errorf("recording epoch %d: %w", r.Epoch, err)
		}
		st.Imported++
	}
	if err := sc.Err(); err != nil {
		return st, err
	}
	return st, nil
}
