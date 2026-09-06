//go:build unix

package proton

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
)

// Running Proton's construction audit inside the witness process.
//
// # Why this is worth the machinery
//
// Proton is the only deployment here that publishes its whole directory, so it
// is the only one where a third party can rebuild the tree and check it against
// the signed root. That is tier B in its strongest form, and until now it
// existed only as a command someone ran by hand — which means the running
// witness was asserting A+ while the evidence for B sat in a terminal
// somewhere.
//
// # The shape of the problem
//
// The audit is not a request. It is: keep a 13.6 GB tree of ~200 million
// leaves, fetch the ~3 MB diff for the next epoch, apply it, rebuild the root
// over the merged result, and compare against the hash Proton signed. That
// takes about nineteen minutes against a four-hour epoch cadence, so it fits
// comfortably — but only if the tree is RETAINED between epochs. Re-downloading
// 13.6 GB each time would turn a 3 MB job into a 13.6 GB one, which is the
// difference between affordable and not.
//
// So this holds state on disk deliberately, and everything below is about
// holding it safely: never filling the volume, never leaving a half-written
// tree that would rebuild to a wrong root, and never blocking the witness loop
// that has to stay responsive to catch equivocation.

// EpochMeta is the published metadata an audit checks against: the tree hash
// Proton signed for the target epoch, and the oldest epoch it still retains.
type EpochMeta struct {
	TreeHash     string
	StartEpochID int64
}

// IncrementalAuditor replays the step between two Proton epochs.
type IncrementalAuditor struct {
	// Dir holds the retained tree. It needs room for two: the base and the
	// merged output, about 28 GB.
	Dir string

	// APIBase and DumpBase locate epoch metadata and the published dumps.
	APIBase  string
	DumpBase string

	// ShardDepth splits the top N levels of the rebuild across cores.
	ShardDepth int

	// Replay names which replay this is — "tip" or "history" — so their
	// progress is reported separately. They are separate trees making separate
	// progress, and reporting them as one would hide exactly the case that
	// occurred: the tip advancing while history sat wedged.
	Replay string

	// MinFreeBytes is the floor below which an audit refuses to start. Filling
	// the volume would take the witness down with it, and a witness that is not
	// running is not witnessing — a far worse outcome than an unaudited epoch.
	MinFreeBytes uint64

	Client *http.Client
}

// AuditResult is what one replayed step established.
type AuditResult struct {
	From, To     int64
	Leaves       int64
	Stats        *DiffStats
	Removals     *RemovalReport
	ExpectedRoot string
	ComputedRoot string
	Match        bool
	Elapsed      time.Duration
}

const (
	defaultShardDepth  = 10
	defaultMinFree     = 40 << 30 // 40 GiB: two trees plus slack
	protonRecordLength = 68
)

func (a *IncrementalAuditor) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: 60 * time.Minute}
}

func (a *IncrementalAuditor) treePath(epoch int64) string {
	return filepath.Join(a.Dir, fmt.Sprintf("epoch_tree_%d.bin", epoch))
}

// Base reports the epoch whose tree is currently retained, or 0 if none is.
//
// The witness uses this to decide whether the next audit is a cheap step or an
// expensive cold start, which is the difference between 3 MB and 13.6 GB.
func (a *IncrementalAuditor) Base() (int64, error) {
	entries, err := os.ReadDir(a.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var best int64
	for _, e := range entries {
		// Sscanf does not require the whole name to be consumed, so
		// "epoch_tree_300.bin.partial" would otherwise match as epoch 300 — an
		// in-progress download picked up as a finished tree.
		name := e.Name()
		if !strings.HasSuffix(name, ".bin") {
			continue
		}
		var epoch int64
		if _, err := fmt.Sscanf(name, "epoch_tree_%d.bin", &epoch); err != nil {
			continue
		}
		// A file of the wrong length is a truncated download, not a tree. It
		// would rebuild to a wrong root and look like Proton misbehaving.
		if fi, err := e.Info(); err != nil || fi.Size() == 0 || fi.Size()%protonRecordLength != 0 {
			continue
		}
		if epoch > best {
			best = epoch
		}
	}
	return best, nil
}

// freeBytes reports space available on the volume holding Dir.
func (a *IncrementalAuditor) freeBytes() (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(a.Dir, &st); err != nil {
		return 0, err
	}
	// Bavail, not Bfree: the reserved blocks are not ours to spend.
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// Step audits the transition from the retained tree to the target epoch.
//
// It is deliberately one step at a time. A backlog is caught up one epoch per
// call rather than in a loop, so the caller keeps control of how much of the
// machine this consumes and can stop between steps.
func (a *IncrementalAuditor) Step(ctx context.Context, from, to int64, meta *EpochMeta) (*AuditResult, error) {
	// One rebuild at a time, process-wide. See stepMu.
	//
	// Waiting is reported before the lock is taken, not after. A replay blocked
	// here emits no log line and, until this call, set no phase — so the whole
	// history replay could sit behind the tip for hours and look, from every
	// exported signal, exactly like a replay that was never configured. That is
	// precisely how it looked while this was being diagnosed.
	SetPhase(a.Replay, PhaseWaiting, to)
	stepMu.Lock()
	defer stepMu.Unlock()

	// Cores this rebuild is about to occupy, declared for as long as it holds
	// the lock so the audit governor can subtract them from its own budget
	// instead of scheduling against them.
	claimCores(treeWorkers())
	defer releaseCores()

	stepStart := time.Now()
	defer func() {
		l := map[string]string{"replay": a.Replay}
		metrics.Add("kt_witness_proton_step_seconds_sum", l, time.Since(stepStart).Seconds())
		metrics.Add("kt_witness_proton_step_total", l, 1)
	}()

	if a.ShardDepth == 0 {
		a.ShardDepth = defaultShardDepth
	}
	if a.MinFreeBytes == 0 {
		a.MinFreeBytes = defaultMinFree
	}
	if err := os.MkdirAll(a.Dir, 0o755); err != nil {
		return nil, err
	}
	if free, err := a.freeBytes(); err == nil && free < a.MinFreeBytes {
		return nil, fmt.Errorf(
			"proton: %d bytes free below the %d floor; refusing to audit. "+
				"Filling this volume would stop the witness, and a witness that is "+
				"not running is worse than an unaudited epoch",
			free, a.MinFreeBytes)
	}

	base := a.treePath(from)
	fi, err := os.Stat(base)
	if err != nil {
		return nil, fmt.Errorf("proton: no retained tree for epoch %d: %w", from, err)
	}
	if fi.Size()%protonRecordLength != 0 {
		return nil, fmt.Errorf("proton: retained tree for %d is %d bytes, not a whole "+
			"number of %d-byte leaves", from, fi.Size(), protonRecordLength)
	}

	SetPhase(a.Replay, PhaseFetch, to)
	diff, err := a.fetch(ctx, fmt.Sprintf("%s/epoch.1.%d.diff", a.DumpBase, to))
	if err != nil {
		SetPhase(a.Replay, PhaseIdle, to)
		return nil, err
	}

	baseData, closeBase, err := mapFile(base)
	if err != nil {
		return nil, err
	}
	defer closeBase()

	SetPhase(a.Replay, PhaseApply, to)
	start := time.Now()
	// Written to a temporary name and renamed only on success: an interrupted
	// merge must never leave a file that Base() would pick up as a tree, since
	// it would rebuild to a wrong root and read as Proton misbehaving.
	tmp := a.treePath(to) + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(out, 1<<22)
	stats, err := ApplyDiff(SliceLeaves(baseData), diff, func(label, value []byte) error {
		if _, err := w.Write(label); err != nil {
			return err
		}
		_, err := w.Write(value)
		return err
	})
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := w.Flush(); err != nil {
		out.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}

	merged, closeMerged, err := mapFile(tmp)
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	SetPhase(a.Replay, PhaseHash, to)
	root, err := TreeRootParallel(SliceLeaves(merged), a.ShardDepth)
	closeMerged()
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}

	res := &AuditResult{
		From: from, To: to,
		Leaves:       int64(len(merged) / protonRecordLength),
		Stats:        stats,
		ExpectedRoot: meta.TreeHash,
		ComputedRoot: hex.EncodeToString(root),
		Elapsed:      time.Since(start),
	}
	res.Match = res.ComputedRoot == res.ExpectedRoot
	res.Removals = JudgeRemovals(stats, to, meta.StartEpochID)

	if !res.Match {
		// Keep the evidence. A mismatch is the strongest finding this project
		// can produce and it must be reproducible by someone else.
		os.Rename(tmp, a.treePath(to)+".mismatch")
		return res, &MismatchError{
			From: from, To: to,
			Computed: res.ComputedRoot, Signed: res.ExpectedRoot,
		}
	}

	if err := os.Rename(tmp, a.treePath(to)); err != nil {
		return res, err
	}
	// The old base is only removed once its successor is safely in place, so an
	// interruption always leaves at least one usable tree.
	os.Remove(base)
	SetPhase(a.Replay, PhaseIdle, to)
	return res, nil
}

// fetch retrieves a published artifact.
func (a *IncrementalAuditor) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			// Proton answers 403 for a diff it has not published yet — the diff
			// lags the epoch it belongs to by a little. Observed directly:
			// epoch 6725 returned 403 and then 200 about a minute later.
			//
			// So this is the ordinary state of being caught up, not a fault. It
			// gets its own error so the caller can wait quietly instead of
			// warning every time the auditor reaches the tip.
			return nil, &NotYetPublishedError{URL: url, Status: resp.StatusCode}
		}
		return nil, fmt.Errorf("proton: GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<30))
}

// Bootstrap downloads a full tree, for the cold start where nothing is
// retained. It is ~13.6 GB and about eight minutes, which is why the whole
// design works to avoid needing it more than once.
func (a *IncrementalAuditor) Bootstrap(ctx context.Context, epoch int64) error {
	SetPhase(a.Replay, PhaseBootstrp, epoch)
	defer SetPhase(a.Replay, PhaseIdle, epoch)

	if err := os.MkdirAll(a.Dir, 0o755); err != nil {
		return err
	}
	if free, err := a.freeBytes(); err == nil && free < a.MinFreeBytes {
		return fmt.Errorf("proton: %d bytes free below the %d floor; refusing to bootstrap",
			free, a.MinFreeBytes)
	}
	url := fmt.Sprintf("%s/epoch.1.%d", a.DumpBase, epoch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proton: GET %s: HTTP %d", url, resp.StatusCode)
	}

	tmp := a.treePath(epoch) + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if n == 0 || n%protonRecordLength != 0 {
		os.Remove(tmp)
		return fmt.Errorf("proton: dump for %d is %d bytes, not a whole number of "+
			"%d-byte leaves", epoch, n, protonRecordLength)
	}
	// Renamed only once complete, so an interrupted download never becomes a
	// tree that rebuilds to a wrong root.
	return os.Rename(tmp, a.treePath(epoch))
}

func mapFile(path string) ([]byte, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if fi.Size() == 0 || fi.Size()%protonRecordLength != 0 {
		f.Close()
		return nil, nil, fmt.Errorf("proton: %s is %d bytes, not a whole number of "+
			"%d-byte leaves", path, fi.Size(), protonRecordLength)
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(fi.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("proton: mmap %s: %w", path, err)
	}
	return data, func() { syscall.Munmap(data); f.Close() }, nil
}

// FetchEpochMeta reads the published metadata for one epoch: the tree hash
// Proton signed, and the oldest epoch that epoch still retains.
//
// Taken per-epoch rather than from the tip, because the retention window moves:
// epoch 6300 names a different StartEpochID than today's, and judging a
// removal against the wrong window would produce a false unexplained removal.
func (a *IncrementalAuditor) FetchEpochMeta(ctx context.Context, epoch int64) (*EpochMeta, error) {
	body, err := a.fetch(ctx, fmt.Sprintf("%s/kt/v1/epochs/%d", a.APIBase, epoch))
	if err != nil {
		return nil, err
	}
	var m struct {
		TreeHash     string `json:"TreeHash"`
		StartEpochID int64  `json:"StartEpochID"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("proton: epoch %d metadata: %w", epoch, err)
	}
	if m.TreeHash == "" {
		return nil, fmt.Errorf("proton: epoch %d has no tree hash", epoch)
	}
	return &EpochMeta{TreeHash: m.TreeHash, StartEpochID: m.StartEpochID}, nil
}

// MismatchError is the one Proton failure that is evidence of misconstruction:
// the retained tree plus the published diff does not rebuild the root Proton
// signed.
//
// It exists as a type so callers can tell it apart from the far more common
// case of not being able to check at all. A fetch that returns 403, a truncated
// download, a full disk — none of those say anything about how Proton built its
// tree, and reporting them in the same breath as a real mismatch is how an
// honest operator gets accused of misbehaviour. That mistake has already been
// made once here, against the Go checksum database.
type MismatchError struct {
	From, To int64
	Computed string
	Signed   string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf(
		"proton: epoch %d plus its published diff does not build epoch %d: computed %s, Proton signed %s",
		e.From, e.To, e.Computed, e.Signed)
}

// NotYetPublishedError is a diff Proton has not made available yet.
//
// Distinct from both a mismatch and a genuine fetch failure: nothing is wrong,
// the auditor has simply caught up with what has been published. Treating it as
// an error produced a warning every time the sweep reached the tip, which is
// the fastest way to teach an operator to ignore warnings.
type NotYetPublishedError struct {
	URL    string
	Status int
}

func (e *NotYetPublishedError) Error() string {
	return fmt.Sprintf("proton: %s is not published yet (HTTP %d)", e.URL, e.Status)
}

// stepMu serialises tree rebuilds across every IncrementalAuditor in the
// process.
//
// The tip replay and the history replay operate on separate trees and look
// independent, so they were left to run concurrently. They are not independent
// in the two resources that matter.
//
// Memory: each rebuild memory-maps its whole tree, so two at once held 26.7 GB
// of a 44 GB container limit. The cgroup hit its ceiling 30,596 times, and
// every one of those reclaims evicted mapped pages that the hash then had to
// fault back in.
//
// CPU: both draw from the same treeWorkers() budget, so running two did not
// double throughput — it halved each one's share. Two replays at ~1.6 cores
// each turned a nineteen-minute step into six hours with nothing to show.
//
// Serialised, one step gets the whole budget and maps one tree. The replays
// still interleave between steps, so neither starves; they simply stop
// competing for the same cores and the same page cache at the same instant.
var stepMu sync.Mutex
