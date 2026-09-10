// kt-proton-backfill audits Proton's entire retained history offline, against
// data already on disk, using the GPU for the root computation.
//
// # What this is for
//
// The witness audits Proton forward from wherever it happens to be. That leaves
// the published history before it arrived unchecked, and the replay that was
// meant to close the gap moves one epoch per rebuild — which on the witness
// costs about two hours, so five hundred epochs is roughly forty days. It has
// never finished. On the GPU a rebuild is 105 seconds, which turns the same
// work into an overnight run.
//
// It is deliberately a separate program rather than a mode of the witness. The
// witness's job is to be watching right now; a job that saturates a card for
// fifteen hours belongs beside it, not inside it.
//
// # The rule this program exists to obey
//
// A rebuilt root that does not match the one Proton signed is the strongest
// finding this project can make. It is never made on the strength of a GPU.
//
// So on any mismatch the epoch is rebuilt on the CPU with the implementation in
// internal/source/proton, which is the specification, and the CPU decides. Three
// outcomes, and they are not the same thing:
//
//   - both agree with Proton: verified.
//   - GPU disagrees, CPU agrees: a bug in the GPU path. Reported loudly, the
//     epoch counted as verified, and the run continues. This is the outcome
//     that must never be silently rounded to "verified".
//   - both disagree with Proton: a construction failure. The run stops and the
//     tree is kept, because that is evidence and somebody must look at it.
//
// # Judgement stays here
//
// Rebuilding a root proves the tree follows from the diff. It says nothing
// about whether the mutations were legitimate — a removal, an overwrite in
// place, a removal of something absent are all things an append-only directory
// should not do, and none of them change the root. That analysis is
// ApplyDiff's DiffStats and JudgeRemovals, it runs here on the CPU, and the GPU
// has nothing to do with it.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source/proton"
)

const entrySize = 68

type epochMeta struct {
	Epoch      int64  `json:"epoch"`
	TreeHash   string `json:"tree_hash"`
	ChainHash  string `json:"chain_hash"`
	StartEpoch int64  `json:"start_epoch"`
}

type result struct {
	Epoch      int64  `json:"epoch"`
	Verified   bool   `json:"verified"`
	Root       string `json:"root"`
	SignedRoot string `json:"signed_root"`
	Source     string `json:"source"` // "gpu", or "cpu" when the GPU had to be checked
	GPUAgreed  bool   `json:"gpu_agreed"`
	Leaves     int64  `json:"leaves"`
	ApplyMS    int64  `json:"apply_ms"`
	RootMS     int64  `json:"root_ms"`
	Added      int    `json:"added"`
	Removed    int    `json:"removed"`
	Overwrote  int    `json:"overwritten"`
	Phantom    int    `json:"phantom_removals"`
	Irregular  int    `json:"irregular_labels"`
	Note       string `json:"note,omitempty"`
}

// outcome is what a rebuild means once the CPU has been consulted.
type outcome int

const (
	verifiedByGPU      outcome = iota // GPU matched the signed root; nothing else to do
	gpuWrong                          // GPU disagreed, CPU matched: a bug here, not a finding
	constructionFailed                // GPU and CPU both disagree with what Proton signed
)

// classify decides what a disagreement means, and is separated from the loop
// that produces it so the rule can be tested rather than inspected.
//
// The asymmetry is the whole point. A GPU that computes a wrong root must cost
// one CPU rebuild and an alarm, never an accusation. Only the CPU — running the
// implementation that is the specification — can conclude that an operator's
// published diff does not carry one epoch into the next.
func classify(gpu, cpu, signed string) outcome {
	if gpu == signed {
		return verifiedByGPU
	}
	if cpu == signed {
		return gpuWrong
	}
	return constructionFailed
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
	if fi.Size() == 0 || fi.Size()%entrySize != 0 {
		f.Close()
		return nil, nil, fmt.Errorf("%s is %d bytes, not a whole number of %d-byte leaves",
			path, fi.Size(), entrySize)
	}
	b, err := syscall.Mmap(int(f.Fd()), 0, int(fi.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	f.Close()
	if err != nil {
		return nil, nil, err
	}
	return b, func() { syscall.Munmap(b) }, nil
}

// gpuRoot runs the CUDA rebuild and returns the root it computed.
func gpuRoot(bin, path string) (string, error) {
	out, err := exec.Command(bin, path).Output()
	if err != nil {
		var ee *exec.ExitError
		if ok := asExit(err, &ee); ok && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	var r struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", fmt.Errorf("rebuild output was not JSON: %s", strings.TrimSpace(string(out)))
	}
	if len(r.Root) != 64 {
		return "", fmt.Errorf("rebuild returned a %d-character root", len(r.Root))
	}
	return r.Root, nil
}

func asExit(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func loadManifest(path string) (map[int64]epochMeta, []int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	m := map[int64]epochMeta{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e epochMeta
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, nil, err
		}
		m[e.Epoch] = e
	}
	epochs := make([]int64, 0, len(m))
	for e := range m {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	return m, epochs, sc.Err()
}

func main() {
	var (
		dir   = flag.String("dir", "/srv/proton-history", "downloaded history: base tree, diffs/, manifest.jsonl")
		work  = flag.String("work", "", "where trees are built (default: -dir)")
		bin   = flag.String("gpu", "/usr/local/bin/kt-proton-gpu", "the GPU rebuild binary")
		out   = flag.String("out", "", "append results here as JSONL (default: <dir>/backfill.jsonl)")
		from  = flag.Int64("from", 0, "first epoch to audit (default: the oldest retained)")
		to    = flag.Int64("to", 0, "last epoch to audit (default: the newest in the manifest)")
		shard = flag.Int("shard-depth", 10, "CPU rebuild shard depth, used only to check a GPU mismatch")
		keep  = flag.Bool("keep-trees", false, "do not delete a tree once its successor is built")
	)
	flag.Parse()
	if *work == "" {
		*work = *dir
	}
	if *out == "" {
		*out = filepath.Join(*dir, "backfill.jsonl")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	meta, epochs, err := loadManifest(filepath.Join(*dir, "manifest.jsonl"))
	if err != nil {
		log.Error("manifest", "err", err)
		os.Exit(1)
	}
	if len(epochs) == 0 {
		log.Error("manifest is empty")
		os.Exit(1)
	}
	floor, tip := epochs[0], epochs[len(epochs)-1]
	if *from == 0 {
		*from = floor
	}
	if *to == 0 {
		*to = tip
	}
	log.Info("retained history", "floor", floor, "tip", tip, "auditing", fmt.Sprintf("%d..%d", *from, *to))

	resf, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Error("results file", "err", err)
		os.Exit(1)
	}
	defer resf.Close()
	enc := json.NewEncoder(resf)

	// Ctrl-C between epochs rather than during one: a half-written tree is the
	// thing this whole design is careful never to leave behind.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	interrupted := false
	go func() { <-stop; interrupted = true; log.Warn("interrupt: finishing this epoch, then stopping") }()

	treePath := func(e int64) string { return filepath.Join(*work, fmt.Sprintf("epoch_tree_%d.bin", e)) }

	// Resume: start from the newest tree already built inside the range.
	base := floor
	for e := *to; e >= floor; e-- {
		if fi, err := os.Stat(treePath(e)); err == nil && fi.Size()%entrySize == 0 {
			base = e
			break
		}
	}
	if _, err := os.Stat(treePath(base)); err != nil {
		log.Error("no base tree; fetch-proton-history.sh must run first", "want", treePath(base))
		os.Exit(1)
	}

	// The base is checked before anything is built on it, ALWAYS — not only
	// when it is the retention floor.
	//
	// The earlier version skipped this when resuming, on the reasoning that a
	// resumed tree was one this program had already verified. That reasoning
	// broke the first time it mattered. Proton serves 403 for epoch 6675, both
	// its diff and its full dump, so the replay could not step past 6674 and
	// had to re-bootstrap from a freshly downloaded dump at 6676 — a tree that
	// arrives looking exactly like a resumed one and has been verified by
	// nobody. Sixty seconds to check is nothing against replaying sixty epochs
	// onto an assumption.
	log.Info("verifying the base tree before replaying from it", "epoch", base)
	if _, ok := meta[base]; !ok {
		log.Error("no signed root in the manifest for the base tree", "epoch", base)
		os.Exit(1)
	}
	baseRoot, err := gpuRoot(*bin, treePath(base))
	if err != nil {
		log.Error("base rebuild", "err", err)
		os.Exit(1)
	}
	if baseRoot != meta[base].TreeHash {
		log.Error("BASE TREE DOES NOT MATCH ITS SIGNED ROOT — refusing to replay from it",
			"epoch", base, "computed", baseRoot, "signed", meta[base].TreeHash)
		os.Exit(1)
	}
	log.Info("base verified", "epoch", base, "root", baseRoot[:16])

	verified, gpuBugs := 0, 0
	for e := base + 1; e <= *to; e++ {
		if interrupted {
			break
		}
		m, ok := meta[e]
		if !ok {
			log.Error("no signed root in the manifest", "epoch", e)
			os.Exit(1)
		}
		diffPath := filepath.Join(*dir, "diffs", fmt.Sprintf("epoch.1.%d.diff", e))
		diff, err := os.ReadFile(diffPath)
		if err != nil {
			log.Error("this epoch cannot be reconstructed: its diff is not present. "+
				"Fetch a full dump for a LATER epoch, place it as the base, and re-run; "+
				"the epochs in between stay unaudited and that is the honest outcome",
				"epoch", e, "err", err)
			os.Exit(4)
		}
		// A diff is a whole number of 69-byte records or it is not a diff. An
		// HTTP error page saved as one is the specific way this went wrong.
		if len(diff)%69 != 0 {
			log.Error("this epoch's diff is not a whole number of 69-byte records — refusing it. "+
				"An HTTP error body saved as a diff looks exactly like this",
				"epoch", e, "bytes", len(diff))
			os.Exit(4)
		}

		prev, closePrev, err := mapFile(treePath(e - 1))
		if err != nil {
			log.Error("base tree", "epoch", e-1, "err", err)
			os.Exit(1)
		}

		// Written under a temporary name and renamed only once complete, for
		// the same reason the witness does: a truncated tree rebuilds to a root
		// that matches nothing, and that is indistinguishable from misbehaviour.
		tmp := treePath(e) + ".partial"
		f, err := os.Create(tmp)
		if err != nil {
			closePrev()
			log.Error("create", "err", err)
			os.Exit(1)
		}
		w := bufio.NewWriterSize(f, 1<<22)
		t0 := time.Now()
		stats, err := proton.ApplyDiff(proton.SliceLeaves(prev), diff, func(label, value []byte) error {
			if _, err := w.Write(label); err != nil {
				return err
			}
			_, err := w.Write(value)
			return err
		})
		if err == nil {
			err = w.Flush()
		}
		cerr := f.Close()
		closePrev()
		if err != nil || cerr != nil {
			os.Remove(tmp)
			log.Error("apply", "epoch", e, "err", err, "close", cerr)
			os.Exit(1)
		}
		if err := os.Rename(tmp, treePath(e)); err != nil {
			log.Error("rename", "err", err)
			os.Exit(1)
		}
		applyMS := time.Since(t0).Milliseconds()

		t1 := time.Now()
		root, err := gpuRoot(*bin, treePath(e))
		if err != nil {
			log.Error("gpu rebuild", "epoch", e, "err", err)
			os.Exit(1)
		}
		rootMS := time.Since(t1).Milliseconds()

		res := result{
			Epoch: e, Root: root, SignedRoot: m.TreeHash, Source: "gpu", GPUAgreed: true,
			ApplyMS: applyMS, RootMS: rootMS,
			Added: stats.Added, Removed: stats.Removed,
			Overwrote: stats.Overwritten, Phantom: stats.PhantomRemovals,
		}
		if fi, err := os.Stat(treePath(e)); err == nil {
			res.Leaves = fi.Size() / entrySize
		}
		if irr := proton.IrregularRemovals(stats); len(irr) > 0 {
			res.Irregular = len(irr)
		}

		if root != m.TreeHash {
			// The rule. A GPU is not allowed to accuse an operator.
			res.GPUAgreed = false
			log.Warn("GPU root does not match the signed root — rebuilding on the CPU before believing it",
				"epoch", e, "gpu", root, "signed", m.TreeHash)
			cur, closeCur, err := mapFile(treePath(e))
			if err != nil {
				log.Error("remap", "err", err)
				os.Exit(1)
			}
			cpu, cerr := proton.TreeRootParallel(proton.SliceLeaves(cur), *shard)
			closeCur()
			if cerr != nil {
				log.Error("cpu rebuild", "epoch", e, "err", cerr)
				os.Exit(1)
			}
			cpuHex := hex.EncodeToString(cpu)
			res.Source = "cpu"
			res.Root = cpuHex
			if classify(root, cpuHex, m.TreeHash) == gpuWrong {
				gpuBugs++
				res.Note = "GPU DISAGREED WITH THE CPU: a bug in the GPU path, not a finding about Proton"
				log.Error("GPU PATH IS WRONG at this epoch; the CPU matches Proton. Continuing, but the GPU result must not be trusted until this is understood",
					"epoch", e, "gpu", root, "cpu", cpuHex)
			} else {
				res.Verified = false
				res.Note = "CONSTRUCTION AUDIT FAILED: the published diff does not carry one epoch into the next"
				enc.Encode(res)
				log.Error("PROTON CONSTRUCTION AUDIT FAILED — stopping and keeping the tree as evidence",
					"epoch", e, "from", e-1, "cpu", cpuHex, "signed", m.TreeHash,
					"evidence", treePath(e))
				os.Exit(2)
			}
		}

		res.Verified = true
		verified++
		if err := enc.Encode(res); err != nil {
			log.Error("write result", "err", err)
			os.Exit(1)
		}

		if stats.Suspicious() {
			log.Warn("epoch mutated the directory in ways an append-only map should not",
				"epoch", e, "removed", stats.Removed, "overwritten", stats.Overwritten,
				"phantom", stats.PhantomRemovals, "irregular_labels", res.Irregular)
		}
		log.Info("epoch verified", "epoch", e, "leaves", res.Leaves,
			"apply_s", applyMS/1000, "root_s", rootMS/1000,
			"added", stats.Added, "removed", stats.Removed,
			"remaining", *to-e)

		if !*keep {
			// Only once the successor is safely in place.
			os.Remove(treePath(e - 1))
		}
	}

	log.Info("backfill finished", "verified", verified, "gpu_disagreements", gpuBugs,
		"results", *out)
	if gpuBugs > 0 {
		log.Warn("the GPU path disagreed with the CPU on some epochs; those roots came from the CPU",
			"count", gpuBugs)
		os.Exit(3)
	}
}
