//go:build unix

// Command kt-proton-audit rebuilds Proton's key directory from its published
// leaves and checks the result against the tree hash Proton signed.
//
// This is the construction audit — the thing an append-only chain of epoch
// hashes cannot give you. The chain proves the sequence of commitments was not
// rewritten. It says nothing about whether each tree was derived from the last
// by legal mutations, because the directory is a mutable map: a binding can be
// removed, or overwritten without bumping its revision, while every published
// epoch hash stays perfectly consistent. Recomputing the root from the leaves is
// what detects that.
//
// The full dump is ~13.6 GB for ~200M leaves. It is published sorted by label,
// which is what makes this affordable: the tree can be rebuilt by recursive
// range splitting over a memory-mapped file, in constant memory, sharded across
// cores.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source/proton"
)

func main() {
	var (
		epoch      = flag.Int64("epoch", 0, "epoch to audit (0 = latest)")
		dir        = flag.String("dir", ".", "directory to cache the tree dump in")
		shardDepth = flag.Int("shard-depth", 10, "split the top N levels across cores")
		apiBase    = flag.String("api", "https://api.protonmail.ch", "Proton API base")
		dumpBase   = flag.String("dumps", "https://proton.me/kt", "tree dump base URL")
		keep       = flag.Bool("keep", false, "keep the downloaded dump for the next run")
		from       = flag.Int64("from", 0, "audit the step from this epoch by applying the target epoch's diff")
	)
	flag.Parse()

	if *from > 0 {
		if err := runIncremental(*from, *epoch, *dir, *shardDepth, *apiBase, *dumpBase, *keep); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*epoch, *dir, *shardDepth, *apiBase, *dumpBase, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type epochMeta struct {
	EpochID   int64  `json:"EpochID"`
	TreeHash  string `json:"TreeHash"`
	ChainHash string `json:"ChainHash"`
}

func run(epoch int64, dir string, shardDepth int, apiBase, dumpBase string, keep bool) error {
	meta, err := fetchEpoch(apiBase, epoch)
	if err != nil {
		return err
	}
	fmt.Printf("epoch %d\n  published tree hash %s\n", meta.EpochID, meta.TreeHash)

	path := filepath.Join(dir, fmt.Sprintf("epoch_tree_%d.bin", meta.EpochID))
	if _, err := os.Stat(path); err != nil {
		url := fmt.Sprintf("%s/epoch.1.%d", dumpBase, meta.EpochID)
		fmt.Printf("  downloading %s\n", url)
		start := time.Now()
		n, err := download(url, path)
		if err != nil {
			return err
		}
		fmt.Printf("  %.2f GB in %s (%.1f MB/s)\n",
			float64(n)/1e9, time.Since(start).Round(time.Second),
			float64(n)/time.Since(start).Seconds()/1e6)
	} else {
		fmt.Printf("  using cached %s\n", path)
	}
	if !keep {
		defer os.Remove(path)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size == 0 || size%68 != 0 {
		return fmt.Errorf("dump is %d bytes, not a whole number of 68-byte leaves", size)
	}
	fmt.Printf("  %d leaves\n", size/68)

	// Mapped rather than read: the tree is rebuilt by walking ranges, so the
	// kernel can page it in and out and the process stays small.
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(data)

	fmt.Printf("  rebuilding (shard depth %d)\n", shardDepth)
	start := time.Now()
	root, err := proton.TreeRootParallel(proton.SliceLeaves(data), shardDepth)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	got := hex.EncodeToString(root)
	fmt.Printf("  recomputed        %s\n  took              %s\n", got, elapsed.Round(time.Second))

	if got != meta.TreeHash {
		return fmt.Errorf("TREE HASH MISMATCH — the published leaves do not build the signed tree")
	}
	fmt.Println("\n  MATCH: the signed tree hash is exactly what these leaves build.")
	return nil
}

func fetchEpoch(apiBase string, epoch int64) (*epochMeta, error) {
	url := apiBase + "/kt/v1/epochs"
	if epoch > 0 {
		url = fmt.Sprintf("%s/kt/v1/epochs/%d", apiBase, epoch)
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if epoch > 0 {
		var m epochMeta
		return &m, json.Unmarshal(body, &m)
	}
	var list struct {
		Epochs []epochMeta `json:"Epochs"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	if len(list.Epochs) == 0 {
		return nil, fmt.Errorf("no epochs returned")
	}
	best := list.Epochs[0]
	for _, e := range list.Epochs {
		if e.EpochID > best.EpochID {
			best = e
		}
	}
	return &best, nil
}

func download(url, path string) (int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	tmp := path + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	// Renamed only once complete, so an interrupted run never leaves a truncated
	// dump that would rebuild to a wrong root.
	return n, os.Rename(tmp, path)
}

// runIncremental audits the step *between* two snapshots: it takes the tree at
// `from`, applies the published diff for the next epoch, rebuilds, and checks
// the result against that epoch's signed tree hash.
//
// This is the check that catches an illegal mutation. A full rebuild proves the
// operator's leaves build the root they signed; it says nothing about whether
// the change from one epoch to the next was legitimate. Only replaying the
// transition shows what actually moved — and the mutations are reported rather
// than folded silently into a new root, because removals and in-place
// overwrites are the whole point.
func runIncremental(from, target int64, dir string, shardDepth int, apiBase, dumpBase string, keep bool) error {
	if target == 0 {
		target = from + 1
	}
	if target <= from {
		return fmt.Errorf("target epoch %d must be after %d", target, from)
	}

	meta, err := fetchEpoch(apiBase, target)
	if err != nil {
		return err
	}
	fmt.Printf("auditing the step %d -> %d\n  published tree hash %s\n", from, target, meta.TreeHash)

	basePath := filepath.Join(dir, fmt.Sprintf("epoch_tree_%d.bin", from))
	if _, err := os.Stat(basePath); err != nil {
		url := fmt.Sprintf("%s/epoch.1.%d", dumpBase, from)
		fmt.Printf("  downloading base tree %s\n", url)
		start := time.Now()
		n, err := download(url, basePath)
		if err != nil {
			return err
		}
		fmt.Printf("  %.2f GB in %s\n", float64(n)/1e9, time.Since(start).Round(time.Second))
	} else {
		fmt.Printf("  using cached base %s\n", basePath)
	}

	diffURL := fmt.Sprintf("%s/epoch.1.%d.diff", dumpBase, target)
	diff, err := fetchBytes(diffURL)
	if err != nil {
		return err
	}
	fmt.Printf("  diff %.2f MB (%d records)\n", float64(len(diff))/1e6, len(diff)/69)

	base, closeBase, err := mapFile(basePath)
	if err != nil {
		return err
	}
	defer closeBase()

	outPath := filepath.Join(dir, fmt.Sprintf("epoch_tree_%d.bin", target))
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(out, 1<<22)

	start := time.Now()
	stats, err := proton.ApplyDiff(proton.SliceLeaves(base), diff, func(label, value []byte) error {
		if _, err := w.Write(label); err != nil {
			return err
		}
		_, err := w.Write(value)
		return err
	})
	if err != nil {
		out.Close()
		os.Remove(outPath)
		return err
	}
	if err := w.Flush(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if !keep {
		defer os.Remove(outPath)
		defer os.Remove(basePath)
	}

	fmt.Printf("  merged in %s\n", time.Since(start).Round(time.Second))
	fmt.Printf("  mutations: %d added, %d removed, %d overwritten in place, %d removals of absent labels\n",
		stats.Added, stats.Removed, stats.Overwritten, stats.PhantomRemovals)
	if stats.Suspicious() {
		// Not an accusation. Proton permits deletion within a retention window,
		// so these need judging against that window — but they are invisible
		// from the epoch chain, so they are surfaced rather than absorbed.
		fmt.Printf("  NOTE: this epoch mutated existing entries. None of that is\n" +
			"        visible from the chain of signed epoch hashes.\n")
	}

	merged, closeMerged, err := mapFile(outPath)
	if err != nil {
		return err
	}
	defer closeMerged()

	fmt.Printf("  rebuilding %d leaves\n", len(merged)/68)
	start = time.Now()
	root, err := proton.TreeRootParallel(proton.SliceLeaves(merged), shardDepth)
	if err != nil {
		return err
	}
	got := hex.EncodeToString(root)
	fmt.Printf("  recomputed        %s\n  took              %s\n", got, time.Since(start).Round(time.Second))

	if got != meta.TreeHash {
		return fmt.Errorf("TREE HASH MISMATCH — the published diff does not carry epoch %d into epoch %d",
			from, target)
	}
	fmt.Printf("\n  MATCH: epoch %d plus its published diff is exactly epoch %d.\n", from, target)
	return nil
}

func fetchBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<30))
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
	if fi.Size() == 0 || fi.Size()%68 != 0 {
		f.Close()
		return nil, nil, fmt.Errorf("%s is %d bytes, not a whole number of 68-byte leaves", path, fi.Size())
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(fi.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("mmap %s: %w", path, err)
	}
	return data, func() { syscall.Munmap(data); f.Close() }, nil
}
