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
	)
	flag.Parse()

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
