// kt-gpu-rootd serves one operation: given a file of sorted transparency-log
// leaves, return the Merkle root it rebuilds to.
//
// # The contract, which is the whole design
//
// This service returns a root. It does NOT decide anything.
//
// It does not fetch the operator's signed root, does not compare, does not
// judge, and does not record. That separation is deliberate and load-bearing.
// A root that disagrees with the one an operator signed reads, in this system,
// as the operator misbehaving — the strongest finding the project can make —
// and it must be made by the witness, on the CPU, from the Go implementation
// that is the specification. A GPU on another machine is not an appropriate
// instrument for that finding, so it is not given the opportunity to make one.
//
// What the caller does with a root from here: compare it with the signed root;
// if they match, the construction is confirmed cheaply. If they do not match,
// rebuild on the CPU and let that decide. A false mismatch costs one CPU
// rebuild. A false match would require landing on the signed hash by accident,
// which is not a failure mode hardware has.
//
// # Why it is this small
//
// It holds no state, keeps no database, and knows nothing about origins,
// epochs, tiers or cosignatures. Everything that could be wrong about a witness
// stays on the witness. What runs here is a hash function with a big fan-out.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// schemes are the tree constructions this build can rebuild. One today; the
// field exists because the point of proving this out on Proton is to do it for
// the other key-transparency trees, and a caller should get a clear refusal
// rather than a wrong root if it asks for one that is not implemented yet.
var schemes = map[string]bool{
	"proton-sparse-256": true,
}

type request struct {
	Scheme string `json:"scheme"`
	Path   string `json:"path"`
}

type server struct {
	root string // the only directory paths may name
	bin  string // the CUDA rebuild binary
	log  *slog.Logger

	// One rebuild at a time. A 201M-leaf tree occupies about 20 GB of a 24 GB
	// card, so two at once do not fit — and a caller that gets 503 can simply
	// come back, which is a better failure than an out-of-memory abort halfway
	// through forty minutes of somebody else's work.
	mu   sync.Mutex
	busy bool
}

// resolve confines a requested path to the served directory.
//
// The path comes from the network, and the directory it names contains files
// that must never be rebuilt: `.partial` is a half-written tree, and rebuilding
// one produces a root that does not match anything — which is indistinguishable,
// at the far end, from the operator having misbehaved. `.mismatch` is retained
// evidence of exactly that finding and is not a tree either. Refusing them here
// means no caller can turn a filename mistake into an accusation.
func (s *server) resolve(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	base := filepath.Base(p)
	if strings.Contains(base, ".partial") {
		return "", errors.New("refusing a .partial file: a half-written tree rebuilds to a root that matches nothing, which is not distinguishable from misbehaviour")
	}
	if strings.Contains(base, ".mismatch") {
		return "", errors.New("refusing a .mismatch file: it is retained evidence, not a tree")
	}
	abs, err := filepath.Abs(filepath.Join(s.root, filepath.Clean("/"+p)))
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("no such tree: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return "", err
	}
	// Prefix-check after resolving symlinks, so a link inside the export
	// cannot reach outside it.
	if real != rootReal && !strings.HasPrefix(real, rootReal+string(os.PathSeparator)) {
		return "", errors.New("path escapes the served directory")
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	return real, nil
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	if req.Scheme == "" {
		req.Scheme = "proton-sparse-256"
	}
	if !schemes[req.Scheme] {
		http.Error(w, "unknown scheme "+req.Scheme, http.StatusBadRequest)
		return
	}
	path, err := s.resolve(req.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		http.Error(w, "a rebuild is already running; the card holds one tree at a time", http.StatusServiceUnavailable)
		return
	}
	s.busy = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.busy = false; s.mu.Unlock() }()

	start := time.Now()
	s.log.Info("rebuild starting", "path", path, "scheme", req.Scheme)
	out, err := exec.CommandContext(r.Context(), s.bin, path).Output()
	if err != nil {
		var ee *exec.ExitError
		detail := err.Error()
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			detail = strings.TrimSpace(string(ee.Stderr))
		}
		s.log.Error("rebuild failed", "path", path, "err", detail)
		http.Error(w, "rebuild failed: "+detail, http.StatusInternalServerError)
		return
	}
	s.log.Info("rebuild done", "path", path, "took", time.Since(start).Round(time.Second))

	// The rebuild binary already emits the JSON the caller wants; passing it
	// through unaltered keeps one description of the result rather than two.
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	busy := s.busy
	s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "busy": busy, "root": s.root,
		"schemes": []string{"proton-sparse-256"},
	})
}

func main() {
	var (
		listen = flag.String("listen", "192.168.0.11:8099", "address to serve on; a LAN address, not 0.0.0.0")
		root   = flag.String("root", "/srv/kt-witness", "directory holding the trees, mounted read-only")
		bin    = flag.String("bin", "/usr/local/bin/kt-proton-gpu", "the rebuild binary")
	)
	flag.Parse()
	if v := os.Getenv("KT_GPU_BIN"); v != "" {
		*bin = v
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s := &server{root: *root, bin: *bin, log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("/root", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)

	srv := &http.Server{
		Addr:    *listen,
		Handler: mux,
		// A rebuild is minutes, so the write timeout has to accommodate one.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Minute,
	}
	log.Info("kt-gpu-rootd", "listen", *listen, "root", *root, "bin", *bin)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
