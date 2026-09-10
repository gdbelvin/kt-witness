package workrpc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProofServer hands out the corrupted proofs that canaries are made of.
//
// It exists because a worker fetches its own proofs from the operator, which is
// the arrangement that makes its verdict worth having — and which leaves this
// witness no way to give it something it ought to refuse. A canary needs bytes
// only we control, so for those assignments the worker is pointed here instead.
//
// # Confined like the work channel
//
// Same LAN-only rule, for a related reason. The corrupted proof itself is not a
// secret — it is public data with a bit flipped — but which epochs are canaries
// is exactly what a worker must not be able to learn, and a public endpoint is
// an enumeration of them.
//
// # Lifetime
//
// A canary proof is served once and then dropped. Holding them would grow
// without bound at 284 MB apiece, and a canary that can be fetched twice is one
// a worker could have fetched already.
type ProofServer struct {
	Log *slog.Logger

	mu     sync.Mutex
	served map[string]string // token -> file path
	base   string
}

// NewProofServer serves on addr, which must name a LAN address for the same
// reason the work channel must.
func NewProofServer(addr string, log *slog.Logger) (*ProofServer, string, error) {
	note, err := CheckListenAddr(addr)
	if err != nil {
		return nil, "", err
	}
	if note != "" && log != nil {
		log.Warn("canary proof server confinement is enforced outside this process",
			"listen", addr, "note", note)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	p := &ProofServer{Log: log, served: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/canary/", p.serve)
	srv := &http.Server{
		Handler: mux,
		// A proof is hundreds of megabytes over a LAN, so the write timeout has
		// to allow for that without letting a stalled fetch hold the slot open
		// indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Minute,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && log != nil {
			log.Error("canary proof server stopped", "err", err)
		}
	}()
	return p, ln.Addr().String(), nil
}

// Offer registers a file to be served once, and returns the URL for it.
func (p *ProofServer) Offer(path, advertiseHost string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("no randomness for a canary token: %w", err)
	}
	token := hex.EncodeToString(b[:])
	p.mu.Lock()
	p.served[token] = path
	p.mu.Unlock()
	return fmt.Sprintf("http://%s/canary/%s", advertiseHost, token), nil
}

func (p *ProofServer) serve(w http.ResponseWriter, r *http.Request) {
	token := filepath.Base(r.URL.Path)
	p.mu.Lock()
	path, ok := p.served[token]
	delete(p.served, token) // once
	p.mu.Unlock()
	if !ok {
		// Deliberately the same answer a real proof store gives for an object
		// that is not there, rather than anything that says "canary".
		http.NotFound(w, r)
		return
	}
	defer os.Remove(path)

	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// Pending reports how many offers have not been fetched.
func (p *ProofServer) Pending() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.served)
}
