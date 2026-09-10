package workrpc

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProofServer is where every worker fetches every proof, and one in a hundred
// of them has a bit flipped.
//
// # Why all of them, and not just the canaries
//
// The first version of this served only corrupted proofs, and pointed workers
// at them with a field that ordinary assignments left empty. That is a canary
// with a label on it: a worker wanting to cheat needed only to notice that a
// proof came from the witness rather than the operator, refuse those, and
// fabricate everything else. It would have scored perfectly on every test while
// verifying nothing, which is worse than not testing at all — the test would
// have been producing evidence for the wrong conclusion.
//
// A test the subject can identify is not a test. So every proof a worker
// verifies comes from here, and the worker cannot tell which is which because
// there is nothing to tell.
//
// # What this does and does not cost
//
// The witness fetches each proof instead of the worker. External bandwidth is
// unchanged — every machine here sits behind one connection, so the bytes cross
// it once either way — and the LAN hop is free. What it does add is that the
// witness is now in the path: a proof it cannot fetch is one no worker can
// verify.
//
// # What a worker still does for itself
//
// The roots. They are resolved from the operator's own listing by the worker,
// never taken from the assignment, and that is what keeps this honest: a proof
// this witness corrupted cannot rebuild roots the operator published. Serving
// the bytes lets us test a worker; it does not let us make one agree with us.
type ProofServer struct {
	Log *slog.Logger

	// Fetch returns the proof for one epoch, as the operator published it.
	Fetch func(origin string, epoch int64) (io.ReadCloser, int64, error)

	// Every is the canary rate: 100 corrupts one proof in a hundred. Zero means
	// that default.
	Every int

	mu       sync.Mutex
	seen     int
	canaries map[string]int64 // "origin\x00epoch" -> when it was served
}

// NewProofServer starts serving on addr, which must be a LAN address for the
// same reason the work channel must.
func NewProofServer(addr string, log *slog.Logger, fetch func(string, int64) (io.ReadCloser, int64, error), every int) (*ProofServer, string, error) {
	note, err := CheckListenAddr(addr)
	if err != nil {
		return nil, "", err
	}
	if note != "" && log != nil {
		log.Warn("proof server confinement is enforced outside this process",
			"listen", addr, "note", note)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	p := &ProofServer{Log: log, Fetch: fetch, Every: every, canaries: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/proof/", p.serve)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// A Meta proof is ~280 MB over a LAN. Long enough for that, short
		// enough that a stalled fetch does not hold the slot forever.
		WriteTimeout: 15 * time.Minute,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && log != nil {
			log.Error("proof server stopped", "err", err)
		}
	}()
	return p, ln.Addr().String(), nil
}

// serve answers /proof/{origin}/{epoch}.
func (p *ProofServer) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/proof/")
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	origin, epochStr := rest[:i], rest[i+1:]
	epoch, err := strconv.ParseInt(epochStr, 10, 64)
	if err != nil || origin == "" {
		http.NotFound(w, r)
		return
	}

	body, size, err := p.Fetch(origin, epoch)
	if err != nil {
		// The same answer the operator's store gives for an object that is not
		// there. A worker learns that it could not have the proof, not why.
		http.Error(w, "", http.StatusNotFound)
		return
	}
	defer body.Close()

	corrupt := p.due()
	if corrupt {
		p.mark(origin, epoch)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	if !corrupt {
		if _, err := io.Copy(w, body); err != nil && p.Log != nil {
			p.Log.Debug("proof transfer interrupted", "origin", origin, "epoch", epoch, "err", err)
		}
		return
	}

	// Flip one bit on the way past, at a position chosen before the transfer
	// starts so the stream is not buffered whole. The byte offset is uniform
	// over the size the operator reported.
	at, bit := int64(0), 0
	if size > 0 {
		if n, err := rand.Int(rand.Reader, big.NewInt(size)); err == nil {
			at = n.Int64()
		}
		if n, err := rand.Int(rand.Reader, big.NewInt(8)); err == nil {
			bit = int(n.Int64())
		}
	}
	if err := copyFlipping(w, body, at, byte(1)<<uint(bit)); err != nil && p.Log != nil {
		p.Log.Debug("canary transfer interrupted", "origin", origin, "epoch", epoch, "err", err)
	}
	if p.Log != nil {
		p.Log.Info("served a canary", "origin", origin, "epoch", epoch,
			"corrupted", fmt.Sprintf("byte %d of %d, bit %d", at, size, bit))
	}
}

// copyFlipping streams src to dst, flipping one bit at offset.
//
// Streaming rather than buffering because these are hundreds of megabytes and
// there may be eight in flight; holding them whole to change one byte would
// make the observer the thing that falls over.
func copyFlipping(dst io.Writer, src io.Reader, offset int64, mask byte) error {
	buf := make([]byte, 1<<20)
	var pos int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if offset >= pos && offset < pos+int64(n) {
				buf[offset-pos] ^= mask
			}
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
			pos += int64(n)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (p *ProofServer) due() bool {
	every := p.Every
	if every <= 0 {
		every = 100
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen++
	return p.seen%every == 0
}

func (p *ProofServer) mark(origin string, epoch int64) {
	p.canaries[key(origin, epoch)] = time.Now().Unix()
}

// WasCanary reports whether the proof served for this epoch was corrupted, and
// forgets it. Called once, when the result comes back.
func (p *ProofServer) WasCanary(origin string, epoch int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := key(origin, epoch)
	_, ok := p.canaries[k]
	if ok {
		delete(p.canaries, k)
	}
	return ok
}

// Outstanding reports canaries served but not yet answered. A worker that takes
// them and never replies is as much a problem as one that answers wrongly.
func (p *ProofServer) Outstanding() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.canaries)
}

func key(origin string, epoch int64) string {
	return origin + "\x00" + strconv.FormatInt(epoch, 10)
}
