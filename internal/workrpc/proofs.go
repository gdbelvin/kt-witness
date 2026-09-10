package workrpc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
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

	// MayRead reports whether this worker currently holds a lease covering the
	// epoch it is asking for. It is the authorisation, and it is what closes
	// the root-chaining bypass described below.
	MayRead func(worker, origin string, epoch int64) bool

	// Every is the canary rate: 100 corrupts one proof in a hundred. Zero means
	// that default.
	Every int

	mu       sync.Mutex
	seen     int
	canaries map[string]int64  // "origin\x00epoch" -> when it was served
	sessions map[string]string // per-session token -> worker name
}

// Session registers a token for one worker's session and returns it. The token
// goes into the proof base URL that session is given, so a worker authenticates
// simply by using the URL it was handed.
func (p *ProofServer) Session(worker string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("no randomness for a session token: %w", err)
	}
	token := hex.EncodeToString(b[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessions == nil {
		p.sessions = map[string]string{}
	}
	p.sessions[token] = worker
	return token, nil
}

// EndSession forgets a token when its stream closes, so a disconnected worker
// cannot keep reading proofs.
func (p *ProofServer) EndSession(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, token)
}

func (p *ProofServer) workerFor(token string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w, ok := p.sessions[token]
	return w, ok
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
	p := &ProofServer{Log: log, Fetch: fetch, Every: every,
		canaries: map[string]int64{}, sessions: map[string]string{}}
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

// serve answers /proof/{session}/{origin}/{epoch}.
func (p *ProofServer) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/proof/")
	j := strings.Index(rest, "/")
	if j < 0 {
		http.NotFound(w, r)
		return
	}
	session, rest := rest[:j], rest[j+1:]
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

	worker, ok := p.workerFor(session)
	if !ok {
		// An unknown session. Answered the same way as a missing proof: a
		// caller learns that it cannot have this, not why, and not whether the
		// epoch exists.
		http.NotFound(w, r)
		return
	}
	if p.MayRead != nil && !p.MayRead(worker, origin, epoch) {
		// Asking for an epoch it does not hold is the signature of the
		// root-chaining bypass, so it is logged rather than merely refused.
		if p.Log != nil {
			p.Log.Warn("worker asked for a proof outside its assignment",
				"worker", worker, "origin", origin, "epoch", epoch,
				"note", "this is what a worker skipping the append-only check would do")
		}
		metricsIncOutOfLease()
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

	// Read the front of the proof before anything goes out, and do it for every
	// proof rather than only for canaries.
	//
	// The scan is what tells the canary where `inserted` ends (see the region
	// comment on pickCanaryBit). Doing it only when corrupting would have handed
	// a worker the tell this whole file exists to deny it: a buffered prefix
	// arrives as a pause and then a LAN-speed burst, an unbuffered one trickles
	// through at the operator's pace, and the two are told apart by a stopwatch
	// rather than by verifying anything. So the ordinary path pays it too, and
	// the only difference between a canary and honest work remains one XOR.
	head, sp := readInserted(body, insertedScanLimit)
	src := io.MultiReader(bytes.NewReader(head), body)

	if !corrupt {
		if _, err := io.Copy(w, src); err != nil && p.Log != nil {
			p.Log.Debug("proof transfer interrupted", "origin", origin, "epoch", epoch, "err", err)
		}
		return
	}

	// Flip one bit on the way past, at a position chosen before the rest of the
	// transfer starts so nothing beyond the scanned prefix is ever buffered.
	at, bit, region := pickCanaryBit(head, sp, size)
	if err := copyFlipping(w, src, at, byte(1)<<uint(bit)); err != nil && p.Log != nil {
		p.Log.Debug("canary transfer interrupted", "origin", origin, "epoch", epoch, "err", err)
	}
	if p.Log != nil {
		// The region is what separates the two failures. A canary in `inserted`
		// that comes back verified means the worker never read the append-only
		// evidence; one in `unchanged` that comes back verified means it did not
		// read the proof at all. Without this line both arrive as the same
		// sentence and the operator cannot tell which is being reported.
		//
		// The inserted span is logged whether or not it was aimed at, because
		// nothing else measures it. No real proof has ever been on this
		// machine's disk to measure, so the fraction below is the only place the
		// witness will ever learn how much of a Meta proof one epoch's additions
		// actually are — and that fraction is exactly what says how badly a
		// uniform canary would have missed.
		p.Log.Info("served a canary", "origin", origin, "epoch", epoch,
			"corrupted", fmt.Sprintf("byte %d of %d, bit %d", at, size, bit),
			"region", region, "inserted", sp.describe(size))
	}
}

// insertedField is `inserted` in SingleAppendOnlyProof: the elements this epoch
// added, as opposed to field 2, the whole previous tree carried forward.
const insertedField = 1

// The canary split, as a fraction: canaryInsertedShare canaries out of every
// canaryShareOf aim inside `inserted`. Argued in the comment on pickCanaryBit.
const (
	canaryInsertedShare = 3
	canaryShareOf       = 4
)

// insertedScanLimit caps how much of a proof is held while the leading
// `inserted` run is framed.
//
// The transfer itself streams — that is why copyFlipping exists — so this is
// the only place the server holds proof bytes, and it is held on every request
// rather than every hundredth. The comment on copyFlipping puts eight transfers
// in flight, so the ceiling this sets is eight times itself plus a read buffer
// each: about 136 MiB, against proofs of 284 MB the witness must never try to
// hold whole. It is a ceiling and not an allocation — the buffer grows to the
// run it actually finds, and on the test fixture that is 3 kB.
//
// A proof whose `inserted` set is larger than this is not a failure: everything
// buffered is still inserted, so the flip still lands inside field 1. It only
// means the choice is confined to the first 16 MiB of the field rather than
// spread over all of it, which is recorded in the log line.
const insertedScanLimit = 16 << 20

// insertedSpan is what framing the front of a proof established about it.
type insertedSpan struct {
	end    int  // bytes [0, end) are a complete run of `inserted` elements
	capped bool // the run was still going when the scan hit its limit
	known  bool // the framing parsed at all
}

func (s insertedSpan) describe(size int64) string {
	if !s.known {
		return "not located; the framing did not parse"
	}
	of := "of a proof whose size the operator did not declare"
	if size > 0 {
		of = fmt.Sprintf("of %d bytes (%.2f%%)", size, 100*float64(s.end)/float64(size))
	}
	if s.capped {
		return fmt.Sprintf("at least %d %s, scan capped at %d", s.end, of, insertedScanLimit)
	}
	return fmt.Sprintf("%d %s", s.end, of)
}

// readInserted reads from src until the leading run of `inserted` elements has
// ended, and returns every byte it consumed along with where that run stops.
//
// Every byte, because the caller puts them back in front of the stream: this
// must not be able to lose part of a proof, including when src is not a proof
// at all and the framing scan gives up on the first tag.
//
// Errors are not returned. A proof whose front does not frame is one the canary
// cannot aim at, which is a lost opportunity and not a reason to refuse a worker
// the bytes — the operator publishes the encoding, and if it ever changes, the
// witness should degrade to the uniform flip it used before rather than stop
// serving.
func readInserted(src io.Reader, limit int) ([]byte, insertedSpan) {
	buf := make([]byte, 0, 1<<16)
	tmp := make([]byte, 1<<20)
	sp := insertedSpan{known: true}
	// A Reader is discouraged from returning nothing without an error, but this
	// runs before a single byte has reached the worker, so a reader that does
	// would spin here holding the transfer slot rather than merely wasting a
	// loop. Give up after a few and let the copy deal with it.
	idle := 0
	for {
		end, ended, err := akdtree.ScanLeading(buf, insertedField, sp.end)
		if err != nil {
			return buf, insertedSpan{}
		}
		sp.end = end
		if ended {
			return buf, sp
		}
		if sp.end >= limit {
			sp.capped = true
			return buf, sp
		}
		n, err := src.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			idle = 0
			continue
		}
		if err == nil {
			if idle++; idle < 8 {
				continue
			}
			return buf, sp
		}
		if err != nil {
			// EOF, or a fetch that broke. Either way there is no more framing to
			// do; what has been read is handed back and the copy will surface the
			// failure again.
			return buf, sp
		}
	}
}

// pickCanaryBit chooses which bit of a proof to flip, and says which half of
// the proof it landed in.
//
// # Why not uniformly, as this did
//
// The published roots chain — curr_E equals prev_{E+1}, which this witness
// enforces as a fork condition — and prev is by definition Root(unchanged). So
// a worker holding proof E+1 can produce both of epoch E's roots from the two
// unchanged sets, report them, and never look at inserted_E: two correct roots,
// and the append-only property never checked. MayRead is what denies it the
// second proof, and this is what catches it if it gets one anyway.
//
// It catches it only if the flipped bit is in bytes the shortcut skips. Chosen
// uniformly over the file it almost never is: `unchanged` is the entire previous
// tree and `inserted` is one epoch of additions, so on the test fixture 11.77%
// of the bytes are inserted and on a Meta proof of several million nodes the
// share is smaller again. A uniform canary was therefore testing, nine times in
// ten, the one thing the shortcut still does honestly.
//
// # The split
//
// Three canaries in four aim inside `inserted`; the fourth is uniform over the
// whole proof. The minority is not there to catch the shortcut — the majority
// does that — but so that where a canary can be is not learnable. If every
// corrupted byte were in the first few megabytes, a worker could hash only the
// prefix, echo the published roots for everything after it, and pass. Keeping a
// quarter of the flips anywhere at all costs a quarter of the sensitivity to
// the shortcut and closes that, which is the better trade while the shortcut is
// the failure we can actually name.
//
// # Where inside inserted
//
// Uniformly over the field's payload bytes — the label_val and value of each
// element — and never over its framing. See PayloadOffset: a flipped length
// desynchronises everything after it and Decode rejects the whole proof, which
// is the verdict an honest verifier returns for it too, so the canary learns
// nothing from that answer. On the fixture the framing is 14.7% of `inserted`,
// so this recovers roughly one canary in seven that would otherwise have asked
// an unanswerable question.
func pickCanaryBit(head []byte, sp insertedSpan, size int64) (at int64, bit int, region string) {
	bit = int(randBelow(8))

	if sp.known && sp.end > 0 && randBelow(canaryShareOf) < canaryInsertedShare {
		field := head[:sp.end]
		if _, total, _, err := akdtree.PayloadOffset(field, insertedField, -1); err == nil && total > 0 {
			off, _, found, err := akdtree.PayloadOffset(field, insertedField, int(randBelow(int64(total))))
			if err == nil && found {
				return int64(off), bit, "inserted"
			}
		}
	}

	if size > 0 {
		at = randBelow(size)
	}
	switch {
	case !sp.known:
		region = "unknown; the framing did not parse"
	case at < int64(sp.end):
		region = "inserted"
	case sp.capped:
		// Past the point the scan reached, and the run was still going there, so
		// this may be either field. Saying "unchanged" would be a guess.
		region = "past the scanned prefix, field unknown"
	default:
		region = "unchanged"
	}
	return at, bit, region
}

// randBelow returns a uniform value in [0, n), or zero if the machine has no
// randomness to give. Zero is a legal offset, so a canary is still served; it is
// simply always the first byte, which the log line will make obvious.
func randBelow(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
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

func metricsIncOutOfLease() {
	metrics.Inc("kt_witness_proof_out_of_lease_total", nil)
}
