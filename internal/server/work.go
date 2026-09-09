package server

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/work"
)

// The worker channel.
//
// # Shape, and why it is not one bidirectional stream
//
// A worker holds open GET /work/stream and receives assignments as they become
// available, newline-delimited, flushed one at a time. It reports on
// POST /work/results, streaming results up the same way.
//
// One full-duplex request would be tidier and is what "streaming RPC" usually
// means. It is not what this does, because the witness is published through a
// tunnel and full-duplex HTTP is the first thing an intermediary breaks —
// usually by buffering one direction until the other completes, which converts
// a working protocol into a hang that only appears in production. Two
// half-duplex streams behave identically for this traffic and survive anything
// that can carry ordinary HTTP.
//
// # What authenticates a worker
//
// A shared token, compared in constant time. That is enough for the threat
// here: a worker cannot cause a misbehaviour finding, so the damage an
// unauthorised one could do is to waste dispatch and inflate a coverage figure
// until it is spot-checked. It is not enough to make results trustworthy, and
// nothing here treats it as though it were.

const workStreamPoll = 2 * time.Second

func (s *Server) authWorker(r *http.Request) bool {
	if s.WorkToken == "" {
		return false // no token configured: the channel is closed, not open
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.WorkToken)) == 1
}

// workStream holds the connection open and writes assignments as they appear.
func (s *Server) workStream(w http.ResponseWriter, r *http.Request) {
	if !s.authWorker(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.Work == nil {
		http.Error(w, "no work queue", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	var hello work.Hello
	hello.Name = r.URL.Query().Get("name")
	if o := r.URL.Query().Get("origins"); o != "" {
		hello.Origins = strings.Split(o, ",")
	}
	if hello.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	// Tell every intermediary not to buffer. Without it a proxy may hold the
	// stream until it closes, which looks exactly like having no work.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	enc := json.NewEncoder(w)
	ticker := time.NewTicker(workStreamPoll)
	defer ticker.Stop()

	for {
		a, err := s.Work.Lease(hello.Name, hello.Origins)
		if err == nil {
			if err := enc.Encode(a); err != nil {
				return // the worker went away; its lease will expire
			}
			flusher.Flush()
			continue
		}
		// Nothing to do. A blank line keeps the connection warm and lets the
		// worker notice a dead link rather than waiting on a queue that may
		// never fill.
		if _, err := fmt.Fprint(w, "\n"); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

// workResults reads a stream of results and records the ones that hold up.
func (s *Server) workResults(w http.ResponseWriter, r *http.Request) {
	if !s.authWorker(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.Work == nil || s.OnResult == nil {
		http.Error(w, "no work queue", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var accepted, refused int
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var res work.Result
		if json.Unmarshal([]byte(line), &res) != nil {
			refused++
			continue
		}
		// Does it answer work we handed out, to whoever we handed it to, in
		// time? This says nothing about whether the epoch verified.
		if err := s.Work.Accept(res); err != nil {
			refused++
			if s.Log != nil {
				s.Log.Warn("refusing a worker result", "assignment", res.AssignmentID,
					"epoch", res.Epoch, "err", err)
			}
			continue
		}
		if err := s.OnResult(res); err != nil {
			refused++
			if s.Log != nil {
				s.Log.Warn("recording a worker result", "epoch", res.Epoch, "err", err)
			}
			continue
		}
		accepted++
	}
	json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "refused": refused})
}
