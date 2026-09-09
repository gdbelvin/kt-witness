// kt-worker verifies transparency-log epochs on somebody else's machine and
// reports the verdicts back.
//
// # Why this exists
//
// The witness is CPU-bound: 31 of its 32 cores busy while its link runs at 40%
// of capacity. The cheapest cores available are the ones already in the room. A
// laptop with hardware SHA does about nine times the per-core hashing of the
// 2017 Xeon the witness runs on, and spends most of the day idle.
//
// # What it is careful about
//
// It runs in the background quality-of-service class, on the efficiency cores.
// This is not the operator's work — it is a favour the machine is doing — and a
// worker that makes a laptop unpleasant to use will be turned off, which
// verifies nothing at all.
//
// It claims no authority. It reports what it computed and the root the operator
// signed; the witness decides what that means, re-runs a sample itself, and
// treats any disagreement as its own problem to resolve rather than as a
// finding about anybody.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/work"
)

func main() {
	var (
		server     = flag.String("server", "https://witness.gdbsecurity.com", "the witness to work for")
		name       = flag.String("name", hostname(), "how this worker identifies itself")
		origins    = flag.String("origins", "", "comma-separated origins this worker can verify (default: whatever it is offered)")
		tokenEnv   = flag.String("token-env", "KT_WORK_TOKEN", "environment variable holding the shared token")
		dry        = flag.Bool("dry-run", false, "take assignments and report them unverified, to exercise the channel")
		akdBin     = flag.String("akd-bin", "", "path to kt-akd-verify")
		akdOrigins = flag.String("akd-origins", "meta.messenger.kt/v1,whatsapp.kt/v2", "origins the AKD sidecar can verify")
		protonBin  = flag.String("proton-bin", "", "path to kt-proton-gpu")
		protonDir  = flag.String("proton-dir", "", "directory holding the retained Proton tree and manifest")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	token := os.Getenv(*tokenEnv)
	if token == "" {
		log.Error("no token", "env", *tokenEnv,
			"note", "the witness closes the work channel when no token is set, rather than opening it")
		os.Exit(2)
	}

	mode, err := background()
	if err != nil {
		// Not fatal. A worker that cannot lower its own priority is merely
		// rude, and refusing to run would trade a real contribution for a
		// preference.
		log.Warn("could not enter background scheduling; continuing at normal priority", "err", err)
		mode = "normal priority"
	}
	log.Info("kt-worker", "server", *server, "name", *name, "scheduling", mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w := &worker{
		server: strings.TrimRight(*server, "/"),
		name:   *name,
		token:  token,
		dry:    *dry,
		log:    log,
		client: &http.Client{Timeout: 0}, // the assignment stream is long-lived
	}
	w.verifiers = map[string]verifier{}
	if *akdBin != "" {
		for _, o := range strings.Split(*akdOrigins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				w.verifiers[o] = akdVerifier{bin: *akdBin}
			}
		}
	}
	if *protonBin != "" && *protonDir != "" {
		w.verifiers["proton.me/kt/v1"] = protonGPUVerifier{bin: *protonBin, dir: *protonDir}
	}
	// Declare exactly what we can do. Left empty the witness may hand out
	// anything, and a worker that reports every epoch unavailable is worse than
	// one that never connected.
	if *origins != "" {
		w.origins = strings.Split(*origins, ",")
	} else {
		for o := range w.verifiers {
			w.origins = append(w.origins, o)
		}
	}
	if len(w.origins) == 0 && !*dry {
		log.Error("no verifiers configured", "hint", "set -akd-bin or -proton-bin, or use -dry-run")
		os.Exit(2)
	}

	// Reconnect on any failure. A laptop closes its lid, changes network, and
	// sleeps; none of those should need a human to restart anything, and the
	// witness reclaims an abandoned lease on its own.
	backoff := time.Second
	for ctx.Err() == nil {
		if err := w.run(ctx); err != nil && ctx.Err() == nil {
			log.Warn("disconnected", "err", err, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
	log.Info("stopped", "verified", w.verified.Load())
}

type worker struct {
	server, name, token string
	origins             []string
	dry                 bool
	log                 *slog.Logger
	client              *http.Client
	// verifiers by origin. A worker declares only the origins it has a
	// verifier for, so it is never handed work it would report as unavailable
	// — which from the witness's side looks exactly like the log being down.
	verifiers map[string]verifier

	verified atomicInt64
}

// run holds the assignment stream open and works each one as it arrives.
func (w *worker) run(ctx context.Context) error {
	q := url.Values{"name": {w.name}}
	if len(w.origins) > 0 {
		q.Set("origins", strings.Join(w.origins, ","))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.server+"/work/stream?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("work stream: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	w.log.Info("connected to the work stream")

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue // keepalive: the witness has nothing to hand out
		}
		var a work.Assignment
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			w.log.Warn("unparseable assignment", "err", err)
			continue
		}
		w.do(ctx, a)
	}
	return sc.Err()
}

// do works one assignment and streams its results back.
func (w *worker) do(ctx context.Context, a work.Assignment) {
	w.log.Info("assignment", "id", a.ID, "origin", a.Origin,
		"from", a.From, "to", a.To, "deadline", time.Until(a.Deadline).Round(time.Second).String())

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for e := a.From; e <= a.To; e++ {
		if ctx.Err() != nil {
			return
		}
		// Past the deadline the witness will refuse whatever we send, and the
		// range has probably been handed to somebody else. Stopping is the
		// polite thing and also the only useful one.
		if time.Now().After(a.Deadline) {
			w.log.Warn("lease expired mid-assignment; stopping", "id", a.ID, "reached", e)
			break
		}
		start := time.Now()
		res := work.Result{
			AssignmentID: a.ID, Nonce: a.Nonce, Origin: a.Origin,
			Epoch: e, Worker: w.name,
		}
		switch v, ok := w.verifiers[a.Origin]; {
		case w.dry:
			res.Err = "dry run"
		case !ok:
			res.Err = "no verifier configured for " + a.Origin
		default:
			ec, cancel := context.WithTimeout(ctx, epochTimeout)
			root, signed, err := v.verify(ec, a.Origin, e)
			cancel()
			switch {
			case err != nil:
				res.Err = err.Error()
			default:
				res.Root, res.SignedRoot = root, signed
				// The worker states what it computed and what the operator
				// signed. It does NOT decide what a mismatch means: that is a
				// claim about an operator's conduct, and it belongs to the
				// witness, which re-runs the epoch itself before believing it.
				res.Verified = root != "" && root == signed
			}
		}
		res.DurationMS = time.Since(start).Milliseconds()
		if res.Verified {
			w.verified.Add(1)
		}
		enc.Encode(res)
	}
	if buf.Len() == 0 {
		return
	}
	if err := w.report(ctx, &buf); err != nil {
		w.log.Warn("reporting results", "id", a.ID, "err", err)
	}
}

func (w *worker) report(ctx context.Context, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.server+"/work/results", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	w.log.Info("reported", "response", strings.TrimSpace(string(b)))
	return nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "worker"
	}
	return h
}

type atomicInt64 struct {
	mu sync.Mutex
	n  int64
}

func (a *atomicInt64) Add(n int64) { a.mu.Lock(); a.n += n; a.mu.Unlock() }
func (a *atomicInt64) Load() int64 { a.mu.Lock(); defer a.mu.Unlock(); return a.n }
