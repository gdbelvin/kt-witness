package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
)

// Acceptance is what a verifier has to pass before anything it says counts.
//
// # The test agreement cannot do
//
// Checking a verifier against real proofs only ever asks it to say yes. Every
// proof a log publishes is valid, so a verifier that returns "valid"
// unconditionally agrees with the reference on every epoch, forever, and builds
// a spotless record while checking nothing. The same holds for a worker that
// reports the operator's published root: the root is public, so its answer is
// right for a reason that has nothing to do with verification.
//
// So half the trials here are corrupted, and the verifier must reject exactly
// those and accept the rest. Getting one wrong in either direction fails the
// whole run.
//
// # Why the count is what it is
//
// A verifier that ignores the proof entirely has a one-in-two chance of being
// right about any single trial, so surviving n corrupted trials has probability
// 2^-n. At 128 that is 2^-128 — the same order of confidence the cryptography
// under all of this rests on, which is the natural place to stop arguing. A
// thousand trials costs a few minutes of one machine and puts it far past any
// question.
//
// The bound covers more than a rubber stamp. Any verifier that fails to notice
// some fraction f of single-bit corruptions is caught with probability
// 1-(1-f)^k over k corrupted trials: a verifier blind to 1% of bit flips gets
// through 128 trials about a quarter of the time and 1000 trials essentially
// never.
//
// # One bit, anywhere
//
// Not a chosen field and not a mangled file. A verifier that checks the
// structure but skips a hash will reject garbage and accept the forgery that
// matters, and only a single flipped bit in an arbitrary position tells those
// apart.

type trialResult struct {
	trial     int
	proof     string
	corrupted bool
	where     string
	accepted  bool
}

// runAcceptance downloads a handful of real proofs and runs trials against
// them. It returns false if the verifier got any trial wrong.
func runAcceptance(src epochSource, from int64, proofs, trials, parallel int) bool {
	dir, err := os.MkdirTemp("", "kt-acceptance-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	defer os.RemoveAll(dir)

	// Several distinct proofs, not one reused: a single proof tests one tree
	// shape, and the shapes differ across a log's history.
	type sample struct {
		path       string
		epoch      int64
		prev, curr akdtree.Digest
	}
	var corpus []sample
	fmt.Printf("fetching %d proofs to test against\n", proofs)
	for i := 0; len(corpus) < proofs && i < proofs*3; i++ {
		epoch := from + int64(i)
		ref, err := src.ResolveEpoch(epoch)
		if err != nil {
			continue
		}
		body, err := fetch(fmt.Sprintf("%s/%d/%s/%s", ref.LogDirectory, epoch, ref.PrevRoot, ref.CurrRoot))
		if err != nil {
			continue
		}
		prev, e1 := akdtree.ParseDigest(ref.PrevRoot)
		curr, e2 := akdtree.ParseDigest(ref.CurrRoot)
		if e1 != nil || e2 != nil {
			continue
		}
		p := filepath.Join(dir, fmt.Sprintf("%d.bin", epoch))
		if err := os.WriteFile(p, body, 0o600); err != nil {
			continue
		}
		corpus = append(corpus, sample{path: p, epoch: epoch, prev: prev, curr: curr})
		fmt.Printf("  epoch %d (%.0f MB)\n", epoch, float64(len(body))/1e6)
	}
	if len(corpus) == 0 {
		fmt.Fprintln(os.Stderr, "no proofs could be fetched; nothing to test against")
		return false
	}

	fmt.Printf("\nrunning %d trials, half corrupted, %d at a time\n\n", trials, parallel)
	var (
		wrong     atomic.Int64
		corrupted atomic.Int64
		clean     atomic.Int64
		mu        sync.Mutex
		failures  []trialResult
	)
	start := time.Now()

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var v akdtree.Verifier
			for n := range jobs {
				s := corpus[randN(len(corpus))]
				data, err := os.ReadFile(s.path)
				if err != nil {
					continue
				}
				// A fair coin, from the same source as the bit position: a
				// predictable schedule would let a verifier that wanted to
				// cheat learn which trials mattered.
				doCorrupt := randN(2) == 0
				where := ""
				if doCorrupt {
					i := randN(len(data))
					bit := randN(8)
					data[i] ^= byte(1) << uint(bit)
					where = fmt.Sprintf("byte %d/%d bit %d", i, len(data), bit)
					corrupted.Add(1)
				} else {
					clean.Add(1)
				}

				accepted := false
				if inserted, unchanged, dErr := akdtree.Decode(data); dErr == nil {
					// A proof that will not decode has not been accepted, which
					// is the property under test.
					if ok, vErr := v.VerifyAppendOnly(unchanged, inserted, s.prev, s.curr, uint64(s.epoch)); vErr == nil {
						accepted = ok
					}
				}

				if accepted == doCorrupt {
					wrong.Add(1)
					mu.Lock()
					failures = append(failures, trialResult{
						trial: n, proof: s.path, corrupted: doCorrupt,
						where: where, accepted: accepted,
					})
					mu.Unlock()
				}
			}
		}()
	}
	for n := 0; n < trials; n++ {
		jobs <- n
	}
	close(jobs)
	wg.Wait()

	took := time.Since(start)
	c, cl, w := corrupted.Load(), clean.Load(), wrong.Load()
	fmt.Printf("%d trials in %s: %d corrupted, %d clean\n", trials, took.Round(time.Second), c, cl)

	if w > 0 {
		fmt.Printf("\nFAILED — %d trials wrong\n\n", w)
		for i, f := range failures {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(failures)-10)
				break
			}
			what := "accepted a corrupted proof"
			if !f.corrupted {
				what = "rejected a valid proof"
			}
			fmt.Printf("  trial %d: %s (%s) proof=%s\n", f.trial, what, f.where, f.proof)
		}
		fmt.Println("\nThis verifier must not be trusted with a verdict.")
		return false
	}

	fmt.Printf("\nPASSED — every corrupted proof rejected, every valid one accepted.\n")
	fmt.Printf("A verifier ignoring the proof would survive %d corrupted trials with\n", c)
	if c >= 1024 {
		fmt.Printf("probability 2^-%d, which is not a number anybody needs to think about.\n", c)
	} else {
		fmt.Printf("probability 2^-%d.\n", c)
	}
	if c < 128 {
		fmt.Printf("\nNOTE: fewer than 128 corrupted trials. That is %s confidence, not the\n", fmt.Sprintf("2^-%d", c))
		fmt.Printf("cryptographic kind — raise -trials before trusting this.\n")
	}
	return true
}

func randN(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// Falling back to a predictable source would silently weaken the whole
		// test, so refuse rather than continue.
		panic("acceptance: no randomness available: " + err.Error())
	}
	return int(v.Int64())
}

func defaultParallel() int {
	n := runtime.NumCPU() - 2
	if n < 1 {
		return 1
	}
	return n
}
