// kt-akd-diff checks the Go verifier against the published roots, on real
// proofs, and reports what it costs.
//
// This is the harness the Go implementation has to earn its way past before it
// is allowed anywhere near a verdict. Two oracles, and they answer different
// questions.
//
// The published roots are the positive oracle, and they are free: a proof's
// object key names the roots the operator committed to, so an implementation
// that rebuilds both from the proof's own nodes has agreed with Meta about the
// arithmetic. Thousands of epochs of that is strong evidence of correctness on
// valid input.
//
// It says nothing about invalid input. An implementation that returned "valid"
// unconditionally would pass every one of those checks — which is why the Rust
// reference remains the authority in production, and why -mutate exists here:
// it corrupts a proof and requires the verifier to reject it.
//
//	usage: kt-akd-diff [-n 20] [-origin meta.messenger.kt/v1] [-from EPOCH] [-mutate]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime/pprof"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/akdtree"
	"github.com/gdbsecurity/kt-witness/internal/source/akd"
)

func main() {
	var (
		configPath = flag.String("config", "deploy/witness.json", "witness config, for each log's proof directory")
		origin     = flag.String("origin", "whatsapp.kt/v2", "log to check against")
		from       = flag.Int64("from", 0, "first epoch (0 picks one from the middle of the published range)")
		n          = flag.Int("n", 10, "how many consecutive epochs to check")
		mutate     = flag.Bool("mutate", false, "also corrupt each proof and require rejection")
		cpuprofile = flag.String("cpuprofile", "", "write a CPU profile here")

		acceptance = flag.Bool("acceptance", false, "run the acceptance test: half the trials corrupted, all must be judged correctly")
		trials     = flag.Int("trials", 1000, "acceptance trials; 128 corrupted gives 2^-128 against a verifier that ignores the proof")
		corpusN    = flag.Int("proofs", 8, "how many distinct proofs to test against")
		parallel   = flag.Int("parallel", 0, "trials at once (default N-2)")
	)
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer pprof.StopCPUProfile()
	}

	sources, err := loadSources(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	src := sources[*origin]
	if src == nil {
		fmt.Fprintf(os.Stderr, "no akd log named %q in %s\n", *origin, *configPath)
		os.Exit(2)
	}

	if *acceptance {
		p := *parallel
		if p <= 0 {
			p = defaultParallel()
		}
		if !runAcceptance(resolverFor(src), *from, *corpusN, *trials, p) {
			os.Exit(1)
		}
		return
	}

	start := *from
	if start == 0 {
		fmt.Fprintln(os.Stderr, "-from is required (an epoch inside the published range)")
		os.Exit(2)
	}

	var (
		agreed, disagreed, failed int
		rejectedMutants           int
		totalNodes                int
		totalVerify               time.Duration
		totalDecode               time.Duration
	)
	for i := 0; i < *n; i++ {
		epoch := start + int64(i)
		ref, err := src.ResolveEpoch(context.Background(), epoch)
		if err != nil {
			fmt.Printf("%d  UNAVAILABLE  %v\n", epoch, err)
			failed++
			continue
		}
		body, err := fetch(fmt.Sprintf("%s/%d/%s/%s", ref.LogDirectory, epoch, ref.PrevRoot, ref.CurrRoot))
		if err != nil {
			fmt.Printf("%d  UNAVAILABLE  %v\n", epoch, err)
			failed++
			continue
		}

		t := time.Now()
		inserted, unchanged, err := akdtree.Decode(body)
		decode := time.Since(t)
		if err != nil {
			fmt.Printf("%d  DECODE ERROR  %v\n", epoch, err)
			failed++
			continue
		}

		prev, err1 := hexDigest(ref.PrevRoot)
		curr, err2 := hexDigest(ref.CurrRoot)
		if err1 != nil || err2 != nil {
			fmt.Printf("%d  BAD ROOTS IN KEY\n", epoch)
			failed++
			continue
		}

		// The proof describes the transition INTO this epoch, so the commitment
		// applied to inserted values uses this epoch number. Getting this wrong
		// verifies the start hash and fails only the end one, which looks
		// exactly like a genuine append-only violation.
		t = time.Now()
		ok, err := akdtree.VerifyAppendOnly(unchanged, inserted, prev, curr, uint64(epoch))
		verify := time.Since(t)

		nodes := len(inserted) + len(unchanged)
		totalNodes += nodes
		totalVerify += verify
		totalDecode += decode

		switch {
		case err != nil:
			fmt.Printf("%d  ERROR  %v\n", epoch, err)
			failed++
		case ok:
			agreed++
			fmt.Printf("%d  agrees   %7d nodes  decode %6.2fs  verify %6.2fs  %5.0f ns/node\n",
				epoch, nodes, decode.Seconds(), verify.Seconds(),
				float64(verify.Nanoseconds())/float64(nodes))
		default:
			disagreed++
			fmt.Printf("%d  DISAGREES with the published roots — %d nodes\n", epoch, nodes)
		}

		if *mutate && ok {
			// Flip one bit of one value. A verifier that still accepts is
			// broken in the only direction that matters.
			inserted2, unchanged2, _ := akdtree.Decode(body)
			victim := unchanged2
			if len(victim) == 0 {
				victim = inserted2
			}
			if len(victim) > 0 {
				j := rand.Intn(len(victim))
				victim[j].Value[0] ^= 1
				bad, err := akdtree.VerifyAppendOnly(unchanged2, inserted2, prev, curr, uint64(epoch))
				if err == nil && bad {
					fmt.Printf("   MUTANT ACCEPTED — a corrupted proof verified. Stop.\n")
					os.Exit(1)
				}
				rejectedMutants++
			}
		}
	}

	fmt.Printf("\n%d agreed, %d disagreed, %d unavailable\n", agreed, disagreed, failed)
	if *mutate {
		fmt.Printf("%d corrupted proofs, all rejected\n", rejectedMutants)
	}
	if totalNodes > 0 {
		fmt.Printf("%d nodes total: decode %.2fs, verify %.2fs, %.0f ns/node\n",
			totalNodes, totalDecode.Seconds(), totalVerify.Seconds(),
			float64(totalVerify.Nanoseconds())/float64(totalNodes))
	}
	if disagreed > 0 {
		os.Exit(1)
	}
}

func fetch(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func hexDigest(s string) (akdtree.Digest, error) {
	var d akdtree.Digest
	if len(s) != 64 {
		return d, fmt.Errorf("root is %d hex chars, want 64", len(s))
	}
	for i := 0; i < 32; i++ {
		var b int
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b); err != nil {
			return d, err
		}
		d[i] = byte(b)
	}
	return d, nil
}

func loadSources(path string) (map[string]*akd.Source, error) {
	return akdSourcesFromConfig(path)
}

// epochSource is the little the acceptance harness needs from a log.
type epochSource interface {
	ResolveEpoch(epoch int64) (*epochRef, error)
}

type epochRef struct {
	LogDirectory       string
	PrevRoot, CurrRoot string
}

type akdResolver struct{ s *akd.Source }

func (r akdResolver) ResolveEpoch(epoch int64) (*epochRef, error) {
	ref, err := r.s.ResolveEpoch(context.Background(), epoch)
	if err != nil {
		return nil, err
	}
	return &epochRef{LogDirectory: ref.LogDirectory, PrevRoot: ref.PrevRoot, CurrRoot: ref.CurrRoot}, nil
}

func resolverFor(s *akd.Source) epochSource { return akdResolver{s} }
