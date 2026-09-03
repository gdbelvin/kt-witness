// Command kt-corpus builds and replays a bounded, on-disk corpus of real
// transparency-log proofs.
//
// # Why this exists
//
// docs/cost.md is emphatic that audit proofs are verified and discarded, and
// that remains true of the witness in production: retaining Meta's and
// WhatsApp's proofs at full rate would be ~136 TB/year and would buy nothing.
// This tool is for a different job. While the verification code is still being
// validated, it is worth keeping a small, fixed set of real proofs so the
// verifiers can be re-run over them repeatedly — offline, deterministically,
// without re-downloading and without hammering a provider. It is also the only
// protection against a provider changing or withdrawing data we already
// checked: a proof we cannot re-fetch is a regression test we cannot run.
//
// # Why the caps are not advisory
//
// The witness host's volumes live on an over-provisioned thin LVM pool — about
// 1.62 TiB of volumes against a 1.71 TB pool, with roughly 691 GB free. Filling
// a thin pool does not merely fail one write; it can freeze every guest sharing
// the pool. So the corpus carries a hard total cap (default 200 GB across all
// ecosystems, not per ecosystem) and a free-space floor (default 100 GB), both
// checked before every download and enforced mid-stream. Reaching either stops
// the run. Neither is a warning an operator is trusted to notice.
//
// # Usage
//
//	kt-corpus -status
//	kt-corpus -fetch -config deploy/witness.json -sidecar ./kt-akd-verify
//	kt-corpus -verify -sidecar ./kt-akd-verify
//	kt-corpus -gc
//
// See docs/corpus.md for the on-disk layout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source/akd"
)

const (
	// defaultCap is deliberately well below the host's 691 GB of free space.
	// The user's ask was "10 to 100 GB per ecosystem"; expressed as a single
	// total this is that, with room for two AKD logs and Signal, and it leaves
	// the thin pool a large margin.
	defaultCap = 200 << 30

	// defaultFloor is the free space that must survive every download.
	defaultFloor = 100 << 30
)

func main() {
	var (
		dir        = flag.String("dir", "corpus", "corpus directory")
		capBytes   = flag.Int64("cap", defaultCap, "hard total size cap in bytes, across all ecosystems")
		floorBytes = flag.Int64("floor", defaultFloor, "minimum free space in bytes that must remain after any download")
		configPath = flag.String("config", "deploy/witness.json", "witness configuration to read log identities from")
		sidecar    = flag.String("sidecar", "", "path to the kt-akd-verify binary (required for AKD fetch and replay)")
		timeout    = flag.Duration("timeout", 10*time.Minute, "per-artifact verification timeout")

		doFetch  = flag.Bool("fetch", false, "download proofs into the corpus")
		doVerify = flag.Bool("verify", false, "re-verify every stored artifact, offline")
		doReplay = flag.Bool("replay", false, "alias for -verify")
		doGC     = flag.Bool("gc", false, "prune the corpus back under the cap")
		doStatus = flag.Bool("status", false, "report what is stored")

		akdCount       = flag.Int("akd-epochs", 4, "AKD epochs to capture per log")
		signalCount    = flag.Int("signal-captures", 8, "Signal responses to capture")
		signalInterval = flag.Duration("signal-interval", 0, "delay between Signal captures, so they describe different trees")
		originFilter   = flag.String("origin", "", "restrict the operation to one origin")
	)
	flag.Parse()

	if *doReplay {
		*doVerify = true
	}
	if !*doFetch && !*doVerify && !*doGC && !*doStatus {
		flag.Usage()
		os.Exit(2)
	}

	// A fetch run can be long and is holding a partial download; interrupting it
	// should unwind through the same cleanup path as any other error rather than
	// leaving a `.partial` file behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c := NewCorpus(*dir, *capBytes, *floorBytes)
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		fatal(err)
	}

	if *doStatus {
		if err := status(c); err != nil {
			fatal(err)
		}
	}
	if *doFetch {
		if err := fetch(ctx, c, *configPath, *sidecar, *originFilter, *akdCount, *signalCount, *signalInterval, *timeout); err != nil {
			// A limit reached is the expected end of a bounded run, and reporting
			// it as a failure would train an operator to ignore it.
			if isLimit(err) {
				fmt.Println("stopped:", err)
			} else {
				fatal(err)
			}
		}
	}
	if *doVerify {
		ok, err := verify(ctx, c, *sidecar, *originFilter, *timeout)
		if err != nil {
			fatal(err)
		}
		if !ok {
			os.Exit(1)
		}
	}
	if *doGC {
		if err := gc(c); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kt-corpus:", err)
	os.Exit(1)
}

func fetch(ctx context.Context, c *Corpus, configPath, sidecarPath, originFilter string, akdCount, signalCount int, signalInterval, timeout time.Duration) error {
	cfg, err := loadWitnessConfig(configPath)
	if err != nil {
		return err
	}
	r, err := NewReplayer(c, sidecarPath, timeout)
	if err != nil {
		return err
	}
	defer r.Close()
	f := NewFetcher(c, r, os.Stdout)

	total, err := c.TotalBytes()
	if err != nil {
		return err
	}
	free, err := c.free(c.Dir)
	if err != nil {
		return err
	}
	fmt.Printf("corpus %s: %s stored, cap %s, %s free on disk, floor %s\n",
		c.Dir, human(total), human(c.MaxBytes), human(free), human(c.MinFreeBytes))

	// Signal first, unconditionally. Its responses are ~490 KB and cover the
	// most intricate verification in the project, so per byte they are worth
	// orders of magnitude more than an AKD proof — and taking them first means a
	// run that hits a limit still ends with the most valuable artifacts stored.
	for _, l := range cfg.Logs {
		if l.Type != "signal" || (originFilter != "" && l.Origin != originFilter) {
			continue
		}
		endpoint := l.Endpoint
		if endpoint == "" {
			endpoint = "https://chat.signal.org"
		}
		if err := f.FetchSignal(ctx, l.Origin, endpoint, signalCount, signalInterval); err != nil {
			return err
		}
	}

	for _, l := range cfg.Logs {
		if l.Type != "akd" || (originFilter != "" && l.Origin != originFilter) {
			continue
		}
		if sidecarPath == "" {
			return errors.New("AKD capture needs -sidecar: an artifact is only admitted once it has verified")
		}
		if err := f.FetchAKD(ctx, akd.Config{
			Origin:            l.Origin,
			LogDirectory:      l.LogDirectory,
			PlexiNamespaceURL: l.PlexiNamespaceURL,
		}, akdCount); err != nil {
			return err
		}
	}
	return nil
}

// verify replays everything and reports pass/fail per artifact.
//
// It returns false rather than stopping at the first failure, because the useful
// output of a regression run is which artifacts broke, not merely that one did.
func verify(ctx context.Context, c *Corpus, sidecarPath, originFilter string, timeout time.Duration) (bool, error) {
	ms, err := c.Manifests()
	if err != nil {
		return false, err
	}
	r, err := NewReplayer(c, sidecarPath, timeout)
	if err != nil {
		return false, err
	}
	defer r.Close()

	var pass, fail, skipped int
	start := time.Now()
	for _, m := range ms {
		if originFilter != "" && m.Origin != originFilter {
			continue
		}
		if m.Kind == KindAKD && sidecarPath == "" {
			fmt.Printf("SKIP  %-24s %-12d no -sidecar\n", m.Origin, m.Seq)
			skipped++
			continue
		}
		t := time.Now()
		if err := r.Replay(ctx, m); err != nil {
			fmt.Printf("FAIL  %-24s %-12d %s\n", m.Origin, m.Seq, err)
			fail++
			continue
		}
		fmt.Printf("ok    %-24s %-12d %8s  %s\n", m.Origin, m.Seq, human(m.Bytes), time.Since(t).Round(time.Millisecond))
		pass++
	}
	fmt.Printf("\n%d passed, %d failed, %d skipped in %s\n", pass, fail, skipped, time.Since(start).Round(time.Millisecond))
	return fail == 0, nil
}

func gc(c *Corpus) error {
	before, err := c.TotalBytes()
	if err != nil {
		return err
	}
	dropped, err := c.GC()
	if err != nil {
		return err
	}
	after, err := c.TotalBytes()
	if err != nil {
		return err
	}
	for _, m := range dropped {
		fmt.Printf("dropped %s %s %d (%s)\n", m.Kind, m.Origin, m.Seq, human(m.Bytes))
	}
	fmt.Printf("%s -> %s, cap %s, %d artifacts dropped\n",
		human(before), human(after), human(c.MaxBytes), len(dropped))
	return nil
}

func status(c *Corpus) error {
	ms, err := c.Manifests()
	if err != nil {
		return err
	}
	free, err := c.free(c.Dir)
	if err != nil {
		return err
	}

	type agg struct {
		n              int
		bytes          int64
		lo, hi         int64
		oldest, newest time.Time
	}
	groups := map[string]*agg{}
	var order []string
	var total int64
	for _, m := range ms {
		k := string(m.Kind) + "  " + m.Origin
		g := groups[k]
		if g == nil {
			g = &agg{lo: m.Seq, hi: m.Seq, oldest: m.CapturedAt, newest: m.CapturedAt}
			groups[k] = g
			order = append(order, k)
		}
		g.n++
		g.bytes += m.Bytes
		total += m.Bytes
		if m.Seq < g.lo {
			g.lo = m.Seq
		}
		if m.Seq > g.hi {
			g.hi = m.Seq
		}
		if m.CapturedAt.Before(g.oldest) {
			g.oldest = m.CapturedAt
		}
		if m.CapturedAt.After(g.newest) {
			g.newest = m.CapturedAt
		}
	}

	fmt.Printf("corpus %s\n", c.Dir)
	for _, k := range order {
		g := groups[k]
		fmt.Printf("  %-40s %4d artifacts %10s  seq %d..%d  captured %s..%s\n",
			k, g.n, human(g.bytes), g.lo, g.hi,
			g.oldest.Format("2006-01-02"), g.newest.Format("2006-01-02"))
	}
	fmt.Printf("  %-40s %4d artifacts %10s\n", "TOTAL", len(ms), human(total))
	fmt.Printf("  cap %s (%s remaining), floor %s, %s free on disk\n",
		human(c.MaxBytes), human(c.MaxBytes-total), human(c.MinFreeBytes), human(free))
	if total > c.MaxBytes {
		fmt.Println("  OVER CAP — run -gc")
	}
	return nil
}
