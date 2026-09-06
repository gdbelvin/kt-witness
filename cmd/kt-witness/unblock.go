package main

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Running the precondition prober on a schedule.
//
// # Why this is wired into the witness
//
// kt-unblock exists because a "blocked" conclusion goes stale silently. It was
// written the day production Sigstore Rekor v2 turned out to have been live for
// months while TODO.md still said to wait for it — a stale note that cost this
// project months of not witnessing a 93-million-entry log, for want of anyone
// re-asking a question that had been answered once.
//
// It was then left as a command to run by hand, and nobody ran it. So the tool
// built to stop conclusions going stale had itself gone stale, which is the same
// failure one level up and a good argument for not relying on anyone to
// remember. Running it here puts its output in the same log as everything else,
// where it is seen by the same people looking at everything else.
//
// # Why weekly, and why it never fails the witness
//
// The things it watches — Apple deploying an RPC that exists in their proto but
// not their service, Meta publishing a pinnable key — move on the scale of
// months. Weekly is frequent enough to catch them and rare enough that the
// output stays worth reading.
//
// # One probe cannot work from here, and that is worth saying out loud
//
// kt-unblock also checks for an attached YubiKey, for the "move the signing key
// to hardware" item. Inside a container with no USB access that probe can only
// ever report "no YubiKey attached" — which reads identically to a genuine
// negative while being structurally incapable of a positive.
//
// That is precisely the failure this tool exists to prevent, so it is named
// rather than left to be rediscovered: a probe that cannot succeed is not
// evidence of anything. Run kt-unblock on the HOST when evaluating the hardware
// item; the scheduled run in here covers the network-reachable preconditions,
// which is all it can honestly claim to cover.
//
// A probe result is a lead, never a finding: it makes no assertion about any
// log and writes nothing to the store. Reachability is not correctness, and a
// precondition becoming available is the start of the work rather than the end
// of it. So this logs and nothing more — it cannot withhold a cosignature or
// mark anything forked.

const unblockInterval = 7 * 24 * time.Hour

// startUnblockProbe runs kt-unblock periodically and logs what it finds.
func startUnblockProbe(ctx context.Context, log *slog.Logger) {
	bin, err := exec.LookPath("kt-unblock")
	if err != nil {
		// Not an error worth raising: a build without the prober is a valid
		// build, and the witness's job does not depend on it.
		log.Debug("kt-unblock not present; precondition probing disabled")
		return
	}
	go func() {
		// A short initial delay so the probe does not compete with startup,
		// when the witness is fetching every log's head at once.
		t := time.NewTimer(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			runUnblockProbe(ctx, bin, log)
			t.Reset(unblockInterval)
		}
	}()
}

func runUnblockProbe(ctx context.Context, bin string, log *slog.Logger) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(cctx, bin, "-timeout", "120s").CombinedOutput()
	if err != nil && cctx.Err() == nil {
		// Exit status 1 means a probe could not be attempted, which is worth
		// knowing but is not a problem with any log.
		log.Warn("precondition probe incomplete", "err", err)
	}
	// "Still blocked" is the expected result and must not read as a failure, or
	// this becomes another red signal people learn to ignore. So every line goes
	// out at INFO and the reader decides what changed.
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		log.Info("precondition probe", "result", line)
	}
}
