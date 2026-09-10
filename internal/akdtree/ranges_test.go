package akdtree

import (
	"bufio"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
)

// What the canary is aiming at, and why it has to aim.
//
// The append-only shortcut is not a hypothetical: the published roots chain, so
// a worker holding proof E+1 can produce both of epoch E's roots out of the two
// `unchanged` sets and never read `inserted_E`. These tests establish the three
// things the witness's canary depends on — that the inserted bytes can be
// located without decoding the proof, that corrupting them produces a proof a
// real verifier rejects, and that the same corrupted proof still hands a
// shortcutting worker the previous root it would report. The last is the one
// that turns the canary into a trap rather than merely a mutation.

// fixture is the proof internal/audit tests against, with the roots it must
// rebuild. It is synthetic — emit_fixture_test.go writes it from
// makeSynthProof(300 unchanged, 40 inserted) — so the byte fractions measured
// below are properties of that shape and not a measurement of a Meta proof.
func fixture(t *testing.T) (wire []byte, prev, curr Digest, epoch uint64) {
	t.Helper()
	wire, err := os.ReadFile("../audit/testdata/proof.bin")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../audit/testdata/proof.roots")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, strings.TrimSpace(sc.Text()))
	}
	if len(lines) < 3 {
		t.Fatalf("proof.roots has %d lines, want 3", len(lines))
	}
	epoch, err = strconv.ParseUint(strings.TrimPrefix(lines[0], "epoch "), 10, 64)
	if err != nil {
		t.Fatalf("first line of proof.roots is %q, want \"epoch N\": %v", lines[0], err)
	}
	if prev, err = ParseDigest(lines[1]); err != nil {
		t.Fatal(err)
	}
	if curr, err = ParseDigest(lines[2]); err != nil {
		t.Fatal(err)
	}
	return wire, prev, curr, epoch
}

// TestFieldRangesMeasuresTheSplit is also the measurement. The number it prints
// is the one that says how badly a uniformly chosen canary bit misses: a flip
// aimed at nothing in particular lands in `inserted` exactly as often as
// `inserted` is a share of the bytes, and `inserted` is one epoch of additions
// against a copy of the entire previous tree.
func TestFieldRangesMeasuresTheSplit(t *testing.T) {
	wire, _, _, _ := fixture(t)
	inserted, unchanged, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		field int
		name  string
		count int
	}{{1, "inserted", len(inserted)}, {2, "unchanged", len(unchanged)}} {
		rs, err := FieldRanges(wire, c.field)
		if err != nil {
			t.Fatal(err)
		}
		// One range, not one per element. A proof is written in field order, so
		// coalescing collapses several million records into a single span — the
		// property that keeps this cheap enough to run on a 284 MB proof.
		if len(rs) != 1 {
			t.Errorf("%s: %d ranges, want 1 — the fields are interleaved, and every "+
				"caller assuming a single span is now wrong", c.name, len(rs))
		}
		n := 0
		for _, r := range rs {
			if r.Start < 0 || r.End > len(wire) || r.Start >= r.End {
				t.Fatalf("%s: nonsensical range %+v over %d bytes", c.name, r, len(wire))
			}
			n += r.End - r.Start
		}
		_, payload, _, err := PayloadOffset(wire, c.field, -1)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d elements, %d of %d bytes (%.2f%%), of which %d payload and %d framing (%.1f%% framing)",
			c.name, c.count, n, len(wire), 100*float64(n)/float64(len(wire)),
			payload, n-payload, 100*float64(n-payload)/float64(n))
	}

	ins, err := FieldRanges(wire, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ins[0].Start != 0 {
		t.Errorf("`inserted` does not start at byte 0 (%d); the streaming scan reads a "+
			"prefix and would find nothing", ins[0].Start)
	}
}

// TestScanLeadingFollowsAPartialProof is the property the proof server needs
// and walk cannot give it: told only a prefix, say whether the run has ended or
// whether there are simply no more bytes yet.
func TestScanLeadingFollowsAPartialProof(t *testing.T) {
	wire, _, _, _ := fixture(t)
	want, ended, err := ScanLeading(wire, 1, 0)
	if err != nil || !ended {
		t.Fatalf("scanning the whole proof: end=%d ended=%v err=%v", want, ended, err)
	}

	// Fed seven bytes at a time, resuming each time from where the last call
	// stopped. Every intermediate answer must be "not ended" and must never
	// claim ground it has not framed.
	end := 0
	for n := 0; n <= len(wire); n += 7 {
		got, ended, err := ScanLeading(wire[:min(n, len(wire))], 1, end)
		if err != nil {
			t.Fatalf("at %d bytes: %v", n, err)
		}
		if got < end {
			t.Fatalf("at %d bytes: the scan went backwards, %d then %d", n, end, got)
		}
		if got > n {
			t.Fatalf("at %d bytes: claimed %d framed", n, got)
		}
		end = got
		if ended {
			if end != want {
				t.Fatalf("at %d bytes: ended at %d, want %d", n, end, want)
			}
			return
		}
	}
	t.Fatalf("the run never ended; stopped at %d, want %d", end, want)
}

// TestScanLeadingRefusesBytesThatAreNotAProof. The server falls back to a
// uniform flip when this errors, so it must error rather than return a
// plausible offset into something it does not understand.
func TestScanLeadingRefusesBytesThatAreNotAProof(t *testing.T) {
	for _, junk := range [][]byte{[]byte("proof"), {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if end, ended, err := ScanLeading(junk, 1, 0); err == nil && ended {
			t.Errorf("%q was framed as a proof: end=%d", junk, end)
		}
	}
}

// TestACanaryInTheInsertedSetIsRejected is the whole point of aiming.
//
// Three things at once, because they are one property. A bit flipped in an
// inserted element's payload must (a) leave a proof that still decodes — if it
// did not, the verdict would be "this does not parse", which an honest verifier
// returns too and which therefore distinguishes nobody; (b) be rejected by
// VerifyAppendOnly, so the canary is a real test and not a mutation nobody
// checks; and (c) leave the `unchanged` set rebuilding the ORIGINAL previous
// root.
//
// (c) is the trap. A worker taking the shortcut computes prev from `unchanged`
// alone and gets the published value, exactly as it would from a clean proof —
// so it reports success on a proof the witness knows is corrupt, and says so in
// its own numbers. That is the alarm, and it only exists because the flip is
// inside `inserted`.
func TestACanaryInTheInsertedSetIsRejected(t *testing.T) {
	wire, prev, curr, epoch := fixture(t)
	cleanIns, cleanUnch, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	ins, err := FieldRanges(wire, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, total, _, err := PayloadOffset(wire, 1, -1)
	if err != nil || total == 0 {
		t.Fatalf("no payload bytes in `inserted`: total=%d err=%v", total, err)
	}

	rng := rand.New(rand.NewSource(20260910))
	const trials = 200
	for i := 0; i < trials; i++ {
		at, _, found, err := PayloadOffset(wire, 1, rng.Intn(total))
		if err != nil || !found {
			t.Fatalf("trial %d: locating a payload byte: found=%v err=%v", i, found, err)
		}
		if at < ins[0].Start || at >= ins[0].End {
			t.Fatalf("trial %d: byte %d is outside `inserted` %+v — the canary would be "+
				"testing the bytes the shortcut already reads", i, at, ins[0])
		}

		bad := append([]byte(nil), wire...)
		bad[at] ^= 1 << uint(rng.Intn(8))

		// (a) it still decodes, and to the same shape.
		gotIns, gotUnch, err := Decode(bad)
		if err != nil {
			t.Fatalf("trial %d: a payload flip at byte %d broke the framing: %v", i, at, err)
		}
		if len(gotIns) != len(cleanIns) || len(gotUnch) != len(cleanUnch) {
			t.Fatalf("trial %d: %d/%d elements, want %d/%d", i,
				len(gotIns), len(gotUnch), len(cleanIns), len(cleanUnch))
		}

		// (b) and a verifier rejects it.
		ok, err := VerifyAppendOnly(gotUnch, gotIns, prev, curr, epoch)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		if ok {
			t.Fatalf("trial %d: a proof corrupted at byte %d verified; the canary tests nothing", i, at)
		}

		// (c) while the shortcut still yields the published previous root.
		_, unch, err := Decode(bad)
		if err != nil {
			t.Fatal(err)
		}
		Sort(unch)
		got, err := Root(unch)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		if got != prev {
			t.Fatalf("trial %d: the corrupted proof's `unchanged` set rebuilds %x, not the "+
				"published %x — a shortcutting worker would report a mismatch and the "+
				"canary would not distinguish it from an honest one", i, got, prev)
		}
	}
	t.Logf("%d flips inside `inserted`: all decoded, all rejected, all left prev=%x intact",
		trials, prev)
}

// TestAUniformFlipUsuallyMissesTheInsertedSet is the arithmetic that motivates
// the change, done rather than asserted.
func TestAUniformFlipUsuallyMissesTheInsertedSet(t *testing.T) {
	wire, _, _, _ := fixture(t)
	ins, err := FieldRanges(wire, 1)
	if err != nil {
		t.Fatal(err)
	}
	share := float64(ins[0].End-ins[0].Start) / float64(len(wire))
	if share > 0.5 {
		t.Fatalf("`inserted` is %.1f%% of this proof; the fixture no longer has the shape "+
			"the canary is aimed at", 100*share)
	}
	t.Logf("a uniformly chosen bit lands in `inserted` %.2f%% of the time, so %.2f%% of "+
		"canaries test bytes the append-only shortcut reads anyway", 100*share, 100*(1-share))
}
