package audit

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loadFixture returns a real append-only proof and the roots it rebuilds.
// Regenerate with:
//
//	KT_EMIT_FIXTURE=1 go test ./internal/akdtree/ -run TestEmitFixture
func loadFixture(t *testing.T) (proof []byte, epoch int64, prev, curr string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "proof.bin"))
	if err != nil {
		t.Fatalf("fixture missing; regenerate it: %v", err)
	}
	f, err := os.Open(filepath.Join("testdata", "proof.roots"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	var e int64
	if _, err := fmt.Sscanf(strings.TrimSpace(sc.Text()), "epoch %d", &e); err != nil {
		t.Fatal(err)
	}
	sc.Scan()
	p := strings.TrimSpace(sc.Text())
	sc.Scan()
	c := strings.TrimSpace(sc.Text())
	return b, e, p, c
}

// TestTheAssembledVerifierRejectsAMutatedProof is the coverage the in-process
// canary used to provide, moved to where it belongs.
//
// internal/akdtree's mutation trials and fuzzing establish that Decode and
// VerifyAppendOnly reject a flipped bit. They say nothing about the wrapper
// around them — whether GoVerifier reports what the arithmetic concluded, or
// whether an error on the way turns into an accepting result. That gap is why
// the witness used to corrupt one production proof in a hundred and check it in
// the live path, at the cost of an extra verification of the scarcest resource
// on the machine, plus a retained proof, a scratch filesystem and something to
// delete the file.
//
// It is a unit test. It runs on every build instead of one epoch in a hundred,
// it is deterministic, and it costs nothing in production.
func TestTheAssembledVerifierRejectsAMutatedProof(t *testing.T) {
	proof, epoch, prev, curr := loadFixture(t)
	dir := t.TempDir()
	g := &GoVerifier{Concurrent: 2}

	// The fixture itself must pass, or the rejections below prove nothing.
	good := filepath.Join(dir, "good.bin")
	if err := os.WriteFile(good, proof, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := g.VerifyCached(context.Background(), "", "", epoch, prev, curr, good, time.Minute)
	if err != nil || res == nil || !res.OK {
		t.Fatalf("the unmodified fixture did not verify: %+v %v", res, err)
	}

	// Now a hundred single-bit mutations, each of which must be refused.
	rng := rand.New(rand.NewSource(4242))
	bad := filepath.Join(dir, "bad.bin")
	for i := 0; i < 100; i++ {
		mutated := make([]byte, len(proof))
		copy(mutated, proof)
		at := rng.Intn(len(mutated))
		mutated[at] ^= 1 << uint(rng.Intn(8))
		if err := os.WriteFile(bad, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := g.VerifyCached(context.Background(), "", "", epoch, prev, curr, bad, time.Minute)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		if res == nil {
			t.Fatalf("trial %d: no result", i)
		}
		if res.OK {
			t.Fatalf("trial %d: the assembled verifier ACCEPTED a proof with bit %d of "+
				"byte %d flipped. Every verdict it has produced is worthless",
				i, at, at)
		}
	}
}

// TestAnUnreadableProofIsNotAnAcceptance pins the direction the wrapper must
// fail in. "I could not check this" and "this is fine" are different answers,
// and only one of them may raise a coverage figure.
func TestAnUnreadableProofIsNotAnAcceptance(t *testing.T) {
	_, epoch, prev, curr := loadFixture(t)
	g := &GoVerifier{Concurrent: 1}
	res, err := g.VerifyCached(context.Background(), "", "", epoch, prev, curr,
		filepath.Join(t.TempDir(), "not-there.bin"), time.Minute)
	if err != nil {
		t.Fatalf("a missing proof was reported as an error rather than a result: %v", err)
	}
	if res.OK {
		t.Error("a proof that could not be read was reported as verified")
	}
	if res.Kind != "fetch" {
		t.Errorf("kind %q; a file that is not there is a fetch problem, not evidence "+
			"about the log", res.Kind)
	}
}
