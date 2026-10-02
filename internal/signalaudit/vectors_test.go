package signalaudit

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

// loadVectors reads Signal's auditor test vectors from $SIGNAL_AUDITOR_VECTORS.
// They are AGPL-licensed and deliberately not in this repository; see the
// package documentation for the one-line fetch.
func loadVectors(tb testing.TB) *Vectors {
	tb.Helper()
	path := os.Getenv("SIGNAL_AUDITOR_VECTORS")
	if path == "" {
		tb.Skip("SIGNAL_AUDITOR_VECTORS not set; fetch with: gh api repos/trailofbits/signal-auditor/contents/tests/kt_test_vectors.pb --jq .content | base64 -d > /tmp/kt_test_vectors.pb")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	v, err := DecodeVectors(b)
	if err != nil {
		tb.Fatal(err)
	}
	if len(v.ShouldSucceed) == 0 || len(v.ShouldFail) == 0 {
		tb.Fatalf("%s: %d should_succeed, %d should_fail — not the vectors file?",
			path, len(v.ShouldSucceed), len(v.ShouldFail))
	}
	return v
}

func TestVectorsShouldSucceed(t *testing.T) {
	v := loadVectors(t)
	var s State
	kinds := map[ProofKind]int{}
	real, bytes, copath := 0, 0, 0
	for i, st := range v.ShouldSucceed {
		u, err := DecodeUpdate(st.Update)
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		kinds[u.Proof]++
		if u.Real {
			real++
		}
		bytes += len(st.Update)
		copath += len(u.Copath)
		if err := s.Apply(u); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		got, err := s.LogRoot()
		if err != nil {
			t.Fatal(err)
		}
		if got != st.LogRoot {
			t.Fatalf("update %d (%v real=%v): log root %x, want %x", i, u.Proof, u.Real, got, st.LogRoot)
		}
		// The canonical re-encoding must be byte-identical: confirms the
		// decoder dropped nothing and our writer matches Signal's.
		if enc := EncodeUpdate(u); string(enc) != string(st.Update) {
			t.Fatalf("update %d: re-encoding differs from Signal's bytes", i)
		}
	}
	nu := float64(len(v.ShouldSucceed))
	t.Logf("should_succeed: %d/%d updates replayed to the expected log root (new_tree %d, different_key %d, same_key %d; real %d, fake %d)",
		len(v.ShouldSucceed), len(v.ShouldSucceed), kinds[NewTree], kinds[DifferentKey], kinds[SameKey],
		real, len(v.ShouldSucceed)-real)
	// Each copath entry costs 34 wire bytes (tag, length, hash); the rest of
	// an update is roughly fixed. That split is what extrapolates to Signal's
	// tree, whose copaths are as deep as log2 of its key count.
	t.Logf("wire: %d bytes, %.1f bytes/update; mean copath %.2f entries; %.1f bytes/update excluding copath",
		bytes, float64(bytes)/nu, float64(copath)/nu, (float64(bytes)-34*float64(copath))/nu)
}

// The reference test (tests/vectors.rs) runs every should_fail vector against
// one shared log and checks only that the last update errs; after the third
// vector that log is no longer empty, so the later vectors fail at their first
// NewTree, for the wrong reason. Here each vector gets a fresh state, every
// update before the last must succeed, and the last must fail with the kind of
// error its description names.
func TestVectorsShouldFail(t *testing.T) {
	v := loadVectors(t)
	// Which error each description should produce: malformed (decided without
	// the tree) or a proof contradiction.
	wantProof := map[string]bool{
		"first proof type must be newTree":                   true,
		"first proof type must be real update":               false,
		"newTree proof cannot be given for a non-empty tree": true,
		"differentKey must match old root":                   true,
		"sameKey must match old root":                        true,
		"proof may not be sameKey if update type is fake":    false,
	}
	rejected := 0
	for _, fv := range v.ShouldFail {
		t.Run(fv.Description, func(t *testing.T) {
			var s State
			var err error
			for i, raw := range fv.Updates {
				var u Update
				if u, err = DecodeUpdate(raw); err == nil {
					err = s.Apply(u)
				}
				if i < len(fv.Updates)-1 && err != nil {
					t.Fatalf("update %d of %d rejected early: %v", i, len(fv.Updates), err)
				}
			}
			if err == nil {
				t.Fatal("last update accepted")
			}
			var pe *ProofError
			var me *MalformedError
			isProof, isMalformed := errors.As(err, &pe), errors.As(err, &me)
			if isProof == isMalformed {
				t.Fatalf("error is neither or both kinds: %v", err)
			}
			if want, ok := wantProof[fv.Description]; ok && want != isProof {
				t.Fatalf("got %v; want proof error = %v", err, want)
			}
			if s.Size() != uint64(len(fv.Updates)-1) {
				t.Fatalf("state advanced past the rejected update: size %d", s.Size())
			}
			t.Logf("rejected: %v", err)
			rejected++
		})
	}
	t.Logf("should_fail: %d/%d vectors rejected at their last update", rejected, len(v.ShouldFail))
}

// Bit flips in the wire bytes of Signal's own updates (every fifth, every bit):
// each must be refused or move the log root.
func TestMutationWireVectors(t *testing.T) {
	v := loadVectors(t)
	var s State
	var out mutOutcome
	identical := 0
	stride := 5
	if testing.Short() {
		stride = 25
	}
	for i, st := range v.ShouldSucceed {
		u, err := DecodeUpdate(st.Update)
		if err != nil {
			t.Fatal(err)
		}
		if i%stride == 0 {
			before0 := snapshot(t, &s)
			w := append([]byte(nil), st.Update...)
			for j := range w {
				for b := 0; b < 8; b++ {
					w[j] ^= 1 << b
					d, err := DecodeUpdate(w)
					switch {
					case err != nil:
						out.rejected++
					case reflect.DeepEqual(d, u):
						identical++
					default:
						mutate(t, &s, before0, u, d, st.LogRoot, &out)
					}
					w[j] ^= 1 << b
				}
			}
		}
		if err := s.Apply(u); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wire bit flips over every %dth vector update: %d rejected, %d changed the root, %d inert, %d decoded identical, 0 undetected",
		stride, out.rejected, out.changed, out.inert, identical)
}
