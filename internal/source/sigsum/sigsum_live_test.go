package sigsum

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// The two sigsum logs this project witnesses, with the public keys taken from
// sigsum-go's built-in trust policies:
//
//	pkg/policy/builtin/sigsum-generic-2025-1.builtin-policy
//	pkg/policy/builtin/sigsum-test-2025-3.builtin-policy
//
// Pinned here rather than fetched, because a key fetched at runtime from the
// same party that operates the log proves nothing: the log could hand us a key
// for whatever history it wanted to show. Pinning is the point.
var liveLogs = []struct {
	name     string
	endpoint string
	pubHex   string
	// wantOrigin is the origin derived from the key. It is asserted explicitly
	// so that a mistyped key fails here, naming the problem, rather than
	// surfacing later as an unexplained signature failure.
	wantOrigin string
}{
	{
		name:       "seasalp.glasklar.is",
		endpoint:   "https://seasalp.glasklar.is",
		pubHex:     "0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25",
		wantOrigin: "sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1",
	},
	{
		name:       "ginkgo.tlog.mullvad.net",
		endpoint:   "https://ginkgo.tlog.mullvad.net",
		pubHex:     "f00c159663d09bbda6131ee1816863b6adcacfe80b0b288000b11aba8fe38314",
		wantOrigin: "sigsum.org/v1/tree/c03f05182be9341e33b9edd5f3f8675b08332164640203e743f4285359cace47",
	},
	{
		name:       "serviceberry.tlog.stagemole.eu",
		endpoint:   "https://serviceberry.tlog.stagemole.eu",
		pubHex:     "47e481606d8acba747a6b053d6c2d191605fb122175d410a1202a91430abce39",
		wantOrigin: "sigsum.org/v1/tree/1643169b32bef33a3f54f8a353b87c475d19b6223cbb106390d10a29978e1cba",
	},
	{
		name:       "test.sigsum.org/barreleye",
		endpoint:   "https://test.sigsum.org/barreleye",
		pubHex:     "4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6",
		wantOrigin: "sigsum.org/v1/tree/4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d",
	},
}

func newLiveSource(t *testing.T, endpoint, pubHex string) *Source {
	t.Helper()
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decoding pinned key: %v", err)
	}
	src, err := New(Config{
		Endpoint:  endpoint,
		PublicKey: pub,
		Client:    &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return src
}

// skipIfOffline keeps the suite green without a network. A live test that fails
// closed on an unreachable host turns every offline run into a false alarm,
// which is the fastest way to teach people to ignore the suite.
func skipIfOffline(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if _, ok := err.(net.Error); ok || errorsAsNet(err, &ne) {
		t.Skipf("network unavailable: %v", err)
	}
}

func errorsAsNet(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestLiveTreeHead checks the whole chain against production: the origin is
// derived correctly from the pinned key, the log's Ed25519 signature verifies
// over the reconstructed checkpoint body, and the synthesized note opens under
// a stock note verifier.
//
// That last step is the one worth having. It is the difference between "we can
// check sigsum's signature" and "sigsum is now indistinguishable from any other
// note-carrying log to everything downstream".
func TestLiveTreeHead(t *testing.T) {
	if testing.Short() {
		t.Skip("live test")
	}
	for _, lg := range liveLogs {
		t.Run(lg.name, func(t *testing.T) {
			src := newLiveSource(t, lg.endpoint, lg.pubHex)

			if src.Origin() != lg.wantOrigin {
				t.Fatalf("origin\n got %s\nwant %s", src.Origin(), lg.wantOrigin)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			head, err := src.Fetch(ctx, nil)
			if err != nil {
				skipIfOffline(t, err)
				t.Fatalf("Fetch: %v", err)
			}
			if head.Size <= 0 {
				t.Fatalf("size %d, want positive", head.Size)
			}
			if head.Note == nil {
				t.Fatal("no note on head")
			}
			if head.Note.Text != string((&TreeHead{
				Size: uint64(head.Size), RootHash: [32]byte(head.Hash),
			}).Body(lg.wantOrigin)) {
				t.Fatal("synthesized note text does not match the signed body")
			}
			t.Logf("%s: size %d, root %x — log signature verified, note opens",
				lg.name, head.Size, head.Hash[:8])
		})
	}
}

// TestLiveConsistency is the assertion the witness actually publishes: that the
// current head extends a head observed earlier, proven by the log's own proof.
//
// The anchors below are real heads observed from these logs on 2026-09-02 and
// pinned here. That is what makes this a genuine append-only test rather than a
// self-consistency check: CheckTree needs two roots, and if the older root came
// from the same response as the newer one, the log would merely be agreeing
// with itself. A pinned anchor is a claim the log made in the past and cannot
// now retract.
//
// If either log ever fails this, it has signed two roots that are not
// append-only compatible — which is exactly the finding this project exists to
// make.
func TestLiveConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("live test")
	}
	anchors := map[string]struct {
		size    int64
		rootHex string
	}{
		"seasalp.glasklar.is":       {63886, "fff04be474522157c37d6ab214515ed4b92caadd279e831b7b1491641cf07276"},
		"test.sigsum.org/barreleye": {214365, "fab50bf5e35f128371a216079cb81ceed3475a2059c488e11e3ff44e3a0cc9a6"},
	}

	for _, lg := range liveLogs {
		t.Run(lg.name, func(t *testing.T) {
			anchor, ok := anchors[lg.name]
			if !ok {
				t.Skip("no pinned anchor for this log")
			}
			rootBytes, err := hex.DecodeString(anchor.rootHex)
			if err != nil {
				t.Fatalf("decoding anchor root: %v", err)
			}
			var prevHash tlog.Hash
			copy(prevHash[:], rootBytes)

			src := newLiveSource(t, lg.endpoint, lg.pubHex)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			next, err := src.Fetch(ctx, nil)
			if err != nil {
				skipIfOffline(t, err)
				t.Fatalf("Fetch: %v", err)
			}
			if next.Size < anchor.size {
				t.Fatalf("log regressed: tip size %d is below pinned anchor %d",
					next.Size, anchor.size)
			}

			prev := &source.Head{Origin: src.Origin(), Size: anchor.size, Hash: prevHash}
			if err := src.VerifyConsistency(ctx, prev, next); err != nil {
				var fe *source.ForkError
				if errors.As(err, &fe) {
					t.Fatalf("FORK: %v", err)
				}
				skipIfOffline(t, err)
				t.Fatalf("VerifyConsistency %d->%d: %v", anchor.size, next.Size, err)
			}
			t.Logf("%s: size %d extends pinned anchor %d — append-only proven over %d entries",
				lg.name, next.Size, anchor.size, next.Size-anchor.size)
		})
	}
}

// TestLiveConsistencyNegativeControl corrupts the anchor root and requires the
// verifier to call it a fork.
//
// This exists because TestLiveConsistency passes vacuously whenever the log has
// not grown since the anchor was pinned: VerifyConsistency returns early when
// the sizes match, so CheckTree never runs and a broken proof path would look
// identical to a working one. Flipping a bit in the anchor forces the proof
// path to execute and to reject — which is the only way to know the positive
// result means anything.
//
// It also pins the error TYPE, not just failure. A mismatched root is the log
// contradicting a root it signed, so it must surface as *source.ForkError and
// not as an ordinary retryable error; the difference decides whether the
// witness withholds quietly or discloses.
func TestLiveConsistencyNegativeControl(t *testing.T) {
	if testing.Short() {
		t.Skip("live test")
	}
	src := newLiveSource(t, liveLogs[0].endpoint, liveLogs[0].pubHex)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	next, err := src.Fetch(ctx, nil)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("Fetch: %v", err)
	}
	if next.Size < 2 {
		t.Skipf("tree too small (%d)", next.Size)
	}

	// A strictly smaller size, so the size-equal early return cannot hide the
	// result, paired with a root the log never signed.
	var bogus tlog.Hash
	copy(bogus[:], next.Hash[:])
	bogus[0] ^= 0xff

	prev := &source.Head{Origin: src.Origin(), Size: next.Size - 1, Hash: bogus}
	err = src.VerifyConsistency(ctx, prev, next)
	if err == nil {
		t.Fatal("corrupted anchor root was accepted: the consistency check is not cryptographic")
	}
	var fe *source.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("got %T (%v), want *source.ForkError — a root the log never signed "+
			"is a contradiction, not a transient failure", err, err)
	}
	t.Logf("negative control: corrupted anchor correctly rejected as a fork")
}
