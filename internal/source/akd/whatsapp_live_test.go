package akd

import (
	"context"
	"os"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// WhatsApp's Key Transparency log — by user count the largest KT deployment
// anywhere, and reachable with no adapter changes at all.
//
// It had been written off: `whatsapp.key-transparency.v1` reports status
// Disabled with inconsistent epochs, and the note in TODO.md said "check v2
// first". v2 is Online, publishes a log directory (bucket
// `whatsapp-kt-audit-proofs`), and uses exactly the same
// epoch/prev_root/curr_root layout as Messenger — so tier A+ is configuration
// rather than code.
//
// Measured 2026-09-02: epoch 1,216,291, a new epoch every **30 seconds**, and
// ~58.5 MB per audit blob. That is a fifth of Messenger's blob at four times
// the rate, so continuous tier B would be ~168 GB/day; at the configured 0.1
// sample rate, ~17 GB/day. One real proof verified in 2.7 s under the Rust
// subprocess's WhatsAppV1Configuration, the verifier in use at the time, so
// tier B needed no new code either.
const (
	WhatsAppV2LogDirectory = "https://d4ttn6vhp3mg0.cloudfront.net"
	WhatsAppV2Namespace    = "https://plexi.key-transparency.cloudflare.com/namespaces/whatsapp.key-transparency.v2"
)

// TestLiveWhatsAppV2 proves the log is witnessable through the Source interface
// the core calls.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveWhatsAppV2(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	s, err := New(Config{
		Origin:            "whatsapp.kt/v2",
		LogDirectory:      WhatsAppV2LogDirectory,
		PlexiNamespaceURL: WhatsAppV2Namespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	head, err := s.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Logf("whatsapp v2: epoch %d, root %x", head.Size, head.Hash[:])
	if head.Size < 1_000_000 {
		t.Errorf("epoch %d is below where this log starts (1,000,000)", head.Size)
	}

	next, err := s.Fetch(ctx, head)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if err := s.VerifyConsistency(ctx, head, next); err != nil {
		t.Fatalf("VerifyConsistency %d -> %d: %v", head.Size, next.Size, err)
	}

	// The head is derived from listings, not signed by WhatsApp, so a
	// contradiction must withhold rather than accuse. Same reasoning as
	// Messenger; see docs/meta.md.
	if !s.DerivedHead() {
		t.Error("WhatsApp heads are derived from listings and must be declared as such")
	}
	if s.Tier() < source.TierAPlus {
		t.Errorf("tier is %v, expected at least A+", s.Tier())
	}
}
