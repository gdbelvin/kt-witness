package c2sp

import (
	"strings"
	"testing"
)

func TestSplitEntries(t *testing.T) {
	// Two records: "ab" and "xyz", each behind a two-byte big-endian length.
	raw := []byte{0, 2, 'a', 'b', 0, 3, 'x', 'y', 'z'}
	got, err := splitTileEntries(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "ab" || string(got[1]) != "xyz" {
		t.Fatalf("parsed %q", got)
	}
}

// A truncated tile must be rejected rather than silently yielding fewer entries
// than the tree claims, which would let leaves go unchecked.
func TestSplitEntriesRejectsTruncated(t *testing.T) {
	for name, raw := range map[string][]byte{
		"cut length prefix": {0},
		"length past end":   {0, 9, 'a', 'b'},
	} {
		if _, err := splitTileEntries(raw); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// Entry verification is off by default: it costs extra requests, and a log whose
// entries we do not read is still witnessed at tier A.
func TestTierReflectsEntryVerification(t *testing.T) {
	const vkey = "thelemail.com/keys+76ead63c+ASduViYkPgYHzuTuDnuTdEkjR/DIprnavuFA3vom4YZT"
	plain, err := New(Config{Origin: "thelemail.com/keys", BaseURL: "https://example.invalid/", VKey: vkey})
	if err != nil {
		t.Fatal(err)
	}
	if got := plain.Tier().String(); !strings.HasPrefix(got, "A ") {
		t.Fatalf("without entry verification the tier should be A, got %q", got)
	}

	full, err := New(Config{Origin: "thelemail.com/keys", BaseURL: "https://example.invalid/", VKey: vkey, VerifyEntries: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := full.Tier().String(); !strings.HasPrefix(got, "B ") {
		t.Fatalf("with entry verification the tier should be B, got %q", got)
	}
}

// A signer's name and a checkpoint's origin line are different things, and real
// logs differ in both: the Go checksum database signs the origin
// "go.sum database tree" with a key named "sum.golang.org". Constructing such a
// source must work — the origin line is pinned by the policy, not by insisting
// the two strings match.
func TestSignerNameMayDifferFromOrigin(t *testing.T) {
	const vkey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	if _, err := New(Config{
		Origin:  "go.sum database tree",
		BaseURL: "https://sum.golang.org/",
		VKey:    vkey,
	}); err != nil {
		t.Fatalf("a log whose signer name differs from its origin was refused: %v", err)
	}
}
