package signal

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// TestACISearchKey pins the construction libsignal specifies:
//
//	[SEARCH_KEY_PREFIX_ACI, self.service_id_binary()].concat()
//
// with SEARCH_KEY_PREFIX_ACI = b"a" and service_id_binary() returning the bare
// 16 UUID bytes for an ACI.
//
// This is worth a unit test rather than only a live one because the failure it
// guards is silent in the worst way: a wrong key still produces a well-formed
// request, and the VRF simply fails to verify, which looks identical to Signal
// misbehaving. Getting a fork accusation out of our own encoding bug is the
// outcome to design against.
func TestACISearchKey(t *testing.T) {
	// A UUID with every byte distinct, so a transposition or a dropped byte
	// cannot pass unnoticed.
	const aci = "00112233-4455-6677-8899-aabbccddeeff"
	got, err := ACISearchKey(aci)
	if err != nil {
		t.Fatalf("ACISearchKey: %v", err)
	}
	want, _ := hex.DecodeString("61" + "00112233445566778899aabbccddeeff")
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("search key\n got %x\nwant %x", got, want)
	}
	if len(got) != 17 {
		t.Fatalf("length %d, want 17 (1 prefix + 16 uuid)", len(got))
	}
	// The ACI branch deliberately omits the ServiceId kind byte. An 18-byte key
	// is the exact mistake this asserts against.
	if got[0] != 'a' {
		t.Fatalf("prefix %q, want 'a'", got[0])
	}
	if got[1] == 0x00 && len(got) == 18 {
		t.Fatal("ServiceId kind byte must not be included for an ACI")
	}
}

func TestACISearchKeyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-a-uuid", "00112233445566778899aabbccddee"} {
		if _, err := ACISearchKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestRedactACINeverLeaks is a guard on the one rule that protects a real
// person: the identifier must not appear in anything we log or publish.
func TestRedactACINeverLeaks(t *testing.T) {
	// The UUID here is wholly synthetic. An earlier version of this test used
	// the operator's real prefix and suffix with zeros between them, which put
	// 48 bits of a live identifier into the repository — in the test written to
	// prove that identifier never escapes. Fixtures that resemble real data are
	// how real data ends up committed.
	const aci = "3f8c1d42-9a7b-4e15-8c60-2b9df04a7e31"
	red := redactACI(aci)
	if strings.Contains(red, "3f8c1d42") || strings.Contains(red, "7e31") {
		t.Fatalf("redaction leaks the identifier: %q", red)
	}
	if red != redactACI(aci) {
		t.Fatal("redaction must be stable so two log lines can be correlated")
	}
	if redactACI("3f8c1d42-9a7b-4e15-8c60-2b9df04a7e32") == red {
		t.Fatal("redaction must distinguish different accounts")
	}
	key, _ := ACISearchKey(aci)
	if n := searchKeyName(key); strings.Contains(n, "3f8c") {
		t.Fatalf("searchKeyName leaks the identifier: %q", n)
	}
	if searchKeyName(DistinguishedKey) != "distinguished" {
		t.Fatal("the distinguished key should still be named plainly")
	}
}

// TestAccountFatalClassification pins the rule that decides whether a failed
// account search withholds the cosignature.
//
// Only a cryptographic contradiction should. If a transport failure withheld,
// Signal could silence this witness by rate-limiting it — which is exactly the
// kind of leverage a transparency system must not hand to the party being
// watched.
func TestAccountFatalClassification(t *testing.T) {
	if accountFatal(nil) {
		t.Fatal("nil is not fatal")
	}
	if accountFatal(&transportError{context.DeadlineExceeded}) {
		t.Fatal("a transport failure must not withhold the cosignature")
	}
	if !accountFatal(context.DeadlineExceeded) {
		t.Fatal("a non-transport error must withhold")
	}
}

// TestLiveAccountSearch verifies a real account proof against production.
//
// Skipped unless the account material is present in the environment. It is
// never in the repository: an ACI identifies a real person, so it lives in
// 1Password and reaches the process through `op run`.
func TestLiveAccountSearch(t *testing.T) {
	aci, key := os.Getenv("KT_SIGNAL_ACI"), os.Getenv("KT_SIGNAL_ACI_IDENTITY_KEY")
	if aci == "" || key == "" || testing.Short() {
		t.Skip("account material not in environment")
	}
	src, err := New(Config{
		Origin: "signal.org/kt", Endpoint: "https://chat.signal.org",
		AccountACI: aci, AccountIdentityKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	head, err := src.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	res := src.LastAccountSearch()
	if res == nil {
		t.Fatal("Fetch did not produce an account proof")
	}
	t.Logf("account %s verified at tree size %d: index %x…, first position %d, "+
		"version %d, %d entries opened",
		src.AccountLabel(), head.Size, res.Index[:8], res.Pos, res.Version, res.Entries)

	// The account's index must differ from the distinguished entry's, or we are
	// not actually exercising a second point in the tree.
	if d := src.LastSearch(); d != nil && d.Index == res.Index {
		t.Fatal("account and distinguished resolved to the same index")
	}
}

// TestLiveAccountWrongSearchKeyRejected is the negative control: a genuine
// response, verified against a search key that is off by one byte, must fail at
// the VRF.
//
// The obvious version of this test — ask for a different account and expect a
// refusal — does not work and is worth recording. Signal answers HTTP 403 for
// an ACI that is not the caller's, so the proof machinery is never reached; such
// a test passes while proving nothing about our verification, only about
// Signal's authorisation.
//
// So the control perturbs the KEY rather than the request. Without it, the
// positive test establishes only that some proof verified — not that it
// verified for the account we asked about, which is the entire claim.
func TestLiveAccountWrongSearchKeyRejected(t *testing.T) {
	aci, key := os.Getenv("KT_SIGNAL_ACI"), os.Getenv("KT_SIGNAL_ACI_IDENTITY_KEY")
	if aci == "" || key == "" || testing.Short() {
		t.Skip("account material not in environment")
	}
	src, err := New(Config{
		Origin: "signal.org/kt", Endpoint: "https://chat.signal.org",
		AccountACI: aci, AccountIdentityKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	head, err := src.Fetch(ctx, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	raw, err := src.searchAccountRaw(ctx, uint64(head.Size))
	if err != nil {
		t.Skipf("could not obtain a response to perturb: %v", err)
	}

	good, err := ACISearchKey(aci)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.verifyAccountResponse(raw, good); err != nil {
		t.Fatalf("the real search key failed to verify, so the control proves nothing: %v", err)
	}

	// One bit, in the UUID rather than the prefix, so the key stays structurally
	// valid and only its identity changes.
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0x01
	if _, err := src.verifyAccountResponse(raw, bad); err == nil {
		t.Fatal("a proof verified under the wrong search key: the VRF binding is not being checked")
	} else {
		t.Logf("negative control: perturbed search key correctly refused (%v)", shortenErr(err))
	}

	// And the prefix itself must matter: 'a' is what distinguishes an ACI from
	// an e164 or a username hash.
	badPrefix := append([]byte(nil), good...)
	badPrefix[0] = 'n'
	if _, err := src.verifyAccountResponse(raw, badPrefix); err == nil {
		t.Fatal("a proof verified with the e164 prefix: the type prefix is not bound")
	}
}

func shortenErr(err error) string {
	s := err.Error()
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}

// TestNoErrorLeaksTheSearchKey walks every error the search path can produce
// with an ACI key and requires that none of them contains the identifier.
//
// This exists because one did. The VRF failure message formatted the search key
// with %q, so a proof mismatch printed the raw ACI bytes into the error — and
// therefore into logs, and into any bug report pasting them. It was found by
// reading the output of the negative-control test rather than by design, which
// is precisely why it deserves a test of its own rather than a fix and a
// promise.
func TestNoErrorLeaksTheSearchKey(t *testing.T) {
	const aci = "3f8c1d42-9a7b-4e15-8c60-2b9df04a7e31"
	key, err := ACISearchKey(aci)
	if err != nil {
		t.Fatal(err)
	}
	// The raw bytes that must never appear, and the hex form a %x would produce.
	rawBytes := string(key[1:])
	hexForm := hex.EncodeToString(key[1:])

	// Drive the verifier with deliberately malformed input so it fails at
	// several different points, and check every resulting message.
	var msgs []string
	for _, m := range []message{
		{}, {1: {[]byte("not-a-vrf-proof")}},
		{1: {[]byte("x")}, 2: {[]byte("y")}},
	} {
		if _, err := verifySearch(nil, key, nil, m, 1); err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	msgs = append(msgs, searchKeyName(key))

	for _, m := range msgs {
		if strings.Contains(m, rawBytes) {
			t.Errorf("error leaks the raw identifier: %q", m)
		}
		if strings.Contains(m, hexForm) {
			t.Errorf("error leaks the hex identifier: %q", m)
		}
		if strings.Contains(m, aci) {
			t.Errorf("error leaks the ACI string: %q", m)
		}
	}
	if len(msgs) < 2 {
		t.Fatal("expected the verifier to fail on malformed input")
	}
}
