package cosig

import (
	"io"
	"net/http"
	"os"
	"testing"
)

// stagemole's published cosignature verifier key, fetched from
// https://witness.stagemole.eu/. Pinned here rather than fetched at runtime:
// the point of verifying another witness's signature is that we hold their key
// independently, and a key we download from the same place as the signature
// proves nothing.
const stagemoleKey = "witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv"

// TestLiveReadsAnotherWitnessesCosignature is the acceptance test: a real
// checkpoint this witness already fetches carries stagemole's cosignature, and
// we can read what stagemole attested from bytes we were downloading anyway.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveReadsAnotherWitnessesCosignature(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	const origin = "thelemail.com/keys"

	resp, err := http.Get("https://tlog.thelemail.com/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	v, err := NewVerifier([]string{stagemoleKey})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := v.Observe(origin, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) == 0 {
		t.Fatal("no verifiable cosignature found — stagemole cosigns this log")
	}
	for _, o := range obs {
		t.Logf("%s attests %s at size %d, root %s, at unix %d",
			o.Witness, o.Origin, o.Size, o.Root, o.Timestamp)
		if o.Witness != "witness.stagemole.eu" {
			t.Errorf("unexpected witness %q", o.Witness)
		}
		if o.Size <= 0 || o.Root == "" || o.Timestamp == 0 {
			t.Errorf("incomplete observation: %+v", o)
		}
	}

	// Negative control: a checkpoint attributed to the wrong origin must not
	// yield an observation. A correctly cosigned checkpoint for a different log
	// says nothing about this one.
	if _, _, ok := parseBody(string(body[:120]), "someone.else/log"); ok {
		t.Error("a body was accepted under the wrong origin")
	}
}

// A signature we cannot verify is not evidence — anyone can write any name on a
// note line — so an unknown signer must be ignored rather than recorded.
func TestUnknownWitnessesAreIgnored(t *testing.T) {
	v, err := NewVerifier([]string{stagemoleKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Names()) != 1 || v.Names()[0] != "witness.stagemole.eu" {
		t.Fatalf("verifier names = %v", v.Names())
	}
	// A note with only an unknown signer yields nothing, and no error: the
	// other witnesses may simply not watch this log, and absence is not
	// evidence.
	obs, err := v.Observe("x/log", []byte("x/log\n1\nAAAA\n\n— nobody.example AAAA\n"))
	if err != nil {
		t.Fatalf("an unknown signer should be ignored, not an error: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("recorded an unverifiable cosignature: %+v", obs)
	}
}

// An empty verifier does nothing rather than failing, so the feature is opt-in.
func TestNoConfiguredWitnessesIsInert(t *testing.T) {
	v, err := NewVerifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := v.Observe("x", []byte("anything"))
	if err != nil || obs != nil {
		t.Errorf("an unconfigured verifier should be inert, got %v / %v", obs, err)
	}
}
