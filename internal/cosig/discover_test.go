package cosig

import (
	"testing"

	"filippo.io/torchwood"
)

// A real checkpoint from a Google CT log: the log signs it, a GREASE line is
// present by design, and two witnesses have cosigned. Only the witness names
// are of interest, and only the ones we cannot check.
const sampleNote = `parcelyard2026h2.prod.certificate.transparency.goog
1851786676
Uoqw8zvFnayYzT0aqa5h58PnU14iebLlMj9xLPwkPTQ=

— parcelyard2026h2.prod.certificate.transparency.goog AAAAAAAA
— grease.invalid Ym9ndXM=
— witness.navigli.sunlight.geomys.org BBBBBBBB
— witness.stagemole.eu CCCCCCCC
`

// TestUnverifiableNamesTheWitnessesWeCannotCheck.
//
// Observe skips unknown signatures silently, which is right for evidence and
// wrong for discovery: it let this witness report one peer and conclude the
// ecosystem was empty while two others were cosigning the same checkpoints.
func TestUnverifiableNamesTheWitnessesWeCannotCheck(t *testing.T) {
	v := &Verifier{byName: map[string]*torchwood.CosignatureVerifier{}}
	got := v.Unverifiable("parcelyard2026h2.prod.certificate.transparency.goog", []byte(sampleNote))

	want := []string{"witness.navigli.sunlight.geomys.org", "witness.stagemole.eu"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The log's own signature is not another witness, and neither is the GREASE
// line every static-ct log includes to keep parsers honest. Reporting either as
// a peer to go and find a key for would be noise that trains the operator to
// ignore the list.
func TestUnverifiableExcludesTheLogAndGrease(t *testing.T) {
	v := &Verifier{byName: map[string]*torchwood.CosignatureVerifier{}}
	got := v.Unverifiable("parcelyard2026h2.prod.certificate.transparency.goog", []byte(sampleNote))
	for _, n := range got {
		if n == "grease.invalid" || n == "parcelyard2026h2.prod.certificate.transparency.goog" {
			t.Errorf("%q should not be offered as a witness to go and find", n)
		}
	}
}

// A witness we already hold a key for is not a lead; it is already evidence,
// and belongs in Observe's output rather than this one.
func TestUnverifiableSkipsWitnessesWeAlreadyKnow(t *testing.T) {
	v := &Verifier{byName: map[string]*torchwood.CosignatureVerifier{"witness.stagemole.eu": nil}}
	got := v.Unverifiable("parcelyard2026h2.prod.certificate.transparency.goog", []byte(sampleNote))
	if len(got) != 1 || got[0] != "witness.navigli.sunlight.geomys.org" {
		t.Fatalf("got %v, want only the witness we cannot check", got)
	}
}
