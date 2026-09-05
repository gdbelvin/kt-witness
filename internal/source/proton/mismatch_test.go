package proton

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestMismatchIsDistinguishableFromCouldNotCheck is the guard against the
// mistake this project has already made once: reporting our own inability to
// fetch as evidence that an operator misbuilt its tree.
//
// A 403 on a diff download says nothing whatsoever about how Proton constructed
// its directory. Only a rebuilt root that disagrees with the signed one does.
func TestMismatchIsDistinguishableFromCouldNotCheck(t *testing.T) {
	real := &MismatchError{From: 6724, To: 6725, Computed: "aaaa", Signed: "bbbb"}
	fetch := fmt.Errorf("proton: GET https://proton.me/kt/epoch.1.6725.diff: HTTP %d", 403)

	var mm *MismatchError
	if !errors.As(real, &mm) {
		t.Fatal("a genuine mismatch must be recognisable")
	}
	if errors.As(fetch, &mm) {
		t.Fatal("a failed download must NOT be recognised as a construction failure")
	}

	// The message has to carry both roots, or the finding cannot be reproduced
	// by anyone else — which is the whole point of retaining evidence.
	msg := real.Error()
	for _, want := range []string{"6724", "6725", "aaaa", "bbbb"} {
		if !strings.Contains(msg, want) {
			t.Errorf("mismatch message omits %q: %s", want, msg)
		}
	}

	// And it must survive wrapping, since callers add context.
	wrapped := fmt.Errorf("proton audit: %w", real)
	if !errors.As(wrapped, &mm) {
		t.Fatal("mismatch is lost when wrapped")
	}
}
