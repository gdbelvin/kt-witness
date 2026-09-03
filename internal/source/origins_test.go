package source

import (
	"strings"
	"testing"
)

// Cosignatures aggregate by origin. Several witnesses attesting one log under a
// single origin is the evidence a monitor consumes; the same log under two
// spellings is two logs nobody can compare. A minted origin is a name we
// invent, so it has to be the name everyone else invents.
func TestOnlyCanonicalMintedOriginsAreAccepted(t *testing.T) {
	for _, ok := range []string{
		OriginMetaMessenger, OriginWhatsApp, OriginProton,
		OriginSignal, OriginAppleTLT, OriginApplePCCAT,
	} {
		if err := CheckMintedOrigin(ok); err != nil {
			t.Errorf("canonical origin %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "meta.messenger.kt", "meta.messenger.kt/v2",
		"Meta.Messenger.KT/v1", "whatsapp.kt/v2 ", "my-own-name",
	} {
		err := CheckMintedOrigin(bad)
		if err == nil {
			t.Errorf("non-canonical origin %q was accepted", bad)
		} else if !strings.Contains(err.Error(), "aggregate") {
			t.Errorf("error for %q should explain why it matters, got: %v", bad, err)
		}
	}
}
