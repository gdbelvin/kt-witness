package source

import "fmt"

// Canonical origin strings for the logs this project mints checkpoints for.
//
// # Why these are pinned in code
//
// For a native C2SP log the origin is chosen by the operator and carried in the
// checkpoint they sign, so there is nothing for us to decide. For a Key
// Transparency deployment there is no signed checkpoint at all — we synthesise
// one, and the origin is a name we invent. See docs/akd-checkpoint.md.
//
// A name we invent has to be the same name everyone else invents, or the whole
// exercise fails at its purpose. Cosignatures aggregate by origin: several
// witnesses attesting the same log under one origin is the evidence a monitor
// consumes, and the same log under two spellings is two logs nobody can compare.
// Leaving the string in per-deployment configuration meant two operators running
// this witness would produce cosignatures that cannot be combined, which is
// precisely the outcome a shared canonicalisation exists to prevent.
//
// So the config may still name a log, but the name has to be one of these.
//
// # Changing one
//
// Do not, once anyone has pinned a cosignature under it. A changed origin is a
// new log to every consumer, and every prior attestation silently stops
// applying to it. Adding a new deployment is fine; renaming an existing one is
// a breaking change to people who are not in this repository.
const (
	OriginMetaMessenger = "meta.messenger.kt/v1"
	OriginWhatsApp      = "whatsapp.kt/v2"
	OriginProton        = "proton.me/kt/v1"
	OriginSignal        = "signal.org/kt"
	OriginAppleTLT      = "apple.com/kt/top-level-tree"
	OriginApplePCCAT    = "apple.com/at/pcc"
)

// mintedOrigins are the origins this project defines rather than reads from an
// operator's own signed checkpoint.
var mintedOrigins = map[string]bool{
	OriginMetaMessenger: true,
	OriginWhatsApp:      true,
	OriginProton:        true,
	OriginSignal:        true,
	OriginAppleTLT:      true,
	OriginApplePCCAT:    true,
}

// CheckMintedOrigin rejects a synthesised origin that is not one of the pinned
// spellings.
//
// It applies only to adapters that mint their own checkpoints. Logs that sign
// their own — C2SP, static CT, the Go checksum database — carry the origin in
// the signed note, so it is theirs to choose and not ours to police.
func CheckMintedOrigin(origin string) error {
	if mintedOrigins[origin] {
		return nil
	}
	return fmt.Errorf(
		"origin %q is not a canonical minted origin; cosignatures aggregate by "+
			"origin, so a private spelling produces attestations that cannot be "+
			"combined with any other witness's. See internal/source/origins.go "+
			"and docs/akd-checkpoint.md", origin)
}
