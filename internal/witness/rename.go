package witness

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

// RepairCosignerName rewrites stored cosignatures that carry a name this
// witness no longer answers to.
//
// Renaming the witness left two published checkpoints unverifiable by anyone
// who only has the current verifier key. The name is not in what
// cosignature/v1 signs — the signed message is the timestamp and the log's own
// checkpoint body — but it IS in the signature line, and the four-byte key hash
// beside it is derived from name and key together. So a cosignature issued
// under the old name presents a key hash nobody looking us up can match, and
// the line is skipped as belonging to a party they do not know.
//
// Almost every log fixed itself: the next round overwrites the record. The ones
// that cannot are closed shards, whose tree never advances again, so their last
// cosignature is their last forever. Reported as issue #1 against two 2026h1
// CT shards, fourteen days after the rename.
//
// Invoked by -repair-cosigner-name, not on every start. A rename is a thing an
// operator does, so the repair is a thing an operator runs — and a reconciler
// that rewrites published attestations unprompted would turn a typo in the
// config's name into a rewrite of all of them.
//
// This rewrites rather than re-signs, which is the honest operation: the
// attestation and the moment it was made are unchanged, and the timestamp still
// says when we actually saw that tree. Re-signing would silently restate a
// two-week-old observation as a fresh one.
//
// A line is only rewritten when the result verifies under our own key, so this
// cannot touch another party's cosignature even if one carried a name we once
// used. That also makes it idempotent: a second run finds nothing to do,
// because a note that already verifies is skipped before any line is examined.
func RepairCosignerName(db *store.Store, v note.Verifier, log *slog.Logger) (int, error) {
	recs, err := db.List()
	if err != nil {
		return 0, fmt.Errorf("witness: rename repair: list: %w", err)
	}
	fixed := 0
	for _, rec := range recs {
		if len(rec.Cosigned) == 0 {
			continue
		}
		if _, err := note.Open(rec.Cosigned, note.VerifierList(v)); err == nil {
			continue // already carries our current name
		}
		repaired, old, ok := renameOurSignature(rec.Cosigned, v)
		if !ok {
			continue
		}
		next := *rec
		next.Cosigned = repaired
		if err := db.CompareAndSet(rec, &next); err != nil {
			return fixed, fmt.Errorf("witness: rename repair %s: %w", rec.Origin, err)
		}
		fixed++
		log.Warn("rewrote a cosignature issued under a former name",
			"origin", rec.Origin, "size", rec.Size, "was", old, "now", v.Name())
	}
	return fixed, nil
}

// renameOurSignature finds the signature line in a note that is ours under some
// other name, and returns the note with that line restated under the current
// one. Every other byte is preserved: the body, and the log's and other
// witnesses' signatures, are not re-serialized. It reports whether it found
// one, and the name it replaced.
func renameOurSignature(signed []byte, v note.Verifier) (out []byte, oldName string, ok bool) {
	lines := bytes.Split(signed, []byte("\n"))
	for i, ln := range lines {
		name, sig, isSig := parseSigLine(ln)
		if !isSig || name == v.Name() || len(sig) < 4 {
			continue
		}
		candidate := bytes.Join(replaced(lines, i, sigLine(v, sig[4:])), []byte("\n"))
		if _, err := note.Open(candidate, note.VerifierList(v)); err != nil {
			continue // somebody else's signature; leave it alone
		}
		return candidate, name, true
	}
	return nil, "", false
}

// parseSigLine splits "— <name> <base64>" into its parts. The dash is an em
// dash, per the note format.
func parseSigLine(ln []byte) (name string, sig []byte, ok bool) {
	rest, found := bytes.CutPrefix(ln, []byte("— "))
	if !found {
		return "", nil, false
	}
	n, b64, found := bytes.Cut(rest, []byte(" "))
	if !found {
		return "", nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return "", nil, false
	}
	return string(n), raw, true
}

// sigLine renders a signature line under v's name and key hash. The hash is
// v's, not the one the bytes arrived with, which is the whole point: it is
// derived from the name, so it has to be recomputed alongside it.
func sigLine(v note.Verifier, sig []byte) []byte {
	raw := make([]byte, 0, 4+len(sig))
	raw = binary.BigEndian.AppendUint32(raw, v.KeyHash())
	raw = append(raw, sig...)
	return fmt.Appendf(nil, "— %s %s", v.Name(), base64.StdEncoding.EncodeToString(raw))
}

// replaced returns lines with index i swapped for ln, without disturbing the
// caller's slice.
func replaced(lines [][]byte, i int, ln []byte) [][]byte {
	out := make([][]byte, len(lines))
	copy(out, lines)
	out[i] = ln
	return out
}
