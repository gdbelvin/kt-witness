package witness

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

const (
	oldName = "witness.kt.example.com"
	newName = "witness.example.com"
)

// renameFixture is one key under two names, and a store holding a checkpoint
// cosigned under the old one — the shape a rename leaves behind on a log that
// will never advance again.
func renameFixture(t *testing.T, body string) (*store.Store, note.Verifier, []byte) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "rename.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	_, priv, _ := ed25519.GenerateKey(nil)
	was, err := torchwood.NewCosignatureSigner(oldName, priv)
	if err != nil {
		t.Fatal(err)
	}
	now, err := torchwood.NewCosignatureSigner(newName, priv)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := note.Sign(&note.Note{Text: body}, was)
	if err != nil {
		t.Fatal(err)
	}
	return db, now.Verifier(), signed
}

const ckpt = "example.com/log\n42\nqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=\n"

func put(t *testing.T, db *store.Store, signed []byte) *store.Record {
	t.Helper()
	rec := &store.Record{Origin: "example.com/log", Size: 42, Cosigned: signed, WitnessedAt: time.Now().UTC()}
	if err := db.CompareAndSet(nil, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The repair is the whole point: a checkpoint cosigned under the old name must
// verify under the published one afterwards, with the signature unchanged.
func TestRepairRewritesAFormerName(t *testing.T) {
	db, v, signed := renameFixture(t, ckpt)
	put(t, db, signed)

	if _, err := note.Open(signed, note.VerifierList(v)); err == nil {
		t.Fatal("fixture is wrong: the old-name note already verifies")
	}

	n, err := RepairCosignerName(db, v, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 record repaired, got %d", n)
	}

	rec, err := db.Get("example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := note.Open(rec.Cosigned, note.VerifierList(v))
	if err != nil {
		t.Fatalf("repaired note does not verify: %v", err)
	}
	if opened.Text != ckpt {
		t.Errorf("body changed:\n got %q\nwant %q", opened.Text, ckpt)
	}
	// The signature bytes are the same attestation, not a fresh one.
	_, oldSig, _ := parseSigLine(bytes.Split(signed, []byte("\n"))[4])
	_, newSig, _ := parseSigLine(bytes.Split(rec.Cosigned, []byte("\n"))[4])
	if !bytes.Equal(oldSig[4:], newSig[4:]) {
		t.Error("signature bytes were replaced; this must rewrite, not re-sign")
	}
}

// Running it twice must be a no-op, because a migration that runs on every
// start is the only kind nobody has to remember to run.
func TestRepairIsIdempotent(t *testing.T) {
	db, v, signed := renameFixture(t, ckpt)
	put(t, db, signed)

	if _, err := RepairCosignerName(db, v, quiet()); err != nil {
		t.Fatal(err)
	}
	first, err := db.Get("example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	n, err := RepairCosignerName(db, v, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second run repaired %d records; want 0", n)
	}
	second, _ := db.Get("example.com/log")
	if !bytes.Equal(first.Cosigned, second.Cosigned) {
		t.Error("second run rewrote the note again")
	}
}

// Somebody else's cosignature is not ours to rename, whatever name it carries.
func TestRepairLeavesOtherPartiesAlone(t *testing.T) {
	db, v, _ := renameFixture(t, ckpt)

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	other, err := torchwood.NewCosignatureSigner(oldName, otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := note.Sign(&note.Note{Text: ckpt}, other)
	if err != nil {
		t.Fatal(err)
	}
	put(t, db, theirs)

	n, err := RepairCosignerName(db, v, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("repaired %d records signed by another key; want 0", n)
	}
	rec, _ := db.Get("example.com/log")
	if !bytes.Equal(rec.Cosigned, theirs) {
		t.Error("another party's cosignature was modified")
	}
}

// A note already under the current name is left exactly as it is, and is not
// even parsed for signature lines.
func TestRepairSkipsCurrentName(t *testing.T) {
	db, v, _ := renameFixture(t, ckpt)
	_, priv, _ := ed25519.GenerateKey(nil)
	cur, err := torchwood.NewCosignatureSigner(v.Name(), priv)
	if err != nil {
		t.Fatal(err)
	}
	// A different key under the same name still opens under its own verifier;
	// use that verifier so the note is "already ours".
	ours, err := note.Sign(&note.Note{Text: ckpt}, cur)
	if err != nil {
		t.Fatal(err)
	}
	put(t, db, ours)

	n, err := RepairCosignerName(db, cur.Verifier(), quiet())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("repaired %d already-current records; want 0", n)
	}
}
