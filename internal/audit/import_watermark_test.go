package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// TestSeedWatermarkUsesTheOperatorsOwnMetadata.
//
// A witness can only observe expiry that happens while it is watching, so one
// that started last week honestly reports nothing lost. The operator's own
// epoch metadata knows better: Proton stamps each epoch with the retention
// floor in force when it was published, so the oldest epoch still served states
// how much has already gone. Without this the page reports a shrinking archive
// as a stable one.
func TestSeedWatermarkUsesTheOperatorsOwnMetadata(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.RecordHistory(&store.History{
		Origin: "p/kt", From: 6236, To: 6736, Epochs: 501, VerifiedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// As observed, nothing has expired — we only just started looking.
	hs, _ := db.Histories()
	if hs[0].Expired() != 0 {
		t.Fatalf("before seeding: Expired() = %d, want 0", hs[0].Expired())
	}

	os.WriteFile(filepath.Join(dir, "manifest.jsonl"), []byte(
		`{"epoch":6236,"tree_hash":"aa","start_epoch":5718}`+"\n"+
			`{"epoch":6237,"tree_hash":"bb","start_epoch":5719}`+"\n"+
			`{"epoch":6238,"tree_hash":"cc","start_epoch":5720}`+"\n"), 0o644)
	results := filepath.Join(dir, "backfill.jsonl")
	os.WriteFile(results, []byte(
		`{"epoch":6237,"verified":true,"root":"bb","signed_root":"bb","gpu_agreed":true}`+"\n"), 0o644)

	if _, err := ImportResults(db, "p/kt", results, quietLog()); err != nil {
		t.Fatal(err)
	}
	hs, _ = db.Histories()
	if hs[0].EverFrom != 5718 {
		t.Errorf("EverFrom = %d, want 5718 — the lowest floor the operator ever published", hs[0].EverFrom)
	}
	if got := hs[0].Expired(); got != 518 {
		t.Errorf("Expired() = %d, want 518", got)
	}

	// Only ever lowers: a later run whose manifest starts higher is not
	// evidence the window grew back.
	os.WriteFile(filepath.Join(dir, "manifest.jsonl"),
		[]byte(`{"epoch":6300,"start_epoch":6000}`+"\n"), 0o644)
	if _, err := ImportResults(db, "p/kt", results, quietLog()); err != nil {
		t.Fatal(err)
	}
	hs, _ = db.Histories()
	if hs[0].EverFrom != 5718 {
		t.Errorf("watermark rose to %d; it must only ever lower", hs[0].EverFrom)
	}
}
