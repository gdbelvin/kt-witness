package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// The search artifact must carry the whole answer — key, index, position,
// version, entry count, committed value — and must say what it does not prove.
// A file that published the proof without the caveat would read as a coverage
// claim the evidence does not support.
func TestSearchExportCarriesTheAnswerAndItsLimits(t *testing.T) {
	e, db, out := newExporter(t)
	origin := "signal.example/kt"
	if err := db.PutSearch(origin, &store.SearchRecord{
		Key: "distinguished", Index: [32]byte{0xab}, Pos: 17, Version: 3,
		Value: []byte{0xde, 0xad}, Entries: 5, Root: [32]byte{0xcd},
		VerifiedAt: 1788300000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out, "searches", "signal.example_kt.json"))
	if err != nil {
		t.Fatalf("search export missing: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("search export is not valid JSON: %v", err)
	}
	for k, want := range map[string]any{
		"search_key":     "distinguished",
		"first_position": float64(17),
		"version":        float64(3),
		"entries_opened": float64(5),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if !strings.HasPrefix(got["vrf_index"].(string), "ab") {
		t.Errorf("vrf_index should be hex, got %v", got["vrf_index"])
	}
	if got["committed_value"] != "dead" {
		t.Errorf("committed value should be hex, got %v", got["committed_value"])
	}
	note, _ := got["note"].(string)
	if !strings.Contains(note, "SPOT CHECK") || !strings.Contains(note, "per-label") {
		t.Errorf("the note must state that this is a per-label spot check, got %q", note)
	}
}

// The ledger is JSON Lines so a 65k-entry file stays greppable; that only works
// if every line, the header included, parses on its own.
func TestEntriesLedgerIsValidJSONLinesInOrder(t *testing.T) {
	e, db, out := newExporter(t)
	origin := "signal.example/kt"
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: 9, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutLogEntries(origin, map[uint64][32]byte{
		9: {0x09}, 1: {0x01}, 4: {0x04},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out, "entries", "signal.example_kt.jsonl"))
	if err != nil {
		t.Fatalf("entries ledger missing: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want a header plus 3 entries, got %d lines", len(lines))
	}
	var header struct {
		Note  string `json:"note"`
		Count int    `json:"count"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header line is not valid JSON: %v", err)
	}
	if header.Count != 3 {
		t.Errorf("header count = %d, want 3", header.Count)
	}
	if !strings.Contains(header.Note, "not a claim about entries we never opened") {
		t.Errorf("the note must disclaim coverage, got %q", header.Note)
	}

	var prev uint64
	for i, ln := range lines[1:] {
		var rec struct {
			Entry uint64 `json:"entry"`
			Leaf  string `json:"leaf"`
		}
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("entry line %d is not valid JSON: %v", i, err)
		}
		if i > 0 && rec.Entry <= prev {
			t.Fatalf("entry ids must ascend; %d follows %d", rec.Entry, prev)
		}
		if len(rec.Leaf) != 64 {
			t.Errorf("leaf should be a 32-byte hex hash, got %q", rec.Leaf)
		}
		prev = rec.Entry
	}
}

// An origin is attacker-influenced text as far as the filesystem is concerned,
// so nothing it contains may put a file outside the export directory.
func TestSearchAndEntryFilesCannotEscapeTheDirectory(t *testing.T) {
	e, db, out := newExporter(t)
	origin := "../../etc/passwd"
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: 1, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutLogEntries(origin, map[uint64][32]byte{1: {0x01}}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSearch(origin, &store.SearchRecord{Key: "distinguished"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(out, "searches", ".._.._etc_passwd.json"),
		filepath.Join(out, "entries", ".._.._etc_passwd.jsonl"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to be written inside the export directory: %v", p, err)
		}
	}
	// Nothing at all may exist beside the export directory.
	sibling, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range sibling {
		if d.Name() == "etc" || d.Name() == "passwd" {
			t.Fatalf("an origin escaped the export directory: %s", d.Name())
		}
	}
}

// Nothing here is a source of truth: the two new artifacts must rebuild after
// the directory is deleted, and must leave no partial file behind.
func TestSearchArtifactsAreDerivedAndAtomic(t *testing.T) {
	e, db, out := newExporter(t)
	origin := "signal.example/kt"
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: 2, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutLogEntries(origin, map[uint64][32]byte{2: {0x02}}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSearch(origin, &store.SearchRecord{Key: "distinguished", Pos: 2}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(out); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatalf("the mirror must rebuild after deletion: %v", err)
	}
	for _, p := range []string{
		filepath.Join(out, "searches", "signal.example_kt.json"),
		filepath.Join(out, "entries", "signal.example_kt.jsonl"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was not rebuilt: %v", p, err)
		}
		if _, err := os.Stat(p + ".tmp"); err == nil {
			t.Errorf("temporary file left behind for %s", p)
		}
	}
}

// A witness that has never verified a search must not publish an empty file:
// present-but-empty reads as "we looked and found nothing".
func TestNoSearchFileWithoutASearch(t *testing.T) {
	e, db, out := newExporter(t)
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: "a.example/log", Size: 1, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(out, "searches"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("searches/ should be empty, got %d files", len(entries))
	}
}
