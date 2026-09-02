package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/tlog"
)

func newExporter(t *testing.T) (*Exporter, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	out := filepath.Join(dir, "public")
	return &Exporter{
		Dir: out, Store: db,
		VKey:    "witness.kt.example.com+576de60c+BOwbxlxZ",
		Version: "test",
	}, db, out
}

func TestSlugIsFilesystemSafeAndRecognisable(t *testing.T) {
	for in, want := range map[string]string{
		"thelemail.com/keys":          "thelemail.com_keys",
		"meta.messenger.kt/v1":        "meta.messenger.kt_v1",
		"apple.com/kt/top-level-tree": "apple.com_kt_top-level-tree",
		"":                            "unnamed",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	// No separators can survive, or a log origin could escape the directory.
	if s := slug("../../etc/passwd"); strings.ContainsAny(s, "/\\") {
		t.Fatalf("slug leaked a path separator: %q", s)
	}
}

// The checkpoint file is what other witnesses and monitors consume, so it must
// be the cosigned note byte for byte, not a re-encoding of it.
func TestCheckpointsAreWrittenVerbatim(t *testing.T) {
	e, db, out := newExporter(t)
	note := []byte("example.com/log\n42\nabcd\n\n— witness sig\n")
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: "example.com/log", Size: 42, Hash: tlog.Hash{1},
		Cosigned: note, WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(out, "checkpoints", "example.com_log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(note) {
		t.Fatalf("checkpoint was not written verbatim:\n got %q\nwant %q", got, note)
	}
}

// Fork evidence is the thing a third party needs to check a disclosure without
// running this binary, so both conflicting views must be in the file.
func TestForkEvidenceIsSelfContained(t *testing.T) {
	e, db, out := newExporter(t)
	when := time.Unix(1788300000, 0).UTC()
	if err := db.RecordFork(&store.Fork{
		Origin: "example.com/log", Reason: "split view at size 10",
		DetectedAt: when,
		PrevSigned: []byte("PREVIOUS NOTE"), NextSigned: []byte("CONFLICTING NOTE"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(out, "forks", "example.com_log-1788300000.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("fork evidence file missing: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("fork evidence is not valid JSON: %v", err)
	}
	if got["previously_witnessed"] != "PREVIOUS NOTE" || got["conflicting"] != "CONFLICTING NOTE" {
		t.Fatalf("both views must be present verbatim, got %v", got)
	}

	// Evidence is written once and never rewritten.
	if err := os.WriteFile(p, []byte(`{"tampered":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(p)
	if string(again) != `{"tampered":true}` {
		t.Fatal("existing fork evidence must not be rewritten")
	}
}

func TestStatusIsValidJSONAndNamesEachLog(t *testing.T) {
	e, db, out := newExporter(t)
	for _, o := range []string{"a.example/log", "b.example/log"} {
		if err := db.CompareAndSet(nil, &store.Record{
			Origin: o, Size: 7, Cosigned: []byte("note"), WitnessedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Witness     string `json:"witness"`
		VerifierKey string `json:"verifier_key"`
		Logs        []struct {
			Origin     string `json:"origin"`
			Checkpoint string `json:"checkpoint_file"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("status.json is not valid JSON: %v", err)
	}
	if status.Witness != "witness.kt.example.com" {
		t.Fatalf("witness name should come from the verifier key, got %q", status.Witness)
	}
	if len(status.Logs) != 2 {
		t.Fatalf("want 2 logs, got %d", len(status.Logs))
	}
	// Every referenced checkpoint file must actually exist.
	for _, l := range status.Logs {
		if _, err := os.Stat(filepath.Join(out, l.Checkpoint)); err != nil {
			t.Errorf("status references %s for %s, which is missing", l.Checkpoint, l.Origin)
		}
	}
}

// Audits are JSON Lines so they can be grepped and streamed; every line must
// parse on its own.
func TestAuditsAreValidJSONLines(t *testing.T) {
	e, db, out := newExporter(t)
	origin := "a.example/log"
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: origin, Size: 3, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	for epoch := int64(1); epoch <= 3; epoch++ {
		if _, _, err := db.ObserveAppHead(time.Now(), &store.AppHead{Origin: origin, TreeID: 1}); err != nil {
			t.Fatal(err)
		}
		if err := db.RecordAudit(&store.Audit{
			Origin: origin, Epoch: epoch, Sampled: true, Verified: true,
			Rate: 0.1, DecidedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(out, "audits", "a.example_log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	var prev int64
	for i, ln := range lines {
		var a store.Audit
		if err := json.Unmarshal([]byte(ln), &a); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if a.Epoch <= prev {
			t.Fatalf("lines should read forwards in time; line %d has epoch %d after %d", i, a.Epoch, prev)
		}
		prev = a.Epoch
	}
}

// The mirror is derived: losing it must cost nothing.
func TestMirrorIsRebuiltFromScratch(t *testing.T) {
	e, db, out := newExporter(t)
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: "a.example/log", Size: 1, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
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
	if _, err := os.Stat(filepath.Join(out, "checkpoints", "a.example_log.txt")); err != nil {
		t.Fatal("checkpoint not rebuilt")
	}
}

// No .tmp files may survive: the directory is meant to be copied or served
// while the witness is running.
func TestNoTempFilesLeftBehind(t *testing.T) {
	e, db, out := newExporter(t)
	if err := db.CompareAndSet(nil, &store.Record{
		Origin: "a.example/log", Size: 1, Cosigned: []byte("note"), WitnessedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(time.Now()); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".tmp") {
			t.Errorf("temporary file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
