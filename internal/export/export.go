// Package export mirrors the witness's state onto the filesystem as plain files.
//
// The database is a single bbolt file, which is right for the writing side: the
// tlog-witness spec calls out a race where two conflicting checkpoints of the
// same size are both accepted, and the fix is a compare-and-set inside one
// transaction. That guarantee is worth keeping.
//
// It is wrong for the reading side. A witness's whole product is evidence other
// people can check, and evidence locked inside a B+tree that needs our binary to
// walk is evidence with a dependency on us. Someone reproducing a fork claim
// should be able to use `cat` and `jq`.
//
// So the database stays authoritative and this writes a derived mirror beside
// it. Nothing here is a source of truth; deleting the whole directory loses
// nothing, and it is rebuilt on the next round.
//
//	<dir>/
//	  status.json                     everything at a glance
//	  checkpoints/<log>.txt           the cosigned note, byte for byte
//	  history.json                    what backfill established
//	  applications.json               observed heads (never cosigned)
//	  audits/<log>.jsonl              recent tier-B decisions, one per line
//	  forks/<log>-<unix>.json         misbehaviour evidence, one file each
//	  searches/<log>.json             the last verified search proof, a spot check
//	  entries/<log>.jsonl             leaf hash per opened entry, one per line
package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// auditWindow bounds how many recent audit decisions are mirrored per log. The
// database keeps the full history; this is the part meant to be read by hand.
const auditWindow = 2000

// Exporter writes the mirror.
type Exporter struct {
	Dir     string
	Store   *store.Store
	VKey    string
	Version string
}

// Run rewrites the mirror. It is cheap — a handful of small files — and safe to
// call after every round.
func (e *Exporter) Run(now time.Time) error {
	for _, sub := range []string{"", "checkpoints", "audits", "forks", "searches", "entries"} {
		if err := os.MkdirAll(filepath.Join(e.Dir, sub), 0o755); err != nil {
			return fmt.Errorf("export: %w", err)
		}
	}

	heads, err := e.Store.List()
	if err != nil {
		return err
	}
	forks, err := e.Store.Forks()
	if err != nil {
		return err
	}
	histories, err := e.Store.Histories()
	if err != nil {
		return err
	}
	apps, err := e.Store.AppHeads()
	if err != nil {
		return err
	}

	// The cosigned notes, verbatim. These are the artifact other witnesses and
	// monitors actually consume, so they are written exactly as served rather
	// than wrapped in JSON — a file here can be diffed against what the
	// monitoring endpoint returns.
	for _, h := range heads {
		p := filepath.Join(e.Dir, "checkpoints", slug(h.Origin)+".txt")
		if err := writeAtomic(p, h.Cosigned); err != nil {
			return err
		}
	}

	type logStatus struct {
		Origin      string    `json:"origin"`
		Size        int64     `json:"size"`
		Hash        string    `json:"root_hash"`
		WitnessedAt time.Time `json:"witnessed_at"`
		Checkpoint  string    `json:"checkpoint_file"`
		Forked      bool      `json:"forked"`
	}
	status := struct {
		Witness     string      `json:"witness"`
		VerifierKey string      `json:"verifier_key"`
		Version     string      `json:"version"`
		GeneratedAt time.Time   `json:"generated_at"`
		Note        string      `json:"note"`
		Logs        []logStatus `json:"logs"`
		ForkCount   int         `json:"fork_count"`
	}{
		VerifierKey: e.VKey,
		Version:     e.Version,
		GeneratedAt: now.UTC(),
		Note: "Derived from witness.db, which is authoritative. Checkpoint files are " +
			"the cosigned notes byte for byte. A non-empty forks/ directory means a log " +
			"was caught contradicting itself and is permanently refused.",
		ForkCount: len(forks),
	}
	if idx := strings.Index(e.VKey, "+"); idx > 0 {
		status.Witness = e.VKey[:idx]
	}
	for _, h := range heads {
		forked, err := e.Store.IsForked(h.Origin)
		if err != nil {
			return err
		}
		status.Logs = append(status.Logs, logStatus{
			Origin:      h.Origin,
			Size:        h.Size,
			Hash:        fmt.Sprintf("%x", h.Hash[:]),
			WitnessedAt: h.WitnessedAt,
			Checkpoint:  "checkpoints/" + slug(h.Origin) + ".txt",
			Forked:      forked,
		})
	}
	if err := writeJSON(filepath.Join(e.Dir, "status.json"), status); err != nil {
		return err
	}

	if err := writeJSON(filepath.Join(e.Dir, "history.json"), map[string]any{
		"note": "Verified published history from a backfill pass. Gaps are recorded, " +
			"not treated as evidence: retention limits produce them too.",
		"histories": histories,
	}); err != nil {
		return err
	}

	if err := writeJSON(filepath.Join(e.Dir, "applications.json"), map[string]any{
		"note": "OBSERVATIONS, NOT ATTESTATIONS. Per-application heads read from the " +
			"leaves of a log we witness. Signed by keys the operator does not publish " +
			"and not bound to the verified root, so they are never cosigned.",
		"applications": apps,
	}); err != nil {
		return err
	}

	// One file per fork, named by when it was caught, never rewritten. These are
	// the files someone else needs to reproduce a disclosure.
	for _, f := range forks {
		name := fmt.Sprintf("%s-%d.json", slug(f.Origin), f.DetectedAt.Unix())
		p := filepath.Join(e.Dir, "forks", name)
		if _, err := os.Stat(p); err == nil {
			continue // evidence is written once
		}
		if err := writeJSON(p, map[string]any{
			"note": "Conclusive contradiction. Both conflicting views are included " +
				"verbatim so this can be checked independently of this witness.",
			"origin":               f.Origin,
			"reason":               f.Reason,
			"detected_at":          f.DetectedAt,
			"previously_witnessed": string(f.PrevSigned),
			"conflicting":          string(f.NextSigned),
		}); err != nil {
			return err
		}
	}

	// Audits as JSON Lines: one object per line, appendable, greppable, and
	// readable by anything without loading the whole file.
	for _, h := range heads {
		records, err := e.Store.Audits(h.Origin, auditWindow)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			continue
		}
		var b strings.Builder
		// Oldest first, so the file reads forwards in time.
		for i := len(records) - 1; i >= 0; i-- {
			line, err := json.Marshal(records[i])
			if err != nil {
				return err
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		p := filepath.Join(e.Dir, "audits", slug(h.Origin)+".jsonl")
		if err := writeAtomic(p, []byte(b.String())); err != nil {
			return err
		}
	}

	// What the search proofs opened. State that exists only in log lines is
	// half-published: a witness's product is evidence other people can read, so
	// the spot check and the entries it established belong in files beside the
	// checkpoints they were verified against.
	if err := e.exportSearches(); err != nil {
		return err
	}
	for _, h := range heads {
		if err := e.exportEntries(h.Origin); err != nil {
			return err
		}
	}

	return nil
}

// slug turns a log origin into a filename. Origins look like URLs, so the
// slashes have to go, but the result should still be recognisable at a glance in
// a directory listing.
func slug(origin string) string {
	var b strings.Builder
	for _, r := range origin {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "unnamed"
	}
	return s
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(data, '\n'))
}

// writeAtomic never leaves a partially written file where a reader might pick it
// up — the mirror is meant to be copied and served while the witness runs.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("export: %w", err)
	}
	return nil
}
