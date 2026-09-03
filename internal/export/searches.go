package export

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// searchNote is what the searches/ artifact does and — the harder half — does
// not establish. A search proof chains a VRF output to a prefix-tree entry, that
// entry to a log position, and that position to a root the operator signed, so
// it does promote "the log is self-consistent" to "the log says X about this
// identifier". But the proofs are per-label: they only answer about identifiers
// the asker can already name, and the VRF exists precisely so that nobody can
// enumerate the rest. Verifying every proof we can obtain therefore still leaves
// the vast majority of the directory unexamined, which is why the witness claims
// tier A plus a continuously verified spot check rather than tier B. A file that
// omitted that would read like a coverage claim.
const searchNote = "A SPOT CHECK, NOT A CONSTRUCTION AUDIT. This is the most recent " +
	"search proof the witness verified end to end: VRF output, prefix tree, log " +
	"inclusion, and commitment, with the implied root compared against a root the " +
	"operator signed. It proves what the log says about THIS identifier at this " +
	"moment. It says nothing about any other identifier: these proofs are per-label " +
	"and the VRF is designed to make the rest of the directory unenumerable, so no " +
	"number of them adds up to an audit of how the tree was built. Full coverage " +
	"needs the operator's auditor feed."

// entriesNote describes the cross-observation ledger. The check it supports is
// narrow and worth stating exactly: an entry that changed contents between two
// proofs would contradict append-only in a way head consistency cannot see. An
// entry that agrees proves only that it did not change while we were looking.
const entriesNote = "Leaf hashes of log entries this witness has opened and verified, " +
	"accumulated across polls. A log entry is immutable once written, so an entry " +
	"whose leaf hash differs from what is recorded here — with both observations " +
	"chaining to roots the operator signed — is a contradiction the append-only " +
	"checks cannot detect. Agreement proves only that these entries did not change " +
	"between our observations: it is not a claim about entries we never opened, nor " +
	"about the log's construction. Only the lowest ids are retained (cap: 65536), so " +
	"a missing id means unrecorded, never absent from the log."

// searchSummary is the published shape. Hashes are hex rather than the base64 or
// integer arrays Go would choose, because the point of the mirror is that a
// person with `jq` can compare a field against what some other tool printed.
type searchSummary struct {
	Note        string    `json:"note"`
	Origin      string    `json:"origin"`
	Key         string    `json:"search_key"`
	Index       string    `json:"vrf_index"`
	Pos         uint64    `json:"first_position"`
	Version     uint32    `json:"version"`
	Entries     int       `json:"entries_opened"`
	Value       string    `json:"committed_value"`
	Root        string    `json:"implied_root"`
	VerifiedAt  time.Time `json:"verified_at"`
	EntriesFile string    `json:"entries_file"`
}

// exportSearches writes one file per origin that has ever had a search proof
// verified. Origins with none are skipped rather than given an empty file: a
// present-but-empty artifact invites the reading that we looked and found
// nothing, when in fact we never looked.
func (e *Exporter) exportSearches() error {
	searches, err := e.Store.Searches()
	if err != nil {
		return err
	}
	for origin, r := range searches {
		s := searchSummary{
			Note:        searchNote,
			Origin:      origin,
			Key:         r.Key,
			Index:       fmt.Sprintf("%x", r.Index[:]),
			Pos:         r.Pos,
			Version:     r.Version,
			Entries:     r.Entries,
			Value:       fmt.Sprintf("%x", r.Value),
			Root:        fmt.Sprintf("%x", r.Root[:]),
			EntriesFile: "entries/" + slug(origin) + ".jsonl",
		}
		if r.VerifiedAt != 0 {
			s.VerifiedAt = time.Unix(r.VerifiedAt, 0).UTC()
		}
		p := filepath.Join(e.Dir, "searches", slug(origin)+".json")
		if err := writeJSON(p, s); err != nil {
			return err
		}
	}
	return nil
}

// exportEntries writes the cross-observation ledger.
//
// JSON Lines, not a JSON array: the ledger holds up to 65,536 entries per
// origin, and an indented 65k-element array is a file you can only open with a
// parser, whereas 65k lines can be grepped for an id, streamed, diffed against a
// later copy, and read one record at a time. The trade is that the artifact's
// note cannot be a wrapper field, so it is the first line — itself a standalone
// JSON object, keeping the property that every line parses on its own.
func (e *Exporter) exportEntries(origin string) error {
	entries, err := e.Store.LogEntries(origin)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	ids := make([]uint64, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var b strings.Builder
	header, err := json.Marshal(map[string]any{
		"note":   entriesNote,
		"origin": origin,
		"count":  len(ids),
	})
	if err != nil {
		return err
	}
	b.Write(header)
	b.WriteByte('\n')
	for _, id := range ids {
		leaf := entries[id]
		line, err := json.Marshal(map[string]any{
			"entry": id,
			"leaf":  fmt.Sprintf("%x", leaf[:]),
		})
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	p := filepath.Join(e.Dir, "entries", slug(origin)+".jsonl")
	return writeAtomic(p, []byte(b.String()))
}
