package server

import "sort"

// Grouping the witnessed logs by what they make transparent.
//
// The flat list treats a certificate log and a key transparency log as the same
// kind of thing because both appear as a row with a tier. They are not. A tier-A
// cosignature over a CT log and a tier-A cosignature over a KT log are the same
// strength of claim about entirely different objects — one says a certificate
// log is append-only, the other says a directory of people's public keys is —
// and a reader scanning eighty rows has no way to hold that distinction.
//
// Grouping also makes the shape of the coverage legible. Nearly all the rows are
// CT and nearly all of them are tier A, because that is what CT logs offer;
// almost all of the construction auditing is in a handful of KT rows. In a flat
// list sorted by size that reads as "mostly tier A with a few exceptions",
// which misdescribes the work. Split by ecosystem it reads correctly: complete
// coverage of one kind, deep coverage of another.

// logGroup is one ecosystem's worth of witnessed logs, with the summary a
// reader wants before deciding whether to read the rows.
type logGroup struct {
	Kind  string
	Label string
	Blurb string

	Logs []logView

	Count   int
	Entries int64
	// Highest tier present in the group, and how many rows have reached it.
	TopTier  string
	AtTop    int
	Forked   int
	Stale    int
	Audited  int64
	Coverage float64 // fraction of published history construction audited
}

// kindOrder puts the ecosystems in a deliberate order rather than an
// alphabetical one: key transparency first because it is what this project is
// for and where the deep auditing is, then certificate transparency because it
// is the bulk of the rows, then everything else.
var kindOrder = []struct{ kind, label, blurb string }{
	{"kt", "Key transparency", "Directories binding people to public keys. This is the ecosystem the project exists for, and the only one where construction auditing is possible at all — a map can be mutated in ways an append-only log cannot."},
	{"ct", "Certificate transparency", "Append-only logs of issued TLS certificates. Tier A is the honest ceiling here: these are entry logs with no mutable map, so append-only IS the whole construction property."},
	{"software", "Software transparency", "Logs binding published artifacts to what was actually built."},
	{"generic", "Other", "Logs whose ecosystem is not declared in the configuration."},
}

// tierRank orders tiers by strength so a group can report its best.
func tierRank(tier string) int {
	switch {
	case tier == "":
		return 0
	case len(tier) >= 2 && tier[:2] == "B+":
		return 5
	case tier[0] == 'B':
		return 4
	case len(tier) >= 2 && tier[:2] == "A+":
		return 3
	case tier[0] == 'A':
		return 2
	default:
		return 1
	}
}

func groupByKind(logs []logView) []logGroup {
	byKind := map[string][]logView{}
	for _, lg := range logs {
		k := lg.Kind
		if k == "" {
			k = "generic"
		}
		byKind[k] = append(byKind[k], lg)
	}

	var out []logGroup
	seen := map[string]bool{}
	add := func(kind, label, blurb string) {
		rows := byKind[kind]
		if len(rows) == 0 {
			return
		}
		seen[kind] = true
		g := logGroup{Kind: kind, Label: label, Blurb: blurb, Logs: rows, Count: len(rows)}
		var total, audited int64
		for _, r := range rows {
			g.Entries += r.Size
			if r.Forked {
				g.Forked++
			}
			if r.Stale {
				g.Stale++
			}
			if tierRank(r.Tier) > tierRank(g.TopTier) {
				g.TopTier = r.Tier
			}
			g.Audited += r.HistoryAudited
			total += r.HistoryTotal
			audited += r.HistoryAudited
		}
		for _, r := range rows {
			if r.Tier == g.TopTier {
				g.AtTop++
			}
		}
		if total > 0 {
			g.Coverage = float64(audited) / float64(total)
		}
		out = append(out, g)
	}

	for _, k := range kindOrder {
		add(k.kind, k.label, k.blurb)
	}
	// Anything with a kind we do not have a heading for still has to appear, or
	// adding a new ecosystem to the config would silently drop its logs off the
	// page while the witness went on cosigning them.
	var rest []string
	for k := range byKind {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k, k, "")
	}
	return out
}
