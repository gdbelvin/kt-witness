package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// The human-facing status page.
//
// The plain-text index is the machine contract and does not change: monitors,
// scripts and the C2SP tooling all read it. This is served only when the client
// asks for HTML, so `curl /` and a browser both get the right thing from the
// same URL.
//
// A witness's product is evidence, and evidence nobody can read is evidence with
// a dependency on its author. The page therefore leads with what is *claimed*
// and at what tier, not with uptime — the tier is the part people must not
// misread — and every number is one the witness actually derived rather than a
// gauge for its own sake.

const auditWindow = 5000

type logView struct {
	Tier           string
	Kind           string
	HistoryAudited int64
	// HistoryUnverified counts epochs with a settled decision that is NOT a
	// successful verification — ones we gave up fetching. Published because a
	// coverage figure that hides them reads as completeness it has not earned.
	HistoryUnverified int64

	// The largest unbroken run of verified epochs, and the number of holes in
	// the swept range. Published together because either alone misleads: a run
	// without a hole count hides what it excludes, and a hole count without the
	// run says nothing about what was actually established.
	VerifiedFrom, VerifiedTo int64
	VerifiedRun              int64
	Holes                    int64
	HistoryTotal             int64
	Origin                   string
	Size                     int64
	Root                     string
	RootShort                string
	Path                     string
	WitnessedAt              time.Time
	Age                      string
	Stale                    bool
	Forked                   bool
	Audited                  int
	Sampled                  int
	Declined                 int
	Unavailable              int
	LastEpoch                int64
	History                  *historyView
	CheckpointID             string
}

type historyView struct {
	From, To int64
	Epochs   int
	Gaps     int
}

type statusView struct {
	Version     string
	VKey        string
	WitnessName string
	Now         time.Time
	Generated   string

	Logs  []logView
	Forks int
	// RetractedForks counts findings that were withdrawn. Reported separately so
	// a retraction is visible rather than simply making a finding disappear.
	RetractedForks int
	ForkOrigins    []string

	// Retired lists origins with stored history that are no longer configured.
	// Kept visible so removing a log is an observable act rather than a silent
	// one, but excluded from liveness reporting.
	Retired []string

	// Aggregates — the nerdy part.
	TotalLogs        int
	TotalEntries     int64
	TotalBackfilled  int
	TotalGaps        int
	TotalAudits      int
	TotalSampled     int
	TotalVerified    int
	TotalUnavailable int
	LargestOrigin    string
	LargestSize      int64
	OldestWitness    time.Time
	NewestWitness    time.Time
	Apps             int
	AppConflicts     int
	SampleRate       float64
}

func humanCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func age(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// buildStatus gathers everything the page shows in one pass over the store.
func (s *Server) buildStatus() (*statusView, error) {
	now := time.Now().UTC()
	v := &statusView{
		Version:   s.Version,
		VKey:      s.VKey,
		Now:       now,
		Generated: now.Format("2006-01-02 15:04:05 UTC"),
	}
	if i := strings.Index(s.VKey, "+"); i > 0 {
		v.WitnessName = s.VKey[:i]
	}

	recs, err := s.Store.List()
	if err != nil {
		return nil, err
	}
	histories, _ := s.Store.Histories()
	byOrigin := map[string]*historyView{}
	for _, h := range histories {
		byOrigin[h.Origin] = &historyView{From: h.From, To: h.To, Epochs: h.Epochs, Gaps: len(h.Gaps)}
		v.TotalBackfilled += h.Epochs
		v.TotalGaps += len(h.Gaps)
	}

	// Live fork state excludes retracted findings.
	//
	// The evidence bucket keeps every fork ever recorded, deliberately — a
	// withdrawn accusation should still be readable. But a retracted finding is
	// not a live one, and reading the evidence as current state would leave a
	// log permanently marked forked and its alert permanently firing after the
	// finding had been withdrawn. That happened the first time this was used.
	forks, _ := s.Store.Forks()
	retractions, _ := s.Store.Retractions()
	retracted := map[string]bool{}
	for _, r := range retractions {
		retracted[r.Origin] = true
	}

	forked := map[string]bool{}
	for _, f := range forks {
		if retracted[f.Origin] {
			continue
		}
		forked[f.Origin] = true
		v.ForkOrigins = append(v.ForkOrigins, f.Origin)
	}
	v.Forks = len(v.ForkOrigins)
	v.RetractedForks = len(retracted)

	for _, rec := range recs {
		// A log that has been removed from the configuration keeps its stored
		// record — that history is evidence and deleting it would be
		// destroying our own audit trail — but it must not be reported as a
		// live origin. Otherwise a log we deliberately stopped witnessing
		// (retired, rejected, or past its temporal window) ages forever and
		// trips the staleness alarm that is supposed to mean the witness is
		// stuck.
		if len(s.Tiers) > 0 {
			if _, configured := s.Tiers[rec.Origin]; !configured {
				v.Retired = append(v.Retired, rec.Origin)
				continue
			}
		}
		lv := logView{
			Origin:       rec.Origin,
			Size:         rec.Size,
			Root:         hex.EncodeToString(rec.Hash[:]),
			WitnessedAt:  rec.WitnessedAt,
			Age:          age(rec.WitnessedAt, now),
			Forked:       forked[rec.Origin],
			History:      byOrigin[rec.Origin],
			CheckpointID: originHashes(rec.Origin)[0],
			Tier:         s.Tiers[rec.Origin],
			Kind:         s.Kinds[rec.Origin],
		}
		lv.RootShort = lv.Root[:16]
		lv.Path = "/" + lv.CheckpointID + "/checkpoint"
		// A cosignature carries a timestamp, so a head we have not refreshed in
		// well over the refresh interval is one a monitor cannot distinguish
		// from a dead witness. Two hours is comfortably past the hourly refresh.
		lv.Stale = now.Sub(rec.WitnessedAt) > 2*time.Hour

		// The tier a source reports is what its own checks establish. Whether a
		// log is ALSO construction audited is decided by the auditor and lives
		// in the record, not in the source: the AKD adapter reports A+ because
		// root-chain continuity is what it proves on its own, while tier B for
		// the same log comes from proofs the sidecar replayed.
		//
		// So the effective tier is computed here, from what was actually done.
		// An earlier version asked the source whether it was tier B, which meant
		// B+ could never be reached by any of the logs that are actually audited.
		if h := lv.History; h != nil {
			settled, verified, err := s.Store.AuditCoverage(rec.Origin, h.From, h.To)
			if err == nil && verified > 0 {
				total := h.To - h.From + 1
				lv.HistoryAudited = settled
				lv.HistoryTotal = total
				lv.HistoryUnverified = settled - verified
				// The contiguous run is the honest shape of the claim: an
				// audited count says how much work was done, not whether the
				// result is a solid range or a sieve, and only a solid range
				// supports "this log's history is construction audited".
				if lo, hi, holes, err := s.Store.VerifiedRegion(rec.Origin, h.From, h.To); err == nil {
					lv.VerifiedFrom, lv.VerifiedTo = lo, hi
					lv.Holes = holes
					if hi >= lo && lo > 0 {
						lv.VerifiedRun = hi - lo + 1
					}
				}
				switch {
				case total > 0 && verified >= total:
					// Every epoch in the published range was actually replayed
					// and checked.
					//
					// Gated on `verified`, not `settled`. Settled includes
					// epochs we gave up fetching after three attempts: they
					// carry a decision, but the decision is "we could not look".
					// Claiming B+ over those would assert construction across a
					// range containing holes — and overpromising the tier is the
					// single largest reputational risk this project has. A log
					// with even one unfetchable epoch stays at B, which is the
					// honest description of what we did.
					lv.Tier = source.TierBPlus.String()
				default:
					lv.Tier = source.TierB.String()
				}
			}
		}

		if audits, err := s.Store.Audits(rec.Origin, auditWindow); err == nil {
			for _, a := range audits {
				lv.Audited++
				if a.Sampled {
					lv.Sampled++
					if a.Verified {
						v.TotalVerified++
					} else {
						lv.Unavailable++
						v.TotalUnavailable++
					}
				} else {
					lv.Declined++
				}
				if a.Epoch > lv.LastEpoch {
					lv.LastEpoch = a.Epoch
				}
				if a.Rate > 0 {
					v.SampleRate = a.Rate
				}
			}
			v.TotalAudits += lv.Audited
			v.TotalSampled += lv.Sampled
		}

		v.TotalEntries += rec.Size
		if rec.Size > v.LargestSize {
			v.LargestSize, v.LargestOrigin = rec.Size, rec.Origin
		}
		if v.OldestWitness.IsZero() || rec.WitnessedAt.Before(v.OldestWitness) {
			v.OldestWitness = rec.WitnessedAt
		}
		if rec.WitnessedAt.After(v.NewestWitness) {
			v.NewestWitness = rec.WitnessedAt
		}
		v.Logs = append(v.Logs, lv)
	}
	sort.Slice(v.Logs, func(i, j int) bool { return v.Logs[i].Size > v.Logs[j].Size })
	v.TotalLogs = len(v.Logs)

	if apps, err := s.Store.AppHeads(); err == nil {
		v.Apps = len(apps)
		for _, a := range apps {
			v.AppConflicts += len(a.Conflicts)
		}
	}
	return v, nil
}

// statusJSON serves the same data the page renders, because a status page that
// cannot be scraped just moves the problem.
func (s *Server) statusJSON(w http.ResponseWriter, r *http.Request) {
	v, err := s.buildStatus()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	v, err := s.buildStatus()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uiTemplate.Execute(w, v); err != nil {
		// Headers are already sent; log-worthy but nothing useful to say to the
		// client at this point.
		return
	}
}

var uiFuncs = template.FuncMap{
	"comma":  func(n int64) string { return humanCount(n) },
	"commai": func(n int) string { return humanCount(int64(n)) },
	"pct": func(a, b int) string {
		if b == 0 {
			return "—"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
	},
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05Z")
	},
}

var uiTemplate = template.Must(template.New("ui").Funcs(uiFuncs).Parse(uiHTML))
