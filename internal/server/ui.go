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
	Tier         string
	Kind         string
	Origin       string
	Size         int64
	Root         string
	RootShort    string
	Path         string
	WitnessedAt  time.Time
	Age          string
	Stale        bool
	Forked       bool
	Audited      int
	Sampled      int
	Declined     int
	Unavailable  int
	LastEpoch    int64
	History      *historyView
	CheckpointID string
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

	Logs        []logView
	Forks       int
	ForkOrigins []string

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

	forks, _ := s.Store.Forks()
	forked := map[string]bool{}
	for _, f := range forks {
		forked[f.Origin] = true
		v.ForkOrigins = append(v.ForkOrigins, f.Origin)
	}
	v.Forks = len(forks)

	for _, rec := range recs {
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
