package server

// The per-log page.
//
// The index answers "is anything wrong"; this answers "what exactly do we know
// about this log, and how did we come to know it". Those are different
// questions and cramming both into one table served neither.
//
// Everything here is derived from what the witness actually stored or measured.
// Where a figure is not available for a given log the row says so rather than
// showing a zero — a zero and an absence look identical on a dashboard, and
// this project has been bitten by that distinction more than once.

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/netmeter"
	"github.com/gdbsecurity/kt-witness/internal/store"
)

type auditRow struct {
	Epoch    int64
	Strategy string
	Verified bool
	Rate     float64
	When     string
}

type peerRow struct {
	Witness    string
	Size       int64
	Root       string
	Comparable bool
	Agrees     bool
}

type logDetail struct {
	WitnessName string
	Log         logView

	// Provenance
	CheckpointURL string
	SignedNote    string

	// Traffic
	BytesIn   string
	BytesOut  string
	Requests  int64
	HaveBytes bool

	// Construction auditing
	Coverage      string
	CoveragePct   float64
	AuditRows     []auditRow
	StrategyMix   map[string]int
	HaveAudits    bool
	FirstAudited  int64
	LastAudited   int64
	VerifiedCount int
	FailedCount   int

	// Gossip
	Peers     []peerRow
	HavePeers bool

	// Withdrawn finding, if any
	Retracted *store.Retraction
	Fork      *store.Fork
}

// logDetail renders one log.
func (s *Server) logPage(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		http.Error(w, "origin required", http.StatusBadRequest)
		return
	}
	rec, err := s.Store.Get(origin)
	if err != nil || rec == nil {
		http.NotFound(w, r)
		return
	}

	v, err := s.buildStatus()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var lv logView
	found := false
	for _, l := range v.Logs {
		if l.Origin == origin {
			lv, found = l, true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	d := &logDetail{
		WitnessName: v.WitnessName,
		Log:         lv,
		SignedNote:  string(rec.Cosigned),
		StrategyMix: map[string]int{},
	}
	if lv.CheckpointID != "" {
		d.CheckpointURL = "/" + lv.CheckpointID + "/checkpoint"
	}

	// Traffic, if this log has moved any. Reported per log because the
	// interesting question is which ecosystem costs what, not the total.
	if st, ok := netmeter.Snapshot()[origin]; ok && (st.BytesIn > 0 || st.Requests > 0) {
		d.HaveBytes = true
		d.BytesIn = humanBytes(st.BytesIn)
		d.BytesOut = humanBytes(st.BytesOut)
		d.Requests = st.Requests
	}

	// Construction audits, most recent first.
	if rows, err := s.Store.Audits(origin, 40); err == nil && len(rows) > 0 {
		d.HaveAudits = true
		for _, a := range rows {
			strat := a.Strategy
			if strat == "" {
				strat = "unknown"
			}
			d.StrategyMix[strat]++
			if a.Verified {
				d.VerifiedCount++
			} else {
				d.FailedCount++
			}
			if d.FirstAudited == 0 || a.Epoch < d.FirstAudited {
				d.FirstAudited = a.Epoch
			}
			if a.Epoch > d.LastAudited {
				d.LastAudited = a.Epoch
			}
			d.AuditRows = append(d.AuditRows, auditRow{
				Epoch: a.Epoch, Strategy: strat, Verified: a.Verified,
				Rate: a.Rate, When: a.DecidedAt.Format("2006-01-02 15:04"),
			})
		}
	}
	if lv.HistoryTotal > 0 {
		d.CoveragePct = float64(lv.HistoryAudited) / float64(lv.HistoryTotal) * 100
		d.Coverage = fmt.Sprintf("%d of %d epochs (%.4f%%)",
			lv.HistoryAudited, lv.HistoryTotal, d.CoveragePct)
	}

	// What other witnesses say about this same log.
	if peers, err := s.Store.PeerAttestations(origin); err == nil && len(peers) > 0 {
		d.HavePeers = true
		for _, p := range peers {
			row := peerRow{
				Witness: p.Witness, Size: p.Size, Root: p.Root,
				Comparable: p.Root != "",
			}
			if row.Comparable && p.Size == rec.Size {
				row.Agrees = p.Root == rootBase64(rec)
			}
			d.Peers = append(d.Peers, row)
		}
		sort.Slice(d.Peers, func(i, j int) bool { return d.Peers[i].Witness < d.Peers[j].Witness })
	}

	// A withdrawn finding travels with the log it was made against.
	if rs, err := s.Store.Retractions(); err == nil {
		for _, rt := range rs {
			if rt.Origin == origin {
				d.Retracted, d.Fork = rt, rt.Fork
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := logTmpl.Execute(w, d); err != nil {
		return
	}
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func rootBase64(rec *store.Record) string {
	return base64.StdEncoding.EncodeToString(rec.Hash[:])
}

var logTmpl = template.Must(template.New("log").Funcs(template.FuncMap{
	"pct": func(f float64) string { return fmt.Sprintf("%.4f", f) },
	"nl":  func(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") },
	"since": func(t time.Time) string {
		return t.UTC().Format("2006-01-02 15:04:05Z")
	},
}).Parse(logPageHTML))
