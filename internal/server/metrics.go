package server

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
)

// Metric names. Declared in one place so the exposition is stable and an alert
// written against it does not break silently when a call site moves.
const (
	MBuildInfo    = "kt_witness_build_info"
	MLogSize      = "kt_witness_log_size"
	MLogWitnessed = "kt_witness_log_last_witnessed_timestamp_seconds"
	MLogAge       = "kt_witness_log_staleness_seconds"
	MLogForked    = "kt_witness_log_forked"
	MLogsTotal    = "kt_witness_logs_total"
	MEntries      = "kt_witness_entries_attested"
	MForksTotal   = "kt_witness_forks_total"

	MBackfillEpochs = "kt_witness_backfill_epochs"
	MBackfillGaps   = "kt_witness_backfill_gaps"

	// How much of a log's PUBLISHED history has a settled construction-audit
	// decision. This is what separates tier B from B+, and it is measured from
	// the stored record rather than claimed by a source.
	MHistoryAudited  = "kt_witness_history_audited_epochs"
	MHistoryTotal    = "kt_witness_history_total_epochs"
	MHistoryCoverage = "kt_witness_history_audit_coverage"

	MAuditEpochs   = "kt_witness_audit_epochs_total"
	MAppHeads      = "kt_witness_application_heads"
	MAppConflicts  = "kt_witness_application_conflicts"
	MScrapeSeconds = "kt_witness_metrics_scrape_duration_seconds"

	// Storage. A witness that runs out of disk stops witnessing, and the
	// database is the only thing on it that cannot be rebuilt from the network.
	MDBBytes        = "kt_witness_database_bytes"
	MExportBytes    = "kt_witness_export_bytes"
	MDiskFreeBytes  = "kt_witness_disk_free_bytes"
	MDiskTotalBytes = "kt_witness_disk_total_bytes"
	MDiskUsedRatio  = "kt_witness_disk_used_ratio"

	// Bandwidth, per log and therefore per ecosystem. This is the resource the
	// witness actually consumes at scale and the one a home connection has a
	// hard limit on.
	MNetBytesIn  = "kt_witness_network_bytes_in_total"
	MNetBytesOut = "kt_witness_network_bytes_out_total"
	MNetRequests = "kt_witness_network_requests_total"

	// Counters maintained by the witness loop rather than derived from storage.
	MRounds              = "kt_witness_rounds_total"
	MCosigned            = "kt_witness_cosignatures_total"
	MWithheld            = "kt_witness_withheld_total"
	MConsecutiveWithheld = "kt_witness_consecutive_withheld"
	MForkDetected        = "kt_witness_forks_detected_total"
	MFetchSeconds        = "kt_witness_fetch_duration_seconds_sum"
	MFetchCount          = "kt_witness_fetch_duration_seconds_count"
	MAuditVerified       = "kt_witness_audit_verified_total"
	MAuditBytes          = "kt_witness_audit_bytes_total"
	MAuditSeconds        = "kt_witness_audit_duration_seconds_sum"
)

// Init declares every metric up front.
//
// Declaring rather than creating on first use matters for alerting: a counter
// that only appears after the first failure is a counter you cannot write
// `rate(...) > 0` against, because before the first failure the series does not
// exist and the expression is simply absent rather than false.
func Init(version string) {
	d := metrics.Describe
	d(MBuildInfo, metrics.Gauge, "Build information; always 1, labelled with the version.")
	d(MLogsTotal, metrics.Gauge, "Number of logs currently witnessed.")
	d(MEntries, metrics.Gauge, "Sum of every witnessed log's size: records whose append-only shape is currently attested.")
	d(MLogSize, metrics.Gauge, "Current witnessed size of a log.")
	d(MLogWitnessed, metrics.Gauge, "Unix timestamp of the most recent cosignature for a log.")
	d(MLogAge, metrics.Gauge, "Seconds since a log was last cosigned. Alert on this: the witness refreshes hourly, so a large value means the witness is stuck, not that the log is quiet.")
	d(MLogForked, metrics.Gauge, "1 if a log has been caught contradicting itself and is permanently refused, else 0.")
	d(MForksTotal, metrics.Gauge, "Total recorded forks across all logs. Any non-zero value warrants a human immediately.")
	d(MBackfillEpochs, metrics.Gauge, "Epochs of published history verified by backfill.")
	d(MBackfillGaps, metrics.Gauge, "Gaps found in a log's published history. Not evidence of misbehaviour by itself: retention limits produce them too.")
	d(MHistoryAudited, metrics.Gauge, "Epochs of published history with a settled construction-audit decision.")
	d(MHistoryTotal, metrics.Gauge, "Epochs of published history in total.")
	d(MHistoryCoverage, metrics.Gauge, "Fraction of published history construction audited, 0 to 1. Reaching 1 is what earns tier B+ — a bare tier B only covers epochs published since we started watching.")
	d(MAuditEpochs, metrics.Counter, "Epochs considered for construction auditing, by outcome: sampled, declined, verified, unavailable.")
	d(MAppHeads, metrics.Gauge, "Per-application heads observed. These are observations, never cosigned.")
	d(MAppConflicts, metrics.Gauge, "Contradictions recorded among observed application heads.")
	d(MScrapeSeconds, metrics.Gauge, "How long it took to gather these metrics from the store.")
	d(MDBBytes, metrics.Gauge, "Size of the bbolt database on disk. Note bbolt never returns freed pages to the filesystem, so this only grows; a large drop means the file was replaced.")
	d(MExportBytes, metrics.Gauge, "Size of the published file mirror.")
	d(MDiskFreeBytes, metrics.Gauge, "Bytes free on the filesystem holding the database.")
	d(MDiskTotalBytes, metrics.Gauge, "Total bytes on the filesystem holding the database.")
	d(MNetBytesIn, metrics.Counter, "Bytes received per log, counted as actually read rather than from Content-Length. Group by kind for per-ecosystem utilisation. Almost all of it is construction-audit proofs.")
	d(MNetBytesOut, metrics.Counter, "Bytes sent per log. A witness sends almost nothing.")
	d(MNetRequests, metrics.Counter, "HTTP requests issued per log.")
	d(MDiskUsedRatio, metrics.Gauge, "Fraction of the database filesystem in use, 0 to 1. A witness that runs out of disk stops witnessing.")

	d(MRounds, metrics.Counter, "Witness rounds completed.")
	d(MCosigned, metrics.Counter, "Cosignatures issued, by origin.")
	d(MConsecutiveWithheld, metrics.Gauge, "Consecutive rounds a log has failed to verify. Resets to 0 on success. Alert above ~20: withholding is the enforcement mechanism, so occasional is healthy and sustained is not.")
	d(MWithheld, metrics.Counter, "Cosignatures withheld because something could not be verified. Withholding is the enforcement mechanism, so a steady rate for one origin is the signal to look at.")
	d(MForkDetected, metrics.Counter, "Forks detected, by origin.")
	d(MFetchSeconds, metrics.Counter, "Cumulative seconds spent fetching heads, by origin.")
	d(MFetchCount, metrics.Counter, "Number of head fetches, by origin. Divide the sum by this for a mean.")
	d(MAuditVerified, metrics.Counter, "Construction proofs replayed and verified, by origin.")
	d(MAuditBytes, metrics.Counter, "Bytes of construction proof downloaded and verified, by origin.")
	d(MAuditSeconds, metrics.Counter, "Cumulative seconds spent verifying construction proofs, by origin.")

	metrics.Set(MBuildInfo, map[string]string{"version": version}, 1)
}

// metricsHandler serves the exposition.
//
// Store-derived gauges are recomputed on each scrape rather than maintained
// incrementally. They come from a handful of bbolt reads, and a gauge computed
// from the authoritative record cannot drift from it — which an incrementally
// maintained one eventually does.
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if err := s.refreshStoreMetrics(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	metrics.Set(MScrapeSeconds, nil, time.Since(start).Seconds())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_ = metrics.Default.Write(w)
}

// StoragePaths tells the metrics layer where to measure. Empty entries are
// skipped rather than reported as zero: a zero-byte database and an unknown one
// are very different things and an alert must not confuse them.
type StoragePaths struct {
	DBPath    string
	ExportDir string
}

func (s *Server) refreshStoreMetrics() error {
	v, err := s.buildStatus()
	if err != nil {
		return err
	}
	now := time.Now()
	s.refreshStorageMetrics()

	metrics.Set(MLogsTotal, nil, float64(v.TotalLogs))
	metrics.Set(MEntries, nil, float64(v.TotalEntries))
	metrics.Set(MForksTotal, nil, float64(v.Forks))
	metrics.Set(MAppHeads, nil, float64(v.Apps))
	metrics.Set(MAppConflicts, nil, float64(v.AppConflicts))

	// Bandwidth, labelled with kind so the dashboard can answer "what is CT
	// costing us" without enumerating 69 origins.
	for origin, st := range netmeter.Snapshot() {
		kind := s.Kinds[origin]
		if kind == "" {
			kind = "generic"
		}
		l := map[string]string{"origin": origin, "kind": kind}
		metrics.Set(MNetBytesIn, l, float64(st.BytesIn))
		metrics.Set(MNetBytesOut, l, float64(st.BytesOut))
		metrics.Set(MNetRequests, l, float64(st.Requests))
	}

	for _, lg := range v.Logs {
		kind := lg.Kind
		if kind == "" {
			kind = "generic"
		}
		l := map[string]string{"origin": lg.Origin, "tier": lg.Tier, "kind": kind}
		metrics.Set(MLogSize, l, float64(lg.Size))
		metrics.Set(MLogWitnessed, l, float64(lg.WitnessedAt.Unix()))
		metrics.Set(MLogAge, l, now.Sub(lg.WitnessedAt).Seconds())
		forked := 0.0
		if lg.Forked {
			forked = 1
		}
		metrics.Set(MLogForked, l, forked)

		origin := map[string]string{"origin": lg.Origin}
		if lg.History != nil {
			metrics.Set(MBackfillEpochs, origin, float64(lg.History.Epochs))
			metrics.Set(MBackfillGaps, origin, float64(lg.History.Gaps))
		}
		if lg.HistoryTotal > 0 {
			metrics.Set(MHistoryAudited, origin, float64(lg.HistoryAudited))
			metrics.Set(MHistoryTotal, origin, float64(lg.HistoryTotal))
			metrics.Set(MHistoryCoverage, origin, float64(lg.HistoryAudited)/float64(lg.HistoryTotal))
		}
		// Audit outcomes are set rather than added: they are recomputed from the
		// stored record every scrape, so adding would double-count.
		for outcome, n := range map[string]int{
			"sampled":     lg.Sampled,
			"declined":    lg.Declined,
			"unavailable": lg.Unavailable,
		} {
			metrics.Set(MAuditEpochs, map[string]string{"origin": lg.Origin, "outcome": outcome}, float64(n))
		}
	}
	return nil
}

// refreshStorageMetrics measures the database, the published mirror, and the
// filesystem underneath them.
func (s *Server) refreshStorageMetrics() {
	if s.Storage.DBPath != "" {
		if fi, err := os.Stat(s.Storage.DBPath); err == nil {
			metrics.Set(MDBBytes, nil, float64(fi.Size()))
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(filepath.Dir(s.Storage.DBPath), &st); err == nil {
			free := float64(st.Bavail) * float64(st.Bsize)
			total := float64(st.Blocks) * float64(st.Bsize)
			metrics.Set(MDiskFreeBytes, nil, free)
			metrics.Set(MDiskTotalBytes, nil, total)
			if total > 0 {
				metrics.Set(MDiskUsedRatio, nil, (total-free)/total)
			}
		}
	}
	if s.Storage.ExportDir != "" {
		var total int64
		// Walk rather than stat: the mirror is a directory of small files, and
		// its growth is what would surprise someone, not any single file.
		_ = filepath.WalkDir(s.Storage.ExportDir, func(_ string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
			return nil
		})
		metrics.Set(MExportBytes, nil, float64(total))
	}
}
