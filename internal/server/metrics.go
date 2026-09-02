package server

import (
	"net/http"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/metrics"
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

	MAuditEpochs   = "kt_witness_audit_epochs_total"
	MAppHeads      = "kt_witness_application_heads"
	MAppConflicts  = "kt_witness_application_conflicts"
	MScrapeSeconds = "kt_witness_metrics_scrape_duration_seconds"

	// Counters maintained by the witness loop rather than derived from storage.
	MRounds        = "kt_witness_rounds_total"
	MCosigned      = "kt_witness_cosignatures_total"
	MWithheld      = "kt_witness_withheld_total"
	MForkDetected  = "kt_witness_forks_detected_total"
	MFetchSeconds  = "kt_witness_fetch_duration_seconds_sum"
	MFetchCount    = "kt_witness_fetch_duration_seconds_count"
	MAuditVerified = "kt_witness_audit_verified_total"
	MAuditBytes    = "kt_witness_audit_bytes_total"
	MAuditSeconds  = "kt_witness_audit_duration_seconds_sum"
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
	d(MAuditEpochs, metrics.Counter, "Epochs considered for construction auditing, by outcome: sampled, declined, verified, unavailable.")
	d(MAppHeads, metrics.Gauge, "Per-application heads observed. These are observations, never cosigned.")
	d(MAppConflicts, metrics.Gauge, "Contradictions recorded among observed application heads.")
	d(MScrapeSeconds, metrics.Gauge, "How long it took to gather these metrics from the store.")

	d(MRounds, metrics.Counter, "Witness rounds completed.")
	d(MCosigned, metrics.Counter, "Cosignatures issued, by origin.")
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

func (s *Server) refreshStoreMetrics() error {
	v, err := s.buildStatus()
	if err != nil {
		return err
	}
	now := time.Now()

	metrics.Set(MLogsTotal, nil, float64(v.TotalLogs))
	metrics.Set(MEntries, nil, float64(v.TotalEntries))
	metrics.Set(MForksTotal, nil, float64(v.Forks))
	metrics.Set(MAppHeads, nil, float64(v.Apps))
	metrics.Set(MAppConflicts, nil, float64(v.AppConflicts))

	for _, lg := range v.Logs {
		l := map[string]string{"origin": lg.Origin, "tier": lg.Tier}
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
