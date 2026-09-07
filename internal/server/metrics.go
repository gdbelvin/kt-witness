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
	MStartTime    = "kt_witness_process_start_time_seconds"
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
	MHistoryAudited    = "kt_witness_history_audited_epochs"
	MHistoryUnverified = "kt_witness_history_unverified_epochs"
	MVerifiedRun       = "kt_witness_verified_region_epochs"
	MVerifiedFrom      = "kt_witness_verified_region_from"
	MVerifiedTo        = "kt_witness_verified_region_to"
	MHoles             = "kt_witness_history_holes"
	MHistoryTotal      = "kt_witness_history_total_epochs"
	MHistoryExpired    = "kt_witness_history_expired_epochs"
	MHistoryFrom       = "kt_witness_history_range_from"
	MHistoryTo         = "kt_witness_history_range_to"
	MAuditPopulation   = "kt_witness_audit_records_retained"
	MHistoryCoverage   = "kt_witness_history_audit_coverage"

	MAuditEpochs   = "kt_witness_audit_epochs_total"
	MAppHeads      = "kt_witness_application_heads"
	MAppConflicts  = "kt_witness_application_conflicts"
	MScrapeSeconds = "kt_witness_metrics_scrape_duration_seconds"
	MCoverageAge   = "kt_witness_coverage_cache_age_seconds"

	// Resource facts that previously required a shell on the host. Every one of
	// these was read by hand during a diagnosis this week.
	MProcCores       = "kt_witness_process_cores_visible"
	MProcGoroutines  = "kt_witness_process_goroutines"
	MProcHeapBytes   = "kt_witness_process_heap_bytes"
	MProcSysBytes    = "kt_witness_process_sys_bytes"
	MCgroupMemBytes  = "kt_witness_cgroup_memory_bytes"
	MCgroupMemLimit  = "kt_witness_cgroup_memory_limit_bytes"
	MCgroupMemEvents = "kt_witness_cgroup_memory_events"
	MCgroupCPUMax    = "kt_witness_cgroup_cpu_max"
	MMachineMemBytes = "kt_witness_machine_memory_bytes"
	MMachineMemAvail = "kt_witness_machine_memory_available_bytes"

	// The proof cache sits between the link and the CPU, and its occupancy is
	// the only thing that distinguishes a bandwidth-bound pipeline from a
	// CPU-bound one.
	MPrefetchBytes    = "kt_witness_prefetch_cache_bytes"
	MPrefetchFiles    = "kt_witness_prefetch_cache_files"
	MPrefetchMax      = "kt_witness_prefetch_cache_max_bytes"
	MPrefetchDiskFree = "kt_witness_prefetch_disk_free_bytes"

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
	MRounds            = "kt_witness_rounds_total"
	MAuditPermits      = "kt_witness_audit_permits"
	MAuditInFlight     = "kt_witness_audit_in_flight"
	MCPUSelfCores      = "kt_witness_cpu_self_cores"
	MCPUMachineCores   = "kt_witness_cpu_machine_cores"
	MCPUSampleComplete = "kt_witness_cpu_sample_complete"

	MCosigned            = "kt_witness_cosignatures_total"
	MWithheld            = "kt_witness_withheld_total"
	MConsecutiveWithheld = "kt_witness_consecutive_withheld"
	MForkDetected        = "kt_witness_forks_detected_total"
	MFetchSeconds        = "kt_witness_fetch_duration_seconds_sum"
	MFetchCount          = "kt_witness_fetch_duration_seconds_count"
	MAuditVerified       = "kt_witness_audit_verified_total"
	MHistoryVerified     = "kt_witness_history_verified_total"
	MAuditBytes          = "kt_witness_audit_bytes_total"
	MAuditSeconds        = "kt_witness_audit_duration_seconds_sum"
)

// Init declares every metric up front.
//
// Declaring rather than creating on first use matters for alerting: a counter
// that only appears after the first failure is a counter you cannot write
// `rate(...) > 0` against, because before the first failure the series does not
// exist and the expression is simply absent rather than false.
func Init(version, commit, built string) {
	d := metrics.Describe
	d(MBuildInfo, metrics.Gauge, "Build information; always 1, labelled with the version, the git commit and the build date. The version constant only changes at a release, so the commit is what actually identifies a running binary — and answers whether a deploy took effect.")
	d(MStartTime, metrics.Gauge, "Unix timestamp of process start. Subtract from now for uptime: a phase duration that equals uptime means the work began at startup, which is the difference between slow and wedged-since-restart.")
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
	d(MHistoryUnverified, metrics.Gauge, "Epochs settled WITHOUT being verified — ones we gave up fetching after repeated attempts. These are holes inside the swept range: they count toward audited, so a rising value means coverage is less complete than the audited figure suggests. Alert on this being non-zero and growing.")
	d(MVerifiedRun, metrics.Gauge, "Length of the largest UNBROKEN run of verified epochs. This is the honest form of the coverage claim: the audited count says how much work was done, this says whether the result is a solid range or a sieve.")
	d(MVerifiedFrom, metrics.Gauge, "First epoch of the largest unbroken verified run.")
	d(MVerifiedTo, metrics.Gauge, "Last epoch of the largest unbroken verified run.")
	d(MHoles, metrics.Gauge, "Epochs inside the swept range that are settled but unverified — gaps in coverage. Retried on a growing backoff rather than abandoned, so a persistently non-zero value means genuinely unfetchable proofs, not a transient refusal.")
	d(MHistoryTotal, metrics.Gauge, "Epochs of published history in total.")
	d(MHistoryExpired, metrics.Gauge, "Epochs that have aged out of an operator's published window since this witness first looked. Not misbehaviour and not recoverable: the evidence needed to check those epochs is no longer served, so nobody can ever verify them. Alert on it RISING, not on its value — a growing figure means an operator's auditable window is closing faster than anyone is auditing it.")
	d(MHistoryFrom, metrics.Gauge, "First epoch of the published range coverage is measured against. Published because coverage is counted only INSIDE this range: work outside it is real but uncounted, which looks identical to no work at all.")
	d(MHistoryTo, metrics.Gauge, "Last epoch of the published range coverage is measured against.")
	d(MAuditPopulation, metrics.Gauge, "Audit records retained for this origin, across all epochs. Compare with history_audited_epochs: a large gap means most records fall outside the measured range, and a value pinned at the retention cap means the oldest are being evicted as fast as new ones arrive — which for a downward sweep means evicting exactly what it just wrote.")
	d(MHistoryCoverage, metrics.Gauge, "Fraction of published history construction audited, 0 to 1. Reaching 1 is what earns tier B+ — a bare tier B only covers epochs published since we started watching.")
	d(MAuditEpochs, metrics.Counter, "Epochs considered for construction auditing, by outcome: sampled, declined, verified, unavailable.")
	d(MAppHeads, metrics.Gauge, "Per-application heads observed. These are observations, never cosigned.")
	d(MAppConflicts, metrics.Gauge, "Contradictions recorded among observed application heads.")
	d(MScrapeSeconds, metrics.Gauge, "How long it took to gather these metrics from the store.")
	d(MPrefetchBytes, metrics.Gauge, "Bytes of proofs downloaded and waiting to be verified. AT THE CAP means downloads are outrunning verification, so the link has headroom and CPU is the constraint. NEAR ZERO while CPU is idle means the opposite: verification is starved and the link or the CDN is the constraint. This is the metric that tells those apart.")
	d(MPrefetchFiles, metrics.Gauge, "Proofs held in the disk cache awaiting verification.")
	d(MPrefetchMax, metrics.Gauge, "Configured cap on the proof cache, so occupancy can be read as a fraction without hardcoding the limit in a dashboard.")
	d(MPrefetchDiskFree, metrics.Gauge, "Free space on the volume holding the proof cache. The cache stops filling before this reaches the floor, because filling the volume would stop the witness recording what it has attested.")
	d(MProcCores, metrics.Gauge, "Cores visible to this process. Not namespaced, so inside a container this is the machine's count.")
	d(MProcGoroutines, metrics.Gauge, "Live goroutines. Monotonic growth means a leak; the staged history pipeline is the thing most likely to produce one.")
	d(MProcHeapBytes, metrics.Gauge, "Go heap in use. Excludes memory-mapped files, which is most of what Proton's replay touches.")
	d(MProcSysBytes, metrics.Gauge, "Memory obtained from the OS by the Go runtime.")
	d(MCgroupMemBytes, metrics.Gauge, "Container memory in use, including page cache.")
	d(MCgroupMemLimit, metrics.Gauge, "Container memory limit. The sidecar pool is derived from this, so it decides throughput as much as core count does.")
	d(MCgroupMemEvents, metrics.Counter, "cgroup memory.events by kind. ALERT ON `max`: it counts how often the container hit its ceiling and had to reclaim, which is not an error and never appears in a log, but sustained growth means time spent evicting and re-faulting pages instead of working. It reached 30,596 during a six-hour stall that nothing else surfaced. `oom_kill` is the same signal after it stops being survivable.")
	d(MCgroupCPUMax, metrics.Gauge, "Container CPU quota, or absent when unlimited.")
	d(MMachineMemBytes, metrics.Gauge, "Total machine memory. Published so a limit larger than the machine is visible rather than discovered by an OOM.")
	d(MMachineMemAvail, metrics.Gauge, "Machine memory available.")
	d(MCoverageAge, metrics.Gauge, "Age of the oldest cached coverage figure. Coverage is scanned from the audit record on a background cadence; if this grows without bound the cache has stopped refreshing and every coverage gauge is frozen — which looks identical to coverage that has stopped moving.")
	d(MDBBytes, metrics.Gauge, "Size of the bbolt database on disk. Note bbolt never returns freed pages to the filesystem, so this only grows; a large drop means the file was replaced.")
	d(MExportBytes, metrics.Gauge, "Size of the published file mirror.")
	d(MDiskFreeBytes, metrics.Gauge, "Bytes free on the filesystem holding the database.")
	d(MDiskTotalBytes, metrics.Gauge, "Total bytes on the filesystem holding the database.")
	d(MNetBytesIn, metrics.Counter, "Bytes received per log, counted as actually read rather than from Content-Length. Group by kind for per-ecosystem utilisation. Almost all of it is construction-audit proofs.")
	d(MNetBytesOut, metrics.Counter, "Bytes sent per log. A witness sends almost nothing.")
	d(MNetRequests, metrics.Counter, "HTTP requests issued per log.")
	d(MDiskUsedRatio, metrics.Gauge, "Fraction of the database filesystem in use, 0 to 1. A witness that runs out of disk stops witnessing.")

	d(MRounds, metrics.Counter, "Witness rounds completed.")
	d(MAuditPermits, metrics.Gauge, "Concurrent backlog verifications the CPU governor currently allows. Zero means the sweep is yielding, which is correct on a busy machine and a stall if it persists on an idle one.")
	d(MAuditInFlight, metrics.Gauge, "Backlog verifications running right now.")
	d(MCPUSelfCores, metrics.Gauge, "CPU cores this container is using, from cgroup v2 cpu.stat.")
	d(MCPUMachineCores, metrics.Gauge, "CPU cores busy across the whole host, from /proc/stat, which is not namespaced inside a container.")
	d(MCPUSampleComplete, metrics.Gauge, "1 if the governor could read both CPU figures. At 0 it is pacing blind and holds a conservative single permit.")
	d(MCosigned, metrics.Counter, "Cosignatures issued, by origin.")
	d(MConsecutiveWithheld, metrics.Gauge, "Consecutive rounds a log has failed to verify. Resets to 0 on success. Alert above ~20: withholding is the enforcement mechanism, so occasional is healthy and sustained is not.")
	d(MWithheld, metrics.Counter, "Cosignatures withheld because something could not be verified. Withholding is the enforcement mechanism, so a steady rate for one origin is the signal to look at.")
	d(MForkDetected, metrics.Counter, "Forks detected, by origin.")
	d(MFetchSeconds, metrics.Counter, "Cumulative seconds spent fetching heads, by origin.")
	d(MFetchCount, metrics.Counter, "Number of head fetches, by origin. Divide the sum by this for a mean.")
	d(MAuditVerified, metrics.Counter, "Construction proofs replayed and verified, by origin. Incremented by both the live path and the history sweep, so its rate does not distinguish keeping up from catching up.")
	d("kt_witness_audit_decode_seconds_sum", metrics.Counter, "Seconds spent decoding audit proofs, by origin. Read beside verify and download: which phase dominates decides whether this work could be moved to other hardware, and guessing at it has been wrong before.")
	d("kt_witness_audit_verify_seconds_sum", metrics.Counter, "Seconds spent verifying decoded audit proofs, by origin.")
	d("kt_witness_audit_download_seconds_sum", metrics.Counter, "Seconds spent fetching audit proofs, by origin. Large relative to the others means the link is the constraint, not the CPU.")
	d(MHistoryVerified, metrics.Counter, "Construction proofs verified by the HISTORY sweep alone, by origin. This is the one to rate for backlog progress: a flat line here with audit_verified_total still climbing means the sweep has stopped and only the tip is being audited.")
	d(MAuditBytes, metrics.Counter, "Bytes of construction proof downloaded and verified, by origin.")
	d(MAuditSeconds, metrics.Counter, "Cumulative seconds spent verifying construction proofs, by origin.")

	metrics.Set(MBuildInfo, map[string]string{
		"version": version, "commit": commit, "built": built}, 1)
	metrics.Set(MStartTime, nil, float64(time.Now().Unix()))
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
	// Coverage is served from a cache. If that cache stopped refreshing, every
	// coverage gauge would freeze at its last value and look exactly like
	// coverage that had stopped moving — the failure this codebase has now
	// rediscovered three times. Export the age so the two are distinguishable.
	metrics.Set(MCoverageAge, nil, s.coverage.oldest().Seconds())
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
			// Epochs settled without being verified: holes inside the swept
			// range. Exported beside the audited count rather than folded into
			// it, because a coverage figure that hides them reads as a
			// completeness it has not earned.
			metrics.Set(MHistoryUnverified, origin, float64(lg.HistoryUnverified))
			// The contiguous verified region, and the holes outside it. A
			// coverage count alone cannot distinguish a solid range from a
			// sieve, and only the solid range supports the tier B+ claim.
			metrics.Set(MVerifiedRun, origin, float64(lg.VerifiedRun))
			metrics.Set(MVerifiedFrom, origin, float64(lg.VerifiedFrom))
			metrics.Set(MVerifiedTo, origin, float64(lg.VerifiedTo))
			metrics.Set(MHoles, origin, float64(lg.Holes))
			metrics.Set(MHistoryAudited, origin, float64(lg.HistoryAudited))
			metrics.Set(MHistoryTotal, origin, float64(lg.HistoryTotal))
			if lg.History != nil {
				metrics.Set(MHistoryExpired, origin, float64(lg.History.Expired))
				metrics.Set(MHistoryFrom, origin, float64(lg.History.From))
				metrics.Set(MHistoryTo, origin, float64(lg.History.To))
			}
			n, err := s.Store.AuditPopulation(lg.Origin)
			if err != nil {
				return err
			}
			metrics.Set(MAuditPopulation, origin, float64(n))
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
