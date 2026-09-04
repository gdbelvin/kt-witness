// Command kt-witness runs a multi-log Key Transparency witness.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/cosig"
	"github.com/gdbsecurity/kt-witness/internal/export"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/server"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/source/akd"
	"github.com/gdbsecurity/kt-witness/internal/source/apple"
	"github.com/gdbsecurity/kt-witness/internal/source/c2sp"
	"github.com/gdbsecurity/kt-witness/internal/source/proton"
	ktsignal "github.com/gdbsecurity/kt-witness/internal/source/signal"
	"github.com/gdbsecurity/kt-witness/internal/source/sigsum"
	"github.com/gdbsecurity/kt-witness/internal/staticct"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
)

const version = "0.1.0"

type config struct {
	// Name is our witness identity, and appears in every cosignature line.
	Name string `json:"name"`

	Listen  string `json:"listen"`
	DB      string `json:"db"`
	KeyFile string `json:"key_file"`

	// PeerStatusURLs maps a witness name to its status page, polled to compare
	// its view against ours. Detection only: those pages are unsigned, so a
	// divergence is a lead to chase, never something to publish.
	PeerStatusURLs map[string]string `json:"peer_status_urls"`

	// PeerWitnesses are other witnesses' cosignature verifier keys. Their
	// cosignatures already ride on checkpoints we fetch, and a disagreement
	// with one of them is the only conclusive split-view evidence a single
	// witness can obtain.
	PeerWitnesses   []string `json:"peer_witnesses"`
	PollInterval    string   `json:"poll_interval"`
	MaxSignDelay    string   `json:"max_sign_delay"`
	RefreshInterval string   `json:"refresh_interval"`

	// ExportDir mirrors state as plain files beside the database, so evidence
	// can be read without this binary. Empty disables it.
	ExportDir string `json:"export_dir"`

	// Audit configures tier B: replaying construction proofs for a sampled
	// subset of epochs. Disabled unless sidecar_path is set.
	// ProtonAudit runs Proton's construction audit inside this process. It
	// retains a ~13.6 GB tree between epochs, which is what makes each step a
	// 3 MB job rather than a 13.6 GB one. Empty dir disables it.
	ProtonAudit struct {
		Dir          string `json:"dir"`
		DumpBase     string `json:"dump_base"`
		ShardDepth   int    `json:"shard_depth"`
		MinFreeBytes uint64 `json:"min_free_bytes"`
	} `json:"proton_audit"`

	Audit struct {
		SidecarPath string `json:"sidecar_path"`

		// SidecarWorkers is how many verifications may run at once. Each peaks
		// near 3.7 GB RSS, so this is a statement about the host's memory, not
		// about how fast auditing ought to go. Defaults to 1.
		SidecarWorkers int `json:"sidecar_workers"`

		// ReserveCores is how many cores to leave free for everything else. The
		// backlog sweep's budget is derived from the machine: it drives total
		// usage toward (cores - reserve). Defaults to 1 when pacing is on.
		//
		// Derived rather than stated because a core count is a fact about
		// hardware that changes, and a stale one has already cost this project
		// twice.
		ReserveCores float64 `json:"reserve_cores"`

		// TargetCores optionally overrides the derived budget, for an operator
		// who wants to use less than the machine allows.
		TargetCores float64 `json:"target_cores"`

		// Pace enables CPU pacing of the backlog sweep. Live auditing is never
		// paced.
		Pace bool `json:"pace_backlog"`

		SampleRate        float64 `json:"sample_rate"`
		Interval          string  `json:"interval"`
		Timeout           string  `json:"timeout"`
		BeaconURL         string  `json:"beacon_url"`
		MaxEpochsPerRound int64   `json:"max_epochs_per_round"`
	} `json:"audit"`

	Logs []logConfig `json:"logs"`
}

type logConfig struct {
	// Type selects the adapter: "c2sp" (default) or "akd".
	Type   string `json:"type"`
	Origin string `json:"origin"`

	// c2sp
	BaseURL       string `json:"base_url"`
	VKey          string `json:"vkey"`
	VerifyEntries bool   `json:"verify_entries"`

	// rekor: PEM public key, as served at /api/v1/log/publicKey, plus the
	// SIGNER name — which for Rekor is not the origin line (the origin carries
	// a tree id suffix).
	SignerName     string `json:"signer_name"`
	CheckpointPath string `json:"checkpoint_path"`
	PublicKeyPEM   string `json:"public_key_pem"`

	// staticct: the log's DER SubjectPublicKeyInfo, base64, exactly as
	// published in the CT log list. Origin must be the submission prefix
	// without scheme; BaseURL is the monitoring prefix.
	LogKey string `json:"log_key"`

	// sigsum: the log's Ed25519 public key as 64 hex characters, taken from a
	// sigsum trust policy. The origin is DERIVED from this key rather than
	// configured, so there is no way to point the adapter at a log without
	// naming which log it is.
	LogKeyHex string `json:"log_key_hex"`

	// akd / proton / signal
	APIBase           string   `json:"api_base"`
	Endpoint          string   `json:"endpoint"`
	AuditorKeys       []string `json:"auditor_keys"`
	TreeID            int64    `json:"tree_id"`
	PublicKeyDER      string   `json:"public_key_der"`
	MinAuditors       int      `json:"min_auditors"`
	LogDirectory      string   `json:"log_directory"`
	PlexiNamespaceURL string   `json:"plexi_namespace_url"`
	LogType           uint64   `json:"log_type"`
	Application       uint64   `json:"application"`
	// signal: names of the environment variables carrying the monitored
	// account's material. The values themselves are never in this file.
	AccountACIEnv         string `json:"account_aci_env"`
	AccountIdentityKeyEnv string `json:"account_identity_key_env"`
	AccountIntervalSec    int    `json:"account_interval_sec"`

	StartEpoch        int64 `json:"start_epoch"`
	MaxEpochsPerRound int64 `json:"max_epochs_per_round"`
}

func (l logConfig) build(log *slog.Logger, entries source.EntryStore, epochs source.EpochRecorder, audits source.AuditRecorder, ctLogs []proton.CTLog) (source.Source, error) {
	switch l.Type {
	case "", "c2sp":
		return c2sp.New(c2sp.Config{
			Origin: l.Origin, BaseURL: l.BaseURL, VKey: l.VKey,
			VerifyEntries: l.VerifyEntries,
			Audits:        audits,
		})
	case "akd":
		return akd.New(akd.Config{
			Origin:            l.Origin,
			LogDirectory:      l.LogDirectory,
			PlexiNamespaceURL: l.PlexiNamespaceURL,
			StartEpoch:        l.StartEpoch,
			MaxEpochsPerRound: l.MaxEpochsPerRound,
		})
	case "staticct":
		// Static CT logs are tlog-tiles logs whose checkpoint carries an
		// RFC 6962 tree head signature instead of Ed25519, so they reuse the
		// c2sp adapter with a different verifier.
		spki, err := base64.StdEncoding.DecodeString(l.LogKey)
		if err != nil {
			return nil, fmt.Errorf("log %q: log_key is not base64: %w", l.Origin, err)
		}
		v, err := staticct.NewVerifier(l.Origin, spki)
		if err != nil {
			return nil, fmt.Errorf("log %q: %w", l.Origin, err)
		}
		return c2sp.New(c2sp.Config{
			Origin: l.Origin, BaseURL: l.BaseURL, Verifier: v,
			// Entry verification is deliberately not offered here: static CT
			// serves entries at tile/entries with a different encoding from
			// tlog-tiles' tile/data, so the c2sp entry reader does not apply.
		})
	case "sumdb":
		// The Go checksum database predates c2sp.org/tlog-tiles: it serves the
		// same signed note at "latest" rather than "checkpoint", and addresses
		// tiles by the go.dev/design/25530-sumdb scheme. Neither difference
		// touches what is proven, so it is the ordinary c2sp adapter with the
		// two paths pointed elsewhere. Its origin line ("go.sum database tree")
		// is not its signer name ("sum.golang.org"), which the adapter allows
		// and pins independently.
		return c2sp.New(c2sp.Config{
			Origin: l.Origin, BaseURL: l.BaseURL, VKey: l.VKey,
			CheckpointPath: "latest", TileLayout: "sumdb",
			VerifyEntries: l.VerifyEntries,
		})
	case "sigsum":
		pub, err := hex.DecodeString(l.LogKeyHex)
		if err != nil {
			return nil, fmt.Errorf("log %q: log_key_hex is not hex: %w", l.Origin, err)
		}
		src, err := sigsum.New(sigsum.Config{Endpoint: l.BaseURL, PublicKey: pub})
		if err != nil {
			return nil, fmt.Errorf("log %q: %w", l.Origin, err)
		}
		// The configured origin is not trusted as the log's name — it is
		// checked against the one the key implies. A mismatch means the
		// operator pinned a key for a different log than they think, which is
		// exactly the confusion worth failing loudly on.
		if l.Origin != "" && l.Origin != src.Origin() {
			return nil, fmt.Errorf("log %q: configured origin does not match the key, which implies %q",
				l.Origin, src.Origin())
		}
		return src, nil
	case "proton":
		return proton.New(proton.Config{
			Origin:            l.Origin,
			APIBase:           l.APIBase,
			MaxEpochsPerRound: l.MaxEpochsPerRound,
			CTLogs:            ctLogs,
			Epochs:            epochs,
		})
	case "apple":
		return apple.New(apple.Config{
			Origin:       l.Origin,
			Endpoint:     l.Endpoint,
			TreeID:       uint64(l.TreeID),
			PublicKeyDER: l.PublicKeyDER,
			LogType:      l.LogType,
			Application:  l.Application,
		})
	case "signal":
		// Account material is read from the environment, never from the config
		// file: the config is committed and mounted into the container, and an
		// ACI identifies a real person. Supply it with `op run` or a Docker
		// secret so it exists only in the process.
		aci := os.Getenv(envOr(l.AccountACIEnv, "KT_SIGNAL_ACI"))
		idKey := os.Getenv(envOr(l.AccountIdentityKeyEnv, "KT_SIGNAL_ACI_IDENTITY_KEY"))
		if (aci == "") != (idKey == "") {
			// Half-configured monitors nothing while looking configured, which
			// is the worst of both.
			return nil, fmt.Errorf("log %q: set both the ACI and the identity key, or neither", l.Origin)
		}
		return ktsignal.New(ktsignal.Config{
			Origin:             l.Origin,
			Endpoint:           l.Endpoint,
			AuditorKeys:        l.AuditorKeys,
			MinAuditors:        l.MinAuditors,
			Entries:            entries,
			AccountACI:         aci,
			AccountIdentityKey: idKey,
			AccountInterval:    time.Duration(l.AccountIntervalSec) * time.Second,
			Log:                log,
		})
	default:
		return nil, fmt.Errorf("log %q: unknown type %q", l.Origin, l.Type)
	}
}

func main() {
	cfgPath := flag.String("config", "witness.json", "path to config file")
	genkey := flag.Bool("genkey", false, "generate a witness signing key and exit")
	once := flag.Bool("once", false, "run a single round and exit (for testing)")
	backfill := flag.Bool("backfill", false, "verify each log's published history before witnessing")
	retract := flag.String("retract-fork", "", "withdraw a fork finding for this origin and exit; requires -reason")
	reason := flag.String("reason", "", "why a fork finding is being withdrawn")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local monitoring endpoint and exit non-zero if it is not serving")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	if *healthcheck {
		// The monitoring endpoint is what makes our cosignatures usable by
		// anyone else, so "healthy" means it is serving — not merely that the
		// process exists.
		if err := probe(cfg.Listen); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *genkey {
		if err := generateKey(cfg); err != nil {
			log.Error("genkey", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := run(cfg, log, *once, *backfill, *retract, *reason); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// probe checks the monitoring endpoint from inside the container, so the image
// needs no curl.
func probe(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("healthcheck: bad listen address %q: %w", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: HTTP %d", resp.StatusCode)
	}
	return nil
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{Listen: ":8080", DB: "witness.db", PollInterval: "60s", MaxSignDelay: "30s", RefreshInterval: "1h"}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		return nil, errors.New("config: name is required (it appears in every cosignature)")
	}
	if cfg.KeyFile == "" {
		return nil, errors.New("config: key_file is required")
	}
	return cfg, nil
}

// generateKey writes a new Ed25519 signing key. In production this key belongs
// in hardware; a file is the development path only.
func generateKey(cfg *config) error {
	if _, err := os.Stat(cfg.KeyFile); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a signing key", cfg.KeyFile)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.KeyFile, []byte(fmt.Sprintf("%x\n", priv.Seed())), 0o600); err != nil {
		return err
	}
	signer, err := torchwood.NewCosignatureSigner(cfg.Name, priv)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\npublish this verifier key:\n  %s\n", cfg.KeyFile, signer.Verifier().String())
	return nil
}

func loadSigner(cfg *config) (*torchwood.CosignatureSigner, error) {
	raw, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key: %w (run -genkey first)", err)
	}
	var seed []byte
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%x", &seed); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key: want %d-byte seed, got %d", ed25519.SeedSize, len(seed))
	}
	return torchwood.NewCosignatureSigner(cfg.Name, ed25519.NewKeyFromSeed(seed))
}

func run(cfg *config, log *slog.Logger, once, backfill bool, retractOrigin, retractReason string) error {
	signer, err := loadSigner(cfg)
	if err != nil {
		return err
	}
	vkey := signer.Verifier().String()

	db, err := store.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()

	pollInterval, err := time.ParseDuration(cfg.PollInterval)
	if err != nil {
		return fmt.Errorf("poll_interval: %w", err)
	}
	maxSignDelay, err := time.ParseDuration(cfg.MaxSignDelay)
	if err != nil {
		return fmt.Errorf("max_sign_delay: %w", err)
	}

	// Proton confirms each epoch certificate's presence in a CT log we already
	// witness, so it needs the whole configured CT set. The whole set, not a
	// hand-picked log: CT shards are temporal and rotate underneath Proton's
	// ~90-day certificates, so pinning one would start withholding the moment
	// their CA moved on.
	var ctLogs []proton.CTLog
	for _, l := range cfg.Logs {
		if l.Type != "staticct" || l.LogKey == "" {
			continue
		}
		spki, err := base64.StdEncoding.DecodeString(l.LogKey)
		if err != nil {
			return fmt.Errorf("log %q: log_key is not base64: %w", l.Origin, err)
		}
		ctLogs = append(ctLogs, proton.CTLog{Origin: l.Origin, BaseURL: l.BaseURL, SPKI: spki})
	}

	var sources []source.Source
	for _, l := range cfg.Logs {
		src, err := l.build(log, db, db, db, ctLogs)
		if err != nil {
			return err
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		return errors.New("config: no logs configured")
	}

	// The tier each origin is witnessed at, so the status page can publish it.
	// Taken from the sources themselves rather than the config, because the
	// source is what actually decides.
	server.Init(version)
	tiers := make(map[string]string, len(sources))
	for _, src := range sources {
		tiers[src.Origin()] = src.Tier().String()
	}
	// What KIND of transparency each log provides. With ~77 origins, most of
	// them certificate logs, a per-origin chart is unreadable and the useful
	// question is almost always "how are the KT logs doing" or "is any CT log
	// stale". The kind makes that a filter rather than a scroll.
	kinds := make(map[string]string, len(cfg.Logs))
	for _, l := range cfg.Logs {
		kinds[l.Origin] = kindOf(l)
	}
	// Published before any goroutine reads it, and never written again.
	logKinds = kinds

	refreshInterval, err := time.ParseDuration(cfg.RefreshInterval)
	if err != nil {
		return fmt.Errorf("refresh_interval: %w", err)
	}

	var auditor *audit.Auditor
	var auditInterval time.Duration
	var resolvers []audit.Resolver
	if cfg.Audit.SidecarPath != "" {
		if auditInterval, err = time.ParseDuration(orDefault(cfg.Audit.Interval, "5m")); err != nil {
			return fmt.Errorf("audit.interval: %w", err)
		}
		auditTimeout, err := time.ParseDuration(orDefault(cfg.Audit.Timeout, "5m"))
		if err != nil {
			return fmt.Errorf("audit.timeout: %w", err)
		}
		rate := cfg.Audit.SampleRate
		if rate <= 0 {
			rate = 0.1
		}
		workers := cfg.Audit.SidecarWorkers
		if workers < 1 {
			workers = 1
		}
		sidecar := audit.NewPool(cfg.Audit.SidecarPath, workers)
		defer sidecar.Close()
		// Pace the backlog against measured CPU rather than a fixed budget. A
		// constant is wrong the moment the hardware or the proof sizes change:
		// the previous value was chosen when a verification took 94 s on four
		// cores, and after more cores arrived it left five of them idle while
		// the backlog still measured months.
		var governor *audit.Governor
		if cfg.Audit.Pace || cfg.Audit.TargetCores > 0 || cfg.Audit.ReserveCores > 0 {
			governor = &audit.Governor{
				ReserveCores:  cfg.Audit.ReserveCores,
				TargetCores:   cfg.Audit.TargetCores,
				MaxConcurrent: workers,
				Log:           log,
			}
		}
		auditor = &audit.Auditor{
			Store: db, Beacon: audit.NewBeacon(cfg.Audit.BeaconURL),
			Sidecar: sidecar, Log: log, Rate: rate, Timeout: auditTimeout,
			MaxEpochsPerRound: maxEpochsPerRound(cfg.Audit.MaxEpochsPerRound),
			Governor:          governor,
		}
		for _, src := range sources {
			if r, ok := src.(audit.Resolver); ok {
				resolvers = append(resolvers, r)
			}
		}
		log.Info("tier B auditing enabled", "sidecar", cfg.Audit.SidecarPath,
			"sample_rate", rate, "logs", len(resolvers), "interval", auditInterval.String(),
			"workers", sidecar.Size(),
			"peak_memory_estimate_gb", float64(sidecar.Size())*3.7)
	}

	peers, err := cosig.NewVerifier(cfg.PeerWitnesses)
	if err != nil {
		return err
	}

	w := &witness.Witness{
		Signer: signer, Store: db, Log: log,
		MaxSignDelay:    maxSignDelay,
		RefreshInterval: refreshInterval,
		Peers:           peers,
	}
	if n := len(peers.Names()); n > 0 {
		log.Info("reading other witnesses' cosignatures", "witnesses", peers.Names())
	}

	log.Info("starting", "version", version, "name", cfg.Name, "logs", len(sources),
		"poll", pollInterval.String(), "refresh", refreshInterval.String(), "vkey", vkey)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	if cfg.ProtonAudit.Dir != "" {
		startProtonAudit(ctx, cfg, sources, db, log)
	}
	if len(cfg.PeerStatusURLs) > 0 {
		startPeerPolling(ctx, cfg.PeerStatusURLs, db, log)
	}
	defer stop()

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&server.Server{Store: db, VKey: vkey, Version: version, Tiers: tiers, Kinds: kinds,
			Storage: server.StoragePaths{DBPath: cfg.DB, ExportDir: cfg.ExportDir}}).Handler(),
	}
	// Bind before starting to witness. A witness whose monitoring endpoint is
	// unreachable is cosigning into the void, so a listener failure is fatal
	// rather than logged and ignored.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server stopped", "err", err)
			stop()
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if retractOrigin != "" {
		// Deliberately explicit: a retraction names its reason, keeps the
		// original evidence, and is recorded as an event in its own right.
		if err := db.RetractFork(retractOrigin, retractReason); err != nil {
			return err
		}
		log.Warn("FORK FINDING WITHDRAWN — the accusation is retracted, the evidence is retained",
			"origin", retractOrigin, "reason", retractReason)
		return nil
	}

	if backfill {
		// Backfill runs in the BACKGROUND, immediately and then on a schedule.
		//
		// It used to run synchronously before the witness loop started, which
		// is why it was never switched on in the deployment: walking Meta's
		// 536,000-epoch listing before witnessing anything means minutes with no
		// equivocation detection, and equivocation is the live incident.
		// History is a completeness exercise and has no business delaying it.
		//
		// Repeating matters as much as starting. Coverage counts audits landing
		// inside the backfilled range, so a range whose upper bound is frozen at
		// the tip of whenever it last ran stops counting today's work, and the
		// gap grows without limit — WhatsApp had drifted 1,628 epochs past its
		// own recorded history. This walks listing metadata, not proofs, so
		// repeating it is cheap relative to what it keeps honest.
		go func() {
			for {
				runBackfill(ctx, db, sources, log)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backfillRefresh):
				}
			}
		}()
	}

	var exporter *export.Exporter
	if cfg.ExportDir != "" {
		exporter = &export.Exporter{
			Dir: cfg.ExportDir, Store: db, VKey: vkey, Version: version,
		}
		log.Info("exporting state as files", "dir", cfg.ExportDir)
	}
	mirror := func() {
		if exporter == nil {
			return
		}
		// Never fatal: the mirror is derived, and failing to write it must not
		// stop the witness from witnessing.
		if err := exporter.Run(time.Now()); err != nil {
			log.Warn("export", "err", err)
		}
	}

	// Witness once before auditing starts. The auditor works from what we have
	// already attested, so launching it first would spend its opening pass on an
	// empty store and then sleep a full interval before doing anything useful.
	round(ctx, w, sources, db, log)
	mirror()
	if once {
		return nil
	}

	if auditor != nil && auditor.Governor != nil {
		go auditor.Governor.Run(ctx)
		log.Info("backlog sweep paced against CPU",
			"cores_detected", runtime.NumCPU(),
			"budget_cores", auditor.Governor.BudgetFor(float64(runtime.NumCPU())),
			"reserve_cores", cfg.Audit.ReserveCores,
			"max_concurrent", cfg.Audit.SidecarWorkers,
			"note", "live auditing is never paced")
	}

	if auditor != nil && len(resolvers) > 0 {
		// Auditing runs on its own cadence: one verification takes ~24 s and
		// must not stall the witness loop's ability to detect equivocation.
		go func() {
			for {
				// Audits across ecosystems are independent and dominated by
				// download time, so they overlap. The sidecar itself is the
				// serialisation point for CPU, which is what we want: memory
				// peaks at ~3.7 GB per verification and running several at once
				// would blow the container limit.
				var awg sync.WaitGroup
				for _, r := range resolvers {
					awg.Add(1)
					go func(r audit.Resolver) {
						defer awg.Done()
						if err := auditor.Run(ctx, r); err != nil && ctx.Err() == nil {
							log.Warn("audit round", "origin", r.Origin(), "err", err)
						}
					}(r)
				}
				awg.Wait()

				select {
				case <-ctx.Done():
					return
				case <-time.After(auditInterval):
				}
			}
		}()

		// The backwards sweep runs on its OWN goroutine, not after the forward
		// one.
		//
		// It used to run after awg.Wait(), which read as a sensible priority
		// rule — the tip is a live incident, history is a completeness exercise
		// — but it made history's progress conditional on the forward pass ever
		// finishing. With an unbounded backlog the forward pass does not
		// finish for days, so the sweep never ran at all: 31 of Meta's 536,043
		// epochs, frozen, with no error and no log line to say why. A
		// completeness metric that silently stops moving is worse than one that
		// is honestly slow.
		//
		// Priority is now enforced where it actually belongs — the sidecar
		// mutex — so the two sweeps interleave one verification at a time
		// instead of one starving the other. Memory stays bounded because only
		// one verification ever runs.
		go func() {
			for {
				// Across origins in parallel, like the forward sweep. The
				// sidecar pool is what bounds real concurrency, so fanning out
				// here costs nothing when the pool is small and uses the whole
				// pool when it is not.
				var hwg sync.WaitGroup
				for _, r := range resolvers {
					hwg.Add(1)
					go func(r audit.Resolver) {
						defer hwg.Done()
						out, err := auditor.RunHistory(ctx, r, historyBudgetPerRound)
						if err != nil && ctx.Err() == nil {
							log.Warn("history sweep", "origin", r.Origin(), "err", err)
							return
						}
						if out != nil && out.Verified > 0 {
							log.Info("history swept", "origin", out.Origin,
								"from", out.From, "to", out.To, "verified", out.Verified,
								"remaining", out.Remaining, "complete", out.Complete)
						}
					}(r)
				}
				hwg.Wait()
				select {
				case <-ctx.Done():
					return
				case <-time.After(auditInterval):
				}
			}
		}()
	}

	// Scanning surfaces other logs' heads carried inside a log we witness —
	// Apple's Top-Level Tree is a log of per-application heads, iMessage among
	// them. Observations only: they are recorded, never cosigned.
	scanApplications(ctx, db, sources, log)

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return nil
		case <-time.After(pollInterval):
		}
		round(ctx, w, sources, db, log)
		scanApplications(ctx, db, sources, log)
		mirror()
	}
}

// runBackfill verifies each log's published history. It is best-effort: a log
// that cannot be backfilled is reported and skipped, because refusing to witness
// the present over a problem in the past would be the wrong trade.
func runBackfill(ctx context.Context, db *store.Store, sources []source.Source, log *slog.Logger) {
	for _, src := range sources {
		b, ok := src.(source.Backfiller)
		if !ok {
			continue
		}
		log.Info("backfill starting", "origin", src.Origin())
		start := time.Now()

		res, err := b.Backfill(ctx, log)
		if err != nil {
			var fe *source.ForkError
			if errors.As(err, &fe) {
				// A contradiction in published history is as conclusive as one
				// found live, and must poison the log the same way.
				log.Error("FORK DETECTED IN PUBLISHED HISTORY",
					"origin", src.Origin(), "reason", fe.Reason)
				db.RecordFork(&store.Fork{
					Origin: src.Origin(), Reason: fe.Reason, DetectedAt: time.Now().UTC(),
				})
				continue
			}
			log.Warn("backfill failed", "origin", src.Origin(), "err", err)
			continue
		}

		h := &store.History{
			Origin: src.Origin(), From: res.From, To: res.To,
			Epochs: res.Epochs, Gaps: res.Gaps, VerifiedAt: time.Now().UTC(),
		}
		if err := db.RecordHistory(h); err != nil {
			log.Warn("recording backfill", "origin", src.Origin(), "err", err)
		}
		log.Info("backfill complete", "origin", src.Origin(),
			"from", res.From, "to", res.To, "epochs", res.Epochs,
			"gaps", len(res.Gaps), "took", time.Since(start).Round(time.Second).String())
	}
}

func scanApplications(ctx context.Context, db *store.Store, sources []source.Source, log *slog.Logger) {
	now := time.Now().UTC()
	for _, src := range sources {
		sc, ok := src.(source.Scanner)
		if !ok {
			continue
		}
		heads, err := sc.ScanApplications(ctx)
		if err != nil {
			log.Warn("application scan", "origin", src.Origin(), "err", err)
			continue
		}
		for _, h := range heads {
			obs := &store.AppHead{
				Origin: src.Origin(), TreeID: h.TreeID, Application: h.Application,
				Name: h.Name, LogSize: h.LogSize, Revision: h.Revision,
				RootHash:       hex.EncodeToString(h.RootHash),
				SigningKeyHash: hex.EncodeToString(h.SigningKeyHash),
			}
			merged, fresh, err := db.ObserveAppHead(now, obs)
			if err != nil {
				log.Warn("recording application head", "tree", h.TreeID, "err", err)
				continue
			}
			// Conflicts are not evidence of misbehaviour we can stand behind —
			// these heads are not signature-verified — but they are exactly what
			// a human should look at. Only newly seen ones are reported: an alarm
			// that repeats every scan forever is an alarm nobody reads.
			if n := len(fresh); n > 0 {
				log.Error("CONTRADICTION IN OBSERVED APPLICATION HEAD",
					"application", h.Name, "tree", h.TreeID,
					"new", n, "latest", fresh[n-1], "total", len(merged.Conflicts))
			}
		}
	}
}

// roundConcurrency bounds how many logs are polled at once.
//
// Every source is network-bound and independent, so a sequential round takes as
// long as the sum of every operator's latency — which at ten origins is already
// most of a poll interval, and at ninety would exceed it outright. A log that is
// polled late is a log where equivocation goes unnoticed for longer, so this is
// a correctness property, not just speed.
//
// Bounded rather than unbounded: the store serialises writes anyway, and one
// burst of ninety simultaneous TLS handshakes is a good way to look like an
// attacker to somebody's rate limiter.
const roundConcurrency = 8

// sustainedWithholding is how many consecutive failed rounds for one log turn a
// routine warning into something that demands attention. At a 60 s poll that is
// roughly twenty minutes of a log not being witnessed at all.
const sustainedWithholding = 20

// historyBudgetPerRound bounds how many historical epochs one pass audits.
//
// Small on purpose. Meta alone has 625,000 published epochs at ~24 s of
// verification each; sweeping them is a months-long background task, not
// something to finish today, and it must never crowd out the forward auditing
// that catches an active equivocation.
const historyBudgetPerRound = 4

// withholding tracks consecutive failures per origin, so a persistent problem
// is distinguishable from the ordinary transient one.
var withholding = &failureTracker{n: map[string]int{}}

type failureTracker struct {
	mu sync.Mutex
	n  map[string]int
}

func (f *failureTracker) fail(origin string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n[origin]++
	metrics.Set(server.MConsecutiveWithheld, labelsFor(origin), float64(f.n[origin]))
	return f.n[origin]
}

func (f *failureTracker) ok(origin string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n[origin] != 0 {
		f.n[origin] = 0
	}
	metrics.Set(server.MConsecutiveWithheld, labelsFor(origin), 0)
}

func round(ctx context.Context, w *witness.Witness, sources []source.Source, db *store.Store, log *slog.Logger) {
	sem := make(chan struct{}, roundConcurrency)
	var wg sync.WaitGroup

	for _, src := range sources {
		wg.Add(1)
		go func(src source.Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			origin := labelsFor(src.Origin())
			roundCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			started := time.Now()
			out, err := w.Process(roundCtx, src)
			cancel()
			metrics.Add(server.MFetchSeconds, origin, time.Since(started).Seconds())
			metrics.Inc(server.MFetchCount, origin)

			switch {
			case err != nil:
				var fe *source.ForkError
				if errors.As(err, &fe) {
					metrics.Inc(server.MForkDetected, origin)
					// Already logged and persisted as evidence by the core. This
					// log is now permanently un-cosignable until a human decides
					// otherwise.
					return
				}
				metrics.Inc(server.MWithheld, origin)
				if n := withholding.fail(src.Origin()); n >= sustainedWithholding {
					// Withholding is the enforcement mechanism, so one is the
					// system working. A log that has not verified for this long
					// is different: either the operator is broken or we are, and
					// nobody finds out from a WARN in a stream of WARNs.
					log.Error("SUSTAINED WITHHOLDING — no cosignature issued for this log in "+
						"consecutive rounds; this needs a human",
						"origin", src.Origin(), "consecutive_failures", n, "err", err)
				} else {
					log.Warn("withheld cosignature", "origin", src.Origin(), "err", err)
				}
			case out.Unchanged:
				withholding.ok(src.Origin())
				recordSearch(db, src, log)
				log.Debug("unchanged", "origin", out.Origin, "size", out.Size)
				metrics.Inc(server.MCosigned, origin)
			default:
				withholding.ok(src.Origin())
				recordSearch(db, src, log)
				metrics.Inc(server.MCosigned, origin)
			}
		}(src)
	}
	wg.Wait()
	metrics.Inc(server.MRounds, nil)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// kindOf classifies a log by what it makes transparent, which is a different
// axis from the assurance tier: a tier-A certificate log and a tier-A key
// transparency log are the same strength of claim about very different things.
func kindOf(l logConfig) string {
	// Rekor is a plain tlog-tiles log, so it arrives here as type "c2sp" and
	// would otherwise be classified "generic". What it makes transparent is
	// software provenance — npm and PyPI attestations chain to it — so it is
	// named by what it carries, not by the adapter that happens to read it.
	if strings.HasSuffix(l.Origin, ".rekor.sigstore.dev") {
		return "software"
	}
	switch l.Type {
	case "akd", "proton", "signal":
		return "kt"
	case "apple":
		// Apple runs both: the Top-Level Tree is key transparency, the AT log is
		// software transparency for Private Cloud Compute.
		if l.TreeID != 0 && uint64(l.TreeID) == apple.ATLogTreeID {
			return "software"
		}
		return "kt"
	case "staticct":
		return "ct"
	case "sumdb", "sigsum":
		return "software"
	default:
		return "generic"
	}
}

// recordSearch persists the most recent verified search proof so the published
// mirror can show what was actually opened, not merely that something was.
//
// Best effort: failing to record evidence is not a reason to withhold a
// cosignature that is otherwise fully verified.
func recordSearch(db *store.Store, src source.Source, log *slog.Logger) {
	type searcher interface{ LastSearch() *ktsignal.SearchResult }
	s, ok := src.(searcher)
	if !ok {
		return
	}
	sr := s.LastSearch()
	if sr == nil {
		return
	}
	if err := db.PutSearch(src.Origin(), &store.SearchRecord{
		Key:        string(ktsignal.DistinguishedKey),
		Index:      sr.Index,
		Pos:        sr.Pos,
		Version:    sr.Version,
		Value:      sr.Value,
		Entries:    sr.Entries,
		Root:       sr.Root,
		VerifiedAt: time.Now().Unix(),
	}); err != nil {
		log.Warn("persisting verified search", "origin", src.Origin(), "err", err)
	}
}

// startProtonAudit runs Proton's construction audit in the background.
//
// Deliberately its own goroutine at a slow cadence. One step is about nineteen
// minutes of CPU against a four-hour epoch, so it fits — but it must never sit
// in the path of the witness loop, which has to stay responsive to catch
// equivocation. A construction audit is thoroughness; equivocation detection is
// urgency, and urgency wins.
func startProtonAudit(ctx context.Context, cfg *config, sources []source.Source, db *store.Store, log *slog.Logger) {
	var origin string
	for _, src := range sources {
		if src.Origin() == source.OriginProton {
			origin = src.Origin()
		}
	}
	if origin == "" {
		log.Warn("proton audit configured but proton is not witnessed")
		return
	}

	api := "https://api.protonmail.ch"
	for _, l := range cfg.Logs {
		if l.Origin == origin && l.APIBase != "" {
			api = l.APIBase
		}
	}
	dumps := cfg.ProtonAudit.DumpBase
	if dumps == "" {
		dumps = "https://proton.me/kt"
	}

	a := &proton.IncrementalAuditor{
		Dir: cfg.ProtonAudit.Dir, APIBase: api, DumpBase: dumps,
		ShardDepth: cfg.ProtonAudit.ShardDepth, MinFreeBytes: cfg.ProtonAudit.MinFreeBytes,
	}

	go func() {
		// Proton publishes roughly every four hours; checking every thirty
		// minutes catches a new epoch promptly without polling hard.
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			runProtonStep(ctx, a, db, origin, log)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func runProtonStep(ctx context.Context, a *proton.IncrementalAuditor, db *store.Store, origin string, log *slog.Logger) {
	base, err := a.Base()
	if err != nil {
		log.Warn("proton audit: reading retained tree", "err", err)
		return
	}
	rec, err := db.Get(origin)
	if err != nil || rec == nil {
		return // nothing witnessed yet
	}
	tip := rec.Size

	if base == 0 {
		// Cold start: ~13.6 GB and about eight minutes, once. Everything about
		// this design exists to avoid needing it again.
		log.Info("proton audit: bootstrapping retained tree — this is a one-off "+
			"~13.6 GB download", "epoch", tip)
		if err := a.Bootstrap(ctx, tip); err != nil {
			log.Warn("proton audit: bootstrap", "epoch", tip, "err", err)
		}
		return
	}
	if base >= tip {
		return // already caught up
	}

	next := base + 1
	meta, err := a.FetchEpochMeta(ctx, next)
	if err != nil {
		log.Warn("proton audit: epoch metadata", "epoch", next, "err", err)
		return
	}

	res, err := a.Step(ctx, base, next, meta)
	if err != nil {
		// A tree-hash mismatch is conclusive and the evidence is retained on
		// disk, but it is reported rather than used to poison the log here: the
		// witness core owns that decision, and a human should see this first.
		log.Error("PROTON CONSTRUCTION AUDIT FAILED — the published diff does not "+
			"carry one epoch into the next; evidence retained on disk",
			"from", base, "to", next, "err", err)
		return
	}

	log.Info("proton epoch construction audited",
		"from", res.From, "to", res.To, "leaves", res.Leaves,
		"added", res.Stats.Added, "removed", res.Stats.Removed,
		"root", res.ComputedRoot[:16], "took", res.Elapsed.Round(time.Second))

	// Record the audit so the coverage accounting can see it.
	//
	// Without this the strongest construction evidence in the project was
	// invisible. Proton is the only deployment here that publishes its whole
	// directory, so it is the only one where the entire tree can be rebuilt and
	// checked against the signed root — which this has been doing, in
	// production, while the witness went on reporting tier A+ because
	// AuditCoverage counts stored records and nothing was storing any.
	//
	// Only a success is recorded. A failed rebuild is already logged loudly and
	// deliberately does not poison the log here; recording it as a settled
	// negative would also let a transient I/O failure masquerade as a
	// construction fault, and absence is not evidence.
	if res.Match {
		ar := &store.Audit{
			Origin: origin, Epoch: res.To,
			// Not drawn by beacon: every epoch is rebuilt in full, so rate 1
			// records that this epoch was checked outright rather than sampled.
			Sampled: true, Rate: 1, Strategy: "rebuild",
			Verified: true, Attempts: 1, DecidedAt: time.Now().UTC(),
		}
		if err := db.RecordAudit(ar); err != nil {
			log.Warn("proton audit: recording", "epoch", res.To, "err", err)
		}
	}

	if res.Removals != nil && !res.Removals.Clean() {
		log.Error("PROTON REMOVALS NOT EXPLAINED BY THE RETENTION WINDOW — "+
			"withholding judgement, not accusing; the window rule is inferred "+
			"from behaviour rather than promised",
			"epoch", res.To, "summary", res.Removals.Summary())
	}
}

// startPeerPolling compares other witnesses' published views against our own.
//
// This is the half of gossip that is possible today. A witness reading
// cosignatures off checkpoints it fetched cannot detect a split view — every
// signature there sits over the same body, so they agree by construction. Only
// an independently obtained view can differ, and polling is how we get one.
//
// It is DETECTION ONLY. The pages are unsigned, so a divergence found here
// cannot support an accusation; it is the signal to go and obtain the signed
// artifact. The witness never poisons a log on this evidence.
func startPeerPolling(ctx context.Context, peers map[string]string, db *store.Store, log *slog.Logger) {
	p := cosig.NewPeerPoller(peers)
	names := make([]string, 0, len(peers))
	for n := range peers {
		names = append(names, n)
	}
	log.Info("polling peer witnesses for their published views", "peers", names)

	go func() {
		// Hourly. Their pages change as slowly as the logs do, and a witness
		// that hammers its peers is a bad neighbour.
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			for name := range peers {
				views, err := p.Poll(ctx, name)
				if err != nil {
					log.Warn("polling peer", "peer", name, "err", err)
					continue
				}
				comparePeerViews(name, views, db, log)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// comparePeerViews looks for a peer reporting a different root at a size we
// also witnessed.
func comparePeerViews(peer string, views []cosig.PeerView, db *store.Store, log *slog.Logger) {
	var checked, agreed, sizeOnly int
	for _, v := range views {
		rec, err := db.Get(v.Origin)
		if err != nil || rec == nil {
			continue // we do not witness this log; nothing to compare
		}
		if !v.HasRoot() {
			// A size with no root cannot contradict anything. Counted so the
			// log line distinguishes "we compared and agreed" from "there was
			// nothing to compare", which otherwise look identical.
			sizeOnly++
			continue
		}
		if rec.Size != v.Size {
			// Different sizes are just different moments. Only the same size
			// can disagree.
			continue
		}
		checked++
		ours := base64.StdEncoding.EncodeToString(rec.Hash[:])
		if ours == v.Root {
			agreed++
			continue
		}
		d := &cosig.Divergence{
			Origin: v.Origin, Size: v.Size,
			OurRoot: ours, Witness: peer, TheirRoot: v.Root,
		}
		log.Error("PEER DIVERGENCE — another witness publishes a different root at "+
			"a size we also witnessed", "detail", d.String())
	}
	if checked > 0 || sizeOnly > 0 {
		log.Info("peer view compared", "peer", peer,
			"logs_in_common_at_same_size", checked, "agreed", agreed,
			"size_only_not_comparable", sizeOnly)
	}
}

// envOr returns name if set, else the default variable name.
func envOr(name, dflt string) string {
	if name != "" {
		return name
	}
	return dflt
}

// maxEpochsPerRound bounds how many epochs one forward pass considers.
//
// Zero used to mean unbounded, which is the setting that stalled the backwards
// sweep in production: with a long backlog the forward pass ran for days
// without returning, and anything sequenced after it never happened. Unbounded
// is not a useful choice for a loop that is supposed to come back around, so an
// unset value now means a bound rather than none.
//
// 64 is roughly two hours of Meta epochs, so a caught-up witness never notices
// the cap, and a witness with a backlog still yields between passes.
func maxEpochsPerRound(configured int64) int64 {
	if configured > 0 {
		return configured
	}
	return 64
}

// backfillRefresh is how often published history is re-walked so the recorded
// range keeps up with the tip.
//
// Six hours is short enough that the coverage metric stays close to true and
// long enough that re-listing a 536,000-epoch bucket is not a background load
// worth noticing.
const backfillRefresh = 6 * time.Hour

// logKinds maps an origin to what it makes transparent, populated once at
// startup and read-only thereafter.
//
// It exists so metric emission sites can label by ecosystem without threading
// the config through every call. Two metrics went without it for a while and
// the dashboard quietly lied about them: panels titled "by kind" grouped on a
// label that was never present, so every log collapsed into one unnamed series
// and a per-ecosystem rate was really one arbitrary log's counter.
var logKinds map[string]string

// labelsFor builds the standard metric labels for an origin.
//
// An unknown origin is labelled "generic" rather than left blank: an empty
// label value is indistinguishable in the exposition format from a missing
// series, which is precisely the confusion this is here to end.
func labelsFor(origin string) map[string]string {
	kind := logKinds[origin]
	if kind == "" {
		kind = "generic"
	}
	return map[string]string{"origin": origin, "kind": kind}
}
