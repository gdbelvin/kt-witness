// Command kt-witness runs a multi-log Key Transparency witness.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/server"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/source/akd"
	"github.com/gdbsecurity/kt-witness/internal/source/c2sp"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"github.com/gdbsecurity/kt-witness/internal/witness"
)

const version = "0.1.0"

type config struct {
	// Name is our witness identity, and appears in every cosignature line.
	Name string `json:"name"`

	Listen          string `json:"listen"`
	DB              string `json:"db"`
	KeyFile         string `json:"key_file"`
	PollInterval    string `json:"poll_interval"`
	MaxSignDelay    string `json:"max_sign_delay"`
	RefreshInterval string `json:"refresh_interval"`

	// Audit configures tier B: replaying construction proofs for a sampled
	// subset of epochs. Disabled unless sidecar_path is set.
	Audit struct {
		SidecarPath       string  `json:"sidecar_path"`
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
	BaseURL string `json:"base_url"`
	VKey    string `json:"vkey"`

	// akd
	LogDirectory      string `json:"log_directory"`
	PlexiNamespaceURL string `json:"plexi_namespace_url"`
	StartEpoch        int64  `json:"start_epoch"`
	MaxEpochsPerRound int64  `json:"max_epochs_per_round"`
}

func (l logConfig) build() (source.Source, error) {
	switch l.Type {
	case "", "c2sp":
		return c2sp.New(c2sp.Config{Origin: l.Origin, BaseURL: l.BaseURL, VKey: l.VKey})
	case "akd":
		return akd.New(akd.Config{
			Origin:            l.Origin,
			LogDirectory:      l.LogDirectory,
			PlexiNamespaceURL: l.PlexiNamespaceURL,
			StartEpoch:        l.StartEpoch,
			MaxEpochsPerRound: l.MaxEpochsPerRound,
		})
	default:
		return nil, fmt.Errorf("log %q: unknown type %q", l.Origin, l.Type)
	}
}

func main() {
	cfgPath := flag.String("config", "witness.json", "path to config file")
	genkey := flag.Bool("genkey", false, "generate a witness signing key and exit")
	once := flag.Bool("once", false, "run a single round and exit (for testing)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	if *genkey {
		if err := generateKey(cfg); err != nil {
			log.Error("genkey", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := run(cfg, log, *once); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
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

func run(cfg *config, log *slog.Logger, once bool) error {
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

	var sources []source.Source
	for _, l := range cfg.Logs {
		src, err := l.build()
		if err != nil {
			return err
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		return errors.New("config: no logs configured")
	}

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
		sidecar := audit.NewSidecar(cfg.Audit.SidecarPath)
		defer sidecar.Close()
		auditor = &audit.Auditor{
			Store: db, Beacon: audit.NewBeacon(cfg.Audit.BeaconURL),
			Sidecar: sidecar, Log: log, Rate: rate, Timeout: auditTimeout,
			MaxEpochsPerRound: cfg.Audit.MaxEpochsPerRound,
		}
		for _, src := range sources {
			if r, ok := src.(audit.Resolver); ok {
				resolvers = append(resolvers, r)
			}
		}
		log.Info("tier B auditing enabled", "sidecar", cfg.Audit.SidecarPath,
			"sample_rate", rate, "logs", len(resolvers), "interval", auditInterval.String())
	}

	w := &witness.Witness{
		Signer: signer, Store: db, Log: log,
		MaxSignDelay:    maxSignDelay,
		RefreshInterval: refreshInterval,
	}

	log.Info("starting", "version", version, "name", cfg.Name, "logs", len(sources),
		"poll", pollInterval.String(), "refresh", refreshInterval.String(), "vkey", vkey)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: (&server.Server{Store: db, VKey: vkey, Version: version}).Handler(),
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

	// Witness once before auditing starts. The auditor works from what we have
	// already attested, so launching it first would spend its opening pass on an
	// empty store and then sleep a full interval before doing anything useful.
	round(ctx, w, sources, log)
	if once {
		return nil
	}

	if auditor != nil && len(resolvers) > 0 {
		// Auditing runs on its own cadence: one verification takes ~24 s and
		// must not stall the witness loop's ability to detect equivocation.
		go func() {
			for {
				for _, r := range resolvers {
					if err := auditor.Run(ctx, r); err != nil && ctx.Err() == nil {
						log.Warn("audit round", "origin", r.Origin(), "err", err)
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(auditInterval):
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return nil
		case <-time.After(pollInterval):
		}
		round(ctx, w, sources, log)
	}
}

func round(ctx context.Context, w *witness.Witness, sources []source.Source, log *slog.Logger) {
	for _, src := range sources {
		roundCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		out, err := w.Process(roundCtx, src)
		cancel()

		switch {
		case err != nil:
			var fe *source.ForkError
			if errors.As(err, &fe) {
				// Already logged and persisted as evidence by the core. This
				// log is now permanently un-cosignable until a human decides
				// otherwise.
				continue
			}
			log.Warn("withheld cosignature", "origin", src.Origin(), "err", err)
		case out.Unchanged:
			log.Debug("unchanged", "origin", out.Origin, "size", out.Size)
		}
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
