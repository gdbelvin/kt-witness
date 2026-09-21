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

	"github.com/gdbsecurity/kt-witness/internal/pace"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/audit"
	"github.com/gdbsecurity/kt-witness/internal/cosig"
	"github.com/gdbsecurity/kt-witness/internal/export"
	"github.com/gdbsecurity/kt-witness/internal/metrics"
	"github.com/gdbsecurity/kt-witness/internal/netmeter"
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

// Stamped by the linker at image build time; see the Dockerfile.
//
// A version constant alone cannot answer "is the fix I deployed actually
// running?" — it only changes when someone remembers to change it, and every
// build between two releases carries the same string. The commit and the build
// date are what distinguish one running binary from another.
var (
	gitCommit = "unknown"
	buildDate = "unknown"
)

type config struct {
	// Name is our witness identity, and appears in every cosignature line.
	Name string `json:"name"`

	Listen string `json:"listen"`

	// PprofListen serves net/http/pprof on its own socket. Empty disables it.
	//
	// Separate from Listen because the monitoring endpoint is reachable over the
	// tailnet and pprof is not something to publish there: it exposes full
	// goroutine dumps and lets a caller start a thirty-second CPU profile on a
	// process whose CPU is the scarce resource. Leave the port unpublished in
	// compose so it stays reachable from the host and nowhere else.
	PprofListen string `json:"pprof_listen"`
	DB          string `json:"db"`
	KeyFile     string `json:"key_file"`

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

	// FundingPath is the FLOSS/fund manifest served at /funding.json. It is
	// read from disk rather than compiled in, because what this project asks
	// to be paid is the operator's business and not the repository's; see
	// internal/server/funding.go. Empty, or a file that is not there, publishes
	// no manifest and 404s the endpoint.
	FundingPath string `json:"funding_path"`

	// Audit configures tier B: replaying construction proofs for a sampled
	// subset of epochs. Runs whenever a configured log can resolve an epoch.
	// ProtonAudit runs Proton's construction audit inside this process. It
	// retains a ~13.6 GB tree between epochs, which is what makes each step a
	// 3 MB job rather than a 13.6 GB one. Empty dir disables it.
	ProtonAudit struct {
		Dir          string `json:"dir"`
		DumpBase     string `json:"dump_base"`
		ShardDepth   int    `json:"shard_depth"`
		MinFreeBytes uint64 `json:"min_free_bytes"`

		// History bootstraps at the EARLIEST epoch Proton still publishes
		// rather than at the tip, so the replay covers the whole published
		// history instead of only what appeared after we started watching.
		//
		// This is the only way Proton can reach B+. Its construction audit is a
		// stateful forward replay — each epoch is checked by applying a
		// published diff to the previous epoch's tree — so unlike AKD there is
		// no self-contained per-epoch proof and no way to sweep backwards. The
		// only route to full coverage is to start at the bottom and walk up.
		//
		// The cost is real and worth stating: one step is ~19 minutes, so ~500
		// epochs is about six days of continuous disk-bound work, preceded by a
		// one-off ~13.6 GB download. During the replay the TIP is not
		// construction-audited, because there is a single retained tree and it
		// is down in the history. Equivocation detection is unaffected — that
		// is tier A+ witnessing, which runs independently.
		// History ran a second retained tree backwards through the published
		// window. Turned off once the offline GPU backfill finished that work:
		// 498 epochs verified against Proton's signed roots in 12.3 hours,
		// against the ~40 days the same replay would have taken here at two
		// hours an epoch. Leaving it on would have spent sixteen cores redoing
		// audits the witness already holds records for.
		History bool `json:"history"`

		// Dir holds the retained tree for a LOCAL replay. Empty means this
		// witness performs no Proton construction audit itself — the rebuild
		// costs 42 billion hashes and takes about two hours here against sixty
		// seconds on a GPU, so it runs beside the card and the conclusions
		// arrive through ImportResults. Emptying it is what releases the
		// sixteen cores PROTON_TREE_WORKERS reserved.
		//
		// ImportResults names a JSONL file of construction audits performed
		// elsewhere — see internal/audit/import.go. A file rather than an
		// endpoint on purpose: coverage is what this witness publishes, so
		// accepting conclusions over the network would let anything that can
		// reach the port inflate our own claims. A path in the config carries
		// exactly the trust of the config.
		ImportResults string `json:"import_results"`
	} `json:"proton_audit"`

	// Work hands verification out to machines on the operator's own network.
	//
	// Disabled unless BOTH an address and a token are set. Two switches rather
	// than one because each guards a different mistake: an address that is not
	// local refuses to start, and a missing token closes the channel rather
	// than opening it.
	Work struct {
		// ProofListen is where corrupted canary proofs are served, and must be
		// a LAN address for the same reason the work channel must. Empty
		// disables canaries for remote workers, which means a worker that
		// reports the published root without verifying cannot be caught.
		ProofListen string `json:"proof_listen"`
		// ProofHost is what a worker should dial to reach it — the host's LAN
		// address and published port, which is not what the container sees
		// itself bound to.
		ProofHost string `json:"proof_host"`
		// CanaryEvery is how often a proof served to a worker has a bit
		// flipped: 100 corrupts one in a hundred. Zero means that default.
		//
		// Every proof goes through the server, not just these, because a
		// corrupted proof a worker can identify tests nothing.
		CanaryEvery int `json:"canary_every"`

		Listen   string `json:"listen"`
		TokenEnv string `json:"token_env"`
		Lease    string `json:"lease"`
		// Origins workers may be given. Empty means every AKD log, which is
		// the set that benefits: AKD replay is stateless, so any worker can do
		// any epoch. Proton is deliberately not in the default, because its
		// rebuild needs the previous epoch's tree and only the machine holding
		// it can do the work.
		Origins []string `json:"origins"`
	} `json:"work"`

	Audit struct {

		// GoConcurrent bounds in-process verifications. Zero derives it from
		// the machine's cores.
		GoConcurrent int `json:"go_concurrent"`

		// ReserveCores is how many cores to leave free for everything else. The
		// governor's budget is derived from the machine: it drives total usage
		// toward (cores - reserve). Defaults to 1 when pacing is on.
		//
		// Derived rather than stated because a core count is a fact about
		// hardware that changes, and a stale one has already cost this project
		// twice.
		ReserveCores float64 `json:"reserve_cores"`

		// PrefetchDir enables downloading proofs ahead of verification. Empty
		// falls back to each verifier fetching its own, which is slow in a
		// specific way: the download then happens in series with the
		// verification rather than beside it.
		PrefetchDir string `json:"prefetch_dir"`

		// PrefetchBytes caps the on-disk cache. Bytes rather than a count
		// because proof sizes vary by tens of megabytes and disk is what runs
		// out.
		PrefetchBytes int64 `json:"prefetch_bytes"`

		// PrefetchWorkers is how many downloads run at once — this is what
		// saturates the link, and since the generator became the fleet's only
		// downloader it has to cover everybody's appetite, not just this
		// machine's.
		//
		// It was 8, which was right when each verifier also fetched its own
		// proofs: the fleet then had about nineteen connections open and pulled
		// 370-480 Mbit/s. Serving workers from the cache removed their
		// connections and left these eight to do all of it — outbound
		// connections fell to five and throughput fell with them. Concurrency
		// that used to be spread across the fleet has to be declared here
		// instead.
		//
		// Not derivable from cores or memory: what it wants to fill is a link,
		// against CDNs giving about 20-25 Mbit/s per connection, and neither
		// number is visible from inside this process. So it is measured and
		// configured — raise it until throughput stops improving.
		PrefetchWorkers int `json:"prefetch_workers"`

		// DSCPClass marks outbound packets so a shaper can sort this traffic
		// into its bulk queue. 8 is CS1, the de-facto scavenger class and what
		// CAKE's diffserv modes recognise; 1 is RFC 8622 Lower Effort, which is
		// more correct and less widely honoured; 0 does not mark.
		//
		// It does not slow anything down on its own — see internal/netmeter,
		// which explains why the mark cannot reach the CDN sending the bytes.
		// It is what a ROUTER doing ingress shaping keys on, via conntrack
		// carrying the outbound class across to the returning packets. Without
		// it a 284 MB proof and a video call look the same to the one queue
		// that could tell them apart.
		DSCPClass int `json:"dscp_class"`

		// MaxDownloadMbit holds every download this process makes below a rate,
		// in megabits per second, across all logs together. Zero is unlimited,
		// which is what this did before and is right for a machine on a link
		// nobody else is using.
		//
		// It exists because the generator pulls as hard as the CDN will serve,
		// and on a home connection that is the whole link: measured here at
		// 674-899 Mbit/s against a line of about 885, which left a video call
		// on the same connection unusable. Set it below the line rate, not at
		// it — what ruins a call is the ISP's downstream queue filling up, and
		// the queue only stays short if the link is never quite full.
		MaxDownloadMbit float64 `json:"max_download_mbit"`

		// PrefetchMinFreeBytes is free space the cache will not consume,
		// whatever its own cap says. The volume also holds the store and
		// Proton's retained tree, and filling it stops the witness recording
		// what it has attested.
		PrefetchMinFreeBytes uint64 `json:"prefetch_min_free_bytes"`

		// TargetCores optionally overrides the derived budget, for an operator
		// who wants to use less than the machine allows.
		TargetCores float64 `json:"target_cores"`

		// Pace enables CPU pacing of this machine's own verification — it is
		// what the local worker's width is read from. Live auditing is never
		// paced.
		Pace bool `json:"pace_backlog"`

		SampleRate float64 `json:"sample_rate"`
		// Interval is how often the forward pass LOOKS for new epochs — not a
		// throttle. Checking is cheap when the auditor is caught up, and pacing
		// is the governor's job; a long interval only makes work arrive in
		// bursts rather than making less of it.
		Interval          string `json:"interval"`
		Timeout           string `json:"timeout"`
		BeaconURL         string `json:"beacon_url"`
		MaxEpochsPerRound int64  `json:"max_epochs_per_round"`
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
	repairName := flag.Bool("repair-cosigner-name", false, "restate stored cosignatures issued under a former witness name, and exit")
	reason := flag.String("reason", "", "why a fork finding is being withdrawn")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local monitoring endpoint and exit non-zero if it is not serving")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// Notable records are kept in memory as well as written to stderr, so a
	// question about what went wrong can be answered over HTTP instead of
	// needing SSH to the host — which has interrupted four diagnoses in a day.
	events := server.NewEventLog()
	log := slog.New(server.NewEventHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
		events))

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

	if err := run(cfg, log, events, *once, *backfill, *repairName, *retract, *reason); err != nil {
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

func run(cfg *config, log *slog.Logger, events *server.EventLog, once, backfill, repairName bool, retractOrigin, retractReason string) error {
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

	// One-shot, like -retract-fork: a correction to state this witness already
	// published, invoked deliberately rather than applied on every start. It
	// needs nothing but the store and the key, so it runs before any source is
	// built and returns without witnessing anything.
	if repairName {
		n, err := witness.RepairCosignerName(db, signer.Verifier(), log)
		if err != nil {
			return err
		}
		log.Info("cosigner name repair complete", "rewritten", n, "name", cfg.Name)
		return nil
	}

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
	server.Init(version, gitCommit, buildDate)
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
	// Held so the work channel can hand it a verified proof once the queue
	// exists; the verifier is built before the channel it serves.
	var auditInterval time.Duration
	var resolvers []audit.Resolver
	// The CPU governor. Declared out here rather than inside the block that
	// builds it because two things outside that block read it: the work
	// channel, whose local worker sizes itself from it, and the goroutine that
	// runs its control loop.
	//
	// It used to be stashed on the Auditor and fetched back out through a
	// governorFor helper. The audit package never read the field — it was a
	// carrier between two points in this function, wearing the shape of a
	// dependency the auditor did not have.
	var governor *pace.Governor
	// Tier B runs when there is a log that can be audited.
	//
	// The gate used to be a path to a Rust verifier binary, which made
	// construction auditing conditional on an external build being present —
	// so the way to turn off the strongest check this witness performs was to
	// mistype a filename, and nothing would say so. There is no external binary
	// now, and the honest precondition was always this one: a source that can
	// resolve an epoch to its published roots.
	auditable := 0
	for _, src := range sources {
		if _, ok := src.(audit.Resolver); ok {
			auditable++
		}
	}
	if auditable > 0 {
		if auditInterval, err = time.ParseDuration(orDefault(cfg.Audit.Interval, "20s")); err != nil {
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
		// One verifier, in this process.
		//
		// This was a pool of Rust subprocesses, sized from the container's
		// memory limit because each peaked near 3.7 GB — and that cap, not the
		// machine's thirty-two cores, was what bounded this witness for months.
		// A verification here holds the proof and a flat array of its nodes, so
		// the ceiling moved off memory and onto cores, and then onto bandwidth,
		// which is where it belongs: Meta publishes 284 MB per epoch and there
		// is one connection.
		//
		// GoConcurrent overrides; zero derives N-2, the same budget every part
		// of this project uses.
		goVerifier := &audit.GoVerifier{Concurrent: cfg.Audit.GoConcurrent}
		var verifier audit.Verifier = goVerifier
		log.Info("verifying append-only proofs in this process",
			"concurrent", goVerifier.Size(),
			"note", "correctness is checked continuously against the roots each "+
				"operator publishes, on every epoch, rather than by a second implementation")
		defer verifier.Close()
		// Pace the backlog against measured CPU rather than a fixed budget. A
		// constant is wrong the moment the hardware or the proof sizes change:
		// the previous value was chosen when a verification took 94 s on four
		// cores, and after more cores arrived it left five of them idle while
		// the backlog still measured months.
		if cfg.Audit.Pace || cfg.Audit.TargetCores > 0 || cfg.Audit.ReserveCores > 0 {
			// The ceiling has to match whatever is actually verifying.
			//
			// Cores, not a process pool's size.
			//
			// That number existed because a Rust verification peaked near
			// 3.7 GB and memory was the binding constraint. It is not any more:
			// a verification here holds the proof and a flat array of its
			// nodes, so what bounds concurrency is how many cores there are —
			// and leaving the old figure would have held a thirty-two core box
			// at eight.
			maxConcurrent := goVerifier.Size()
			governor = &pace.Governor{
				ReserveCores:  cfg.Audit.ReserveCores,
				TargetCores:   cfg.Audit.TargetCores,
				MaxConcurrent: maxConcurrent,
				Log:           log,
			}
		}
		// Fetch proofs ahead of verifying them so the link and the CPU are busy
		// at once rather than taking turns. Bounded by disk, and every cached
		// proof is released the moment it has been verified.
		var prefetch *audit.Prefetcher
		if d := cfg.Audit.PrefetchDir; d != "" {
			prefetch = &audit.Prefetcher{
				Dir: d,
				// Set HERE, at construction, and not later by whoever uses it.
				//
				// A cache key hashes the origin, so recovering which log a
				// cached file belongs to needs the candidate list — and that
				// happens once, inside init(), on first use. Stats() below is a
				// first use. Setting Origins afterwards was therefore too late:
				// 464 adopted files holding 58 GB went unclassified, the queue
				// saw an empty cache, and the generator could not add to it
				// because by its own accounting the cache was full.
				Origins:      akdOrigins(cfg),
				MaxBytes:     cfg.Audit.PrefetchBytes,
				Workers:      cfg.Audit.PrefetchWorkers,
				MinFreeBytes: cfg.Audit.PrefetchMinFreeBytes,
				Log:          log,
			}
			// Set before any client dials, so the first connection is marked.
			if c := cfg.Audit.DSCPClass; c > 0 {
				netmeter.SetDSCP(c)
				log.Info("outbound traffic marked", "dscp", c,
					"note", "a shaper must act on this; the mark alone slows nothing down")
			}
			metrics.Set(server.MDSCPClass, nil, float64(netmeter.DSCP()))

			// Applied here rather than inside the prefetcher: the cap is a fact
			// about the link, and three different things in this process download
			// over it.
			if mbit := cfg.Audit.MaxDownloadMbit; mbit > 0 {
				netmeter.SetLimit(mbit * 1e6 / 8)
				log.Info("download rate capped", "mbit_per_sec", mbit,
					"note", "set below the line rate; a full link is what ruins a call on the same connection")
			}
			metrics.Set(server.MDownloadLimit, nil, netmeter.Limit())

			files, bytes := prefetch.Stats()
			log.Info("proof prefetch enabled", "dir", d,
				"cap_gb", prefetch.MaxBytes>>30, "adopted_files", files, "adopted_gb", bytes>>30,
				"workers", cfg.Audit.PrefetchWorkers)
			// Published because it decides the download rate and there was no
			// way to confirm from outside that a change to it had taken: the
			// value was measured by raising it and watching for an effect,
			// which is exactly the experiment that cannot distinguish "no
			// effect" from "never deployed".
			metrics.Set(server.MPrefetchWorkers, nil, float64(prefetch.Concurrency()))
		}
		auditor = &audit.Auditor{
			Store: db, Beacon: audit.NewBeacon(cfg.Audit.BeaconURL),
			Verifier: goVerifier, Log: log, Rate: rate, Timeout: auditTimeout,
			MaxEpochsPerRound: maxEpochsPerRound(cfg.Audit.MaxEpochsPerRound),
			Prefetch:          prefetch,
		}
		for _, src := range sources {
			if r, ok := src.(audit.Resolver); ok {
				resolvers = append(resolvers, r)
			}
		}
		log.Info("tier B auditing enabled",
			"sample_rate", rate, "logs", len(resolvers), "interval", auditInterval.String(),
			"concurrent", goVerifier.Size(),
			"machine_cores", runtime.NumCPU(),
			"concurrency_derived", cfg.Audit.GoConcurrent < 1)
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

	// Local replay and importing results are independent now. Proton's audit
	// runs beside the GPU, so this witness keeps no retained tree of its own and
	// Dir is empty — but it still takes in the conclusions, which is where its
	// tier claim comes from.
	if cfg.ProtonAudit.Dir != "" {
		startProtonAudit(ctx, cfg, sources, db, log)
	}
	if p := cfg.ProtonAudit.ImportResults; p != "" {
		for _, src := range sources {
			if src.Origin() == source.OriginProton {
				go runImportLoop(ctx, db, src.Origin(), p, log)
				break
			}
		}
	}
	if len(cfg.PeerStatusURLs) > 0 {
		startPeerPolling(ctx, cfg.PeerStatusURLs, db, log)
	}
	var workers func() map[string]time.Time
	if cfg.Work.Listen != "" {
		// The work channel needs what the sweep needs: something that can turn
		// an epoch into the roots the operator published, and the one pool that
		// bounds concurrent replays. Passing them rather than letting the local
		// worker build its own is what keeps the memory bound a single number.
		var (
			wVerifier  audit.Verifier
			wPrefetch  *audit.Prefetcher
			wResolvers []audit.Resolver
			wTimeout   = 5 * time.Minute
		)
		if auditor != nil {
			wVerifier, wResolvers = auditor.Verifier, resolvers
			// The same cache the sweep uses. One cache, because it is one disk
			// and one link, and two would compete for both while each believed
			// it was within its budget.
			wPrefetch = auditor.Prefetch
			if auditor.Timeout > 0 {
				wTimeout = auditor.Timeout
			}
		}
		w, err := startWorkChannel(ctx, cfg, db, governor, wVerifier, wPrefetch, wResolvers, wTimeout, log)
		if err != nil {
			// Refusing to start is the point. A work channel that silently did
			// not come up would leave the witness looking healthy while the
			// machines meant to be helping it sat idle.
			log.Error("work channel", "err", err)
			os.Exit(1)
		}
		workers = w
	}
	defer stop()

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&server.Server{Store: db, VKey: vkey, Version: version, Commit: gitCommit, Built: buildDate, Workers: workers, Log: log, Tiers: tiers, Kinds: kinds,
			Events:      events,
			Storage:     server.StoragePaths{DBPath: cfg.DB, ExportDir: cfg.ExportDir},
			FundingPath: cfg.FundingPath}).Handler(),
	}
	startPprof(ctx, cfg.PprofListen, log)
	startUnblockProbe(ctx, log)

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

	// Resource facts on their own cadence: cgroup pressure, container and
	// machine memory, goroutines. All of it was read by hand over SSH this week.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			server.RefreshRuntimeMetrics()
			proton.ReportProgress()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	if auditor != nil && auditor.Prefetch != nil {
		// The cache occupancy is what distinguishes a CPU-bound pipeline from a
		// bandwidth-bound one, so it is sampled on its own cadence rather than
		// only when something happens to touch the cache.
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for {
				// Prune before reporting, so the number published is the one
				// after enforcement rather than before it.
				//
				// Prune existed, was documented for exactly this case, and was
				// called from nowhere — so the cap was advisory: Fetch declined
				// to ADD past it, but nothing ever removed the excess. Proofs
				// for epochs the sweep had moved past were never released and
				// never evicted, and the cache sat 5.9 GB over its limit on a
				// volume shared with the database and Proton's retained trees.
				auditor.Prefetch.Prune()
				auditor.Prefetch.ReportMetrics()
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	if governor != nil {
		go governor.Run(ctx)
		log.Info("local verification paced against CPU",
			"cores_detected", runtime.NumCPU(),
			"budget_cores", governor.BudgetFor(float64(runtime.NumCPU())),
			"reserve_cores", cfg.Audit.ReserveCores,
			"max_concurrent", governor.MaxConcurrent,
			"note", "live auditing is never paced")
	}

	if auditor != nil && len(resolvers) > 0 {
		// Auditing runs on its own cadence: one verification takes ~24 s and
		// must not stall the witness loop's ability to detect equivocation.
		go func() {
			for {
				// Audits across ecosystems are independent and dominated by
				// download time, so they overlap. Verification itself is the
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

		// The backwards sweep that used to live here is gone, and so is the
		// hole-repair pass beside it.
		//
		// Both were the witness auditing history by itself: one cursor walking
		// down, verifying inline, on the same download budget the work generator
		// needs. The generator plus the queue now do the same job better in the
		// two ways that were the sweep's standing defects.
		//
		// The sweep's cursor only ever walked down, so an epoch it could not
		// fetch was behind it forever and every transient CDN refusal became a
		// permanent hole — which is the entire reason repair.go existed. The
		// generator's backward cursor WRAPS: at the bottom it restarts from the
		// forward pass's floor, and it selects with FirstUnverified, so an epoch
		// recorded unverified is offered again on the next descent. Holes heal as
		// an ordinary consequence of the descent instead of needing a second pass
		// with its own backoff table.
		//
		// And the sweep verified on this box. The queue hands the same epochs to
		// whoever has capacity, which after the pool fix is this box at full
		// width plus every borrowed machine.
		//
		// Coverage does not depend on either of them and never did: the server
		// computes it by scanning audit records in the store, and a worker's
		// result is recorded with the same shape the sweep wrote.
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
		// Extend the range we already verified, rather than re-walking it.
		//
		// A full listing is ~500 paginated requests to somebody else's CDN, and
		// doing that hourly to learn about a hundred new epochs spends most of a
		// scan rediscovering verified history. Extension costs a few requests per
		// new epoch. A full walk still happens periodically, because only that
		// re-reads old objects — and an operator rewriting history would rewrite
		// the part nobody looks at twice.
		var (
			res *source.BackfillResult
			err error
		)
		// Ask before announcing. A source that knows it has nothing to walk is
		// skipped silently rather than logging a start with no finish.
		if probe, ok := src.(source.BackfillProbe); ok && !probe.BackfillApplicable() {
			continue
		}

		inc, canExtend := src.(source.IncrementalBackfiller)
		prior := storedHistory(db, src.Origin())
		full := prior == nil || !canExtend || time.Since(prior.VerifiedAt) > fullBackfillEvery

		start := time.Now()
		if full {
			log.Info("backfill starting", "origin", src.Origin(), "mode", "full walk")
			res, err = b.Backfill(ctx, log)
		} else {
			log.Info("backfill starting", "origin", src.Origin(),
				"mode", "extend", "from", prior.To)
			res, err = inc.BackfillFrom(ctx, log, prior.To)
			if err == nil && res != nil {
				// The extension only covers the new tail; the recorded range is
				// the union with what was already verified.
				res.From = prior.From
				res.Epochs += prior.Epochs - 1
				res.Gaps = append(prior.Gaps, res.Gaps...)
			}
		}
		if errors.Is(err, source.ErrNotBackfillable) {
			// Nothing to walk in this configuration. Skipped before it is
			// announced, so the log does not carry a start line with no finish.
			continue
		}
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
	// Same reasoning for entry logs that carry key material. thelemail.com/keys
	// is a plain tlog read by the c2sp adapter, so type alone would classify it
	// "generic" — and it is the only log here at B+, so the one ecosystem this
	// project exists for would have had its best result filed under "Other".
	// Grouping the page by ecosystem is what surfaced that; a flat list had
	// hidden it for weeks.
	if strings.HasSuffix(l.Origin, "/keys") {
		return "kt"
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
		Dir: cfg.ProtonAudit.Dir, APIBase: api, DumpBase: dumps, Replay: "tip",
		ShardDepth: cfg.ProtonAudit.ShardDepth, MinFreeBytes: cfg.ProtonAudit.MinFreeBytes,
	}

	// The tip replay: follows Proton forward as it publishes.
	go runProtonLoop(ctx, a, db, origin, false, "tip", log)

	// The history replay, on its own retained tree.
	//
	// Two trees rather than one, because the alternative is a false choice. The
	// audit is a stateful forward replay, so a single tree can be either at the
	// tip or down in the history, never both — and moving the existing tree to
	// the bottom would surrender construction coverage of the tip for the six
	// days the replay takes. Tip coverage is the more perishable of the two: an
	// operator misbehaving today is a live incident, while an unaudited epoch
	// from last month will still be there next week.
	//
	// The second tree costs ~27 GB at peak against 626 GB free, and the two
	// converge: once the history replay reaches the tip the ranges meet and one
	// of them becomes redundant.
	if cfg.ProtonAudit.History {
		h := &proton.IncrementalAuditor{
			Dir: cfg.ProtonAudit.Dir + "-history", APIBase: api, DumpBase: dumps,
			Replay:     "history",
			ShardDepth: cfg.ProtonAudit.ShardDepth, MinFreeBytes: cfg.ProtonAudit.MinFreeBytes,
		}
		go runProtonLoop(ctx, h, db, origin, true, "history", log)
	}

}

// runImportLoop ingests an offline backfill's results as they appear.
func runImportLoop(ctx context.Context, db *store.Store, origin, path string, log *slog.Logger) {
	log = log.With("import", path, "origin", origin)
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		st, err := audit.ImportResults(db, origin, path, log)
		switch {
		case os.IsNotExist(err):
			// Not an error worth shouting about: the file appears when a run
			// has produced something.
			log.Debug("no imported results yet")
		case err != nil:
			log.Warn("importing offline audits", "err", err)
		case st.Imported > 0 || st.Rejected > 0 || st.Failures > 0:
			log.Info("imported offline construction audits",
				"read", st.Read, "imported", st.Imported, "skipped", st.Skipped,
				"rejected", st.Rejected, "failed_audits", st.Failures,
				"gpu_disagreements", st.Mismatch, "through_epoch", st.LastEpoch)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runProtonLoop steps one retained tree forward for as long as there is ground
// to make up.
//
// This used to run exactly one step per thirty-minute tick, which is fine at
// the tip — Proton publishes every four hours — and hopeless for a backlog:
// replaying five hundred epochs one per tick would add ten days of idle waiting
// on top of the six days of actual work. When there is a backlog the right
// cadence is "immediately".
func runProtonLoop(ctx context.Context, a *proton.IncrementalAuditor, db *store.Store,
	origin string, history bool, mode string, log *slog.Logger) {

	log = log.With("proton_replay", mode)
	for {
		stepped := runProtonStep(ctx, a, db, origin, history, log)
		if ctx.Err() != nil {
			return
		}
		if stepped {
			continue // more to do; do not wait
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

// runProtonStep advances the retained tree by at most one epoch. It reports
// whether it did work, so the caller knows whether to come straight back.
func runProtonStep(ctx context.Context, a *proton.IncrementalAuditor, db *store.Store,
	origin string, history bool, log *slog.Logger) bool {

	base, err := a.Base()
	if err != nil {
		log.Warn("proton audit: reading retained tree", "err", err)
		return false
	}
	rec, err := db.Get(origin)
	if err != nil || rec == nil {
		return false // nothing witnessed yet
	}
	tip := rec.Size

	if base == 0 {
		// Cold start: ~13.6 GB, once. Everything about this design exists to
		// avoid needing it again.
		//
		// Where we start decides what can ever be claimed. Bootstrapping at the
		// tip means the replay only ever covers epochs published after we
		// showed up, so "tier B" for Proton means "since we arrived" and B+ is
		// unreachable by construction — which is exactly where this sat, at 11
		// epochs of a 501-epoch published history. Starting at the earliest
		// epoch Proton still publishes is the only way the whole history gets
		// checked, because the audit is a forward replay and cannot sweep back.
		start := tip
		if history {
			if from, ok := earliestProtonEpoch(db, origin); ok {
				start = from
			}
		}
		log.Info("proton audit: bootstrapping retained tree — this is a one-off "+
			"~13.6 GB download", "epoch", start, "mode", protonMode(history),
			"tip", tip)
		if err := a.Bootstrap(ctx, start); err != nil {
			log.Warn("proton audit: bootstrap", "epoch", start, "err", err)
			return false
		}
		return true
	}
	if base >= tip {
		return false // already caught up
	}

	next := base + 1
	meta, err := a.FetchEpochMeta(ctx, next)
	if err != nil {
		log.Warn("proton audit: epoch metadata", "epoch", next, "err", err)
		return false
	}

	res, err := a.Step(ctx, base, next, meta)
	if err != nil {
		var mm *proton.MismatchError
		if errors.As(err, &mm) {
			// The retained tree plus the published diff does not rebuild the
			// root Proton signed. Conclusive, and the evidence is on disk —
			// but reported rather than used to poison the log here, because
			// the witness core owns that decision and a human should see it.
			log.Error("PROTON CONSTRUCTION AUDIT FAILED — the published diff does not "+
				"carry one epoch into the next; evidence retained on disk",
				"from", base, "to", next, "err", err)
			return false
		}
		var pending *proton.NotYetPublishedError
		if errors.As(err, &pending) {
			// Caught up: the diff for this epoch is not out yet. Nothing is
			// wrong, so nothing is said above debug — a warning on every pass
			// at the tip is how warnings stop being read.
			log.Debug("proton audit: waiting for the next diff", "epoch", next)
			return false
		}
		// Everything else means we could not check: a refused download, a
		// truncated body, no disk. None of that is evidence about how Proton
		// built its tree, and saying so at ERROR would accuse an operator of
		// misbehaviour on the strength of our own failure to fetch.
		log.Warn("proton audit: could not verify this epoch; withholding judgement, not accusing",
			"from", base, "to", next, "err", err)
		return false
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
		// Counted like every other verification. A counter that omits one
		// ecosystem's work makes its rate read as zero while it is running.
		lbl := map[string]string{"origin": origin}
		metrics.Inc(server.MAuditVerified, lbl)
		metrics.Add(server.MAuditBytes, lbl, float64(res.Stats.Added+res.Stats.Removed))
	}

	if res.Removals != nil && !res.Removals.Clean() {
		log.Error("PROTON REMOVALS NOT EXPLAINED BY THE RETENTION WINDOW — "+
			"withholding judgement, not accusing; the window rule is inferred "+
			"from behaviour rather than promised",
			"epoch", res.To, "summary", res.Removals.Summary())
	}
	return true
}

// earliestProtonEpoch is the bottom of Proton's published history, as
// established by backfill.
//
// Reported rather than assumed: Proton retains a moving window, so the earliest
// epoch is whatever it currently serves, not a constant.
func earliestProtonEpoch(db *store.Store, origin string) (int64, bool) {
	hs, err := db.Histories()
	if err != nil {
		return 0, false
	}
	for _, h := range hs {
		if h.Origin == origin && h.From > 0 {
			return h.From, true
		}
	}
	return 0, false
}

func protonMode(history bool) string {
	if history {
		return "history (whole published range)"
	}
	return "tip only (epochs published from now on)"
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
// A timer rather than something driven by CPU, and deliberately so. Backfill is
// network work against somebody else's CDN — roughly 500 paginated listing
// requests, almost all of it spent waiting — so pacing it by our own idleness
// would mean hammering Meta hardest whenever this box had nothing to do. That
// is the distinction in docs/design.md: waits that exist because of another
// party's server stay timers.
//
// Nor can it be made incremental, which would otherwise be the answer. Object
// keys sort lexicographically rather than numerically ("99999" > "624700"), so
// there is no start-after meaning "epochs above N"; finding new ones means
// listing all of them.
//
// An hour rather than the six it used to be. The cost is about two minutes of
// listing, which is nothing; the consequence of waiting is that the coverage
// denominator lags the tip, and audits landing above the recorded range are
// real work that no metric counts. At six hours WhatsApp drifted past its own
// recorded history by seven hundred epochs.
const backfillRefresh = time.Hour

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

// storedHistory returns what we have already verified for an origin, or nil.
func storedHistory(db *store.Store, origin string) *store.History {
	hs, err := db.Histories()
	if err != nil {
		return nil
	}
	for _, h := range hs {
		if h.Origin == origin {
			return h
		}
	}
	return nil
}

// fullBackfillEvery is how often published history is re-walked in full rather
// than extended.
//
// Extension checks the new tail and trusts what an earlier pass verified. That
// is sound against an append-only operator and blind to one that goes back and
// rewrites an object nobody re-reads — which is exactly where a rewrite would
// be put. A daily full walk closes that, at two minutes of listing.
const fullBackfillEvery = 24 * time.Hour

func canaryEvery(n int) int {
	if n <= 0 {
		return 100
	}
	return n
}
