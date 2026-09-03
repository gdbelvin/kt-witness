package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source/akd"
	"github.com/gdbsecurity/kt-witness/internal/source/signal"
)

// Fetcher captures new artifacts into the corpus.
//
// Every capture is verified before it is admitted, using the same replay path a
// later -verify run will use. An unverified artifact would be worse than no
// artifact: its manifest would record an expectation nothing ever produced, so
// every future replay would compare the code against itself and pass
// regardless.
type Fetcher struct {
	corpus   *Corpus
	replayer *Replayer
	client   *http.Client
	out      io.Writer
}

func NewFetcher(c *Corpus, r *Replayer, out io.Writer) *Fetcher {
	return &Fetcher{
		corpus:   c,
		replayer: r,
		client: &http.Client{
			Timeout:   30 * time.Minute,
			Transport: &http.Transport{TLSClientConfig: captureTLS()},
		},
		out: out,
	}
}

// signalRootCer is Signal's own CA, a copy of the certificate
// internal/source/signal pins.
//
// Signal's chat host does not present a publicly trusted certificate, so a
// client using only the system pool cannot reach it at all. The witness handles
// that by embedding the CA in the source adapter, where it is unexported; this
// is the same file, copied rather than imported because the corpus tool is not
// permitted to widen that package's API, and a plain copy is preferable to
// turning verification off. It is a public certificate, and if it is ever
// replaced the symptom is a capture that fails loudly rather than one that
// silently trusts anybody.
//
//go:embed signal-root.cer
var signalRootCer []byte

// captureTLS builds the transport configuration for capturing, trusting the
// system pool plus Signal's CA. Note that the capture's TLS is not what makes an
// artifact trustworthy — nothing is admitted to the corpus until it has verified
// under Signal's pinned Ed25519 service and auditor keys, which no interposed
// party can forge. TLS is here so the connection succeeds at all, and because
// there is no reason to accept less than the production client does.
func captureTLS() *tls.Config {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cert, err := x509.ParseCertificate(signalRootCer); err == nil {
		pool.AddCert(cert)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func (f *Fetcher) logf(format string, args ...any) {
	fmt.Fprintf(f.out, format+"\n", args...)
}

// diverseEpochs picks which epochs to capture for an AKD log.
//
// Spread beats volume. A contiguous run of epochs from one afternoon exercises
// the verifier with nearly identical trees; the same number of epochs spread
// across the log's history covers different tree sizes, different node
// distributions and, over time, different versions of the provider's own
// publishing code. So the selection walks back from the tip in doubling steps —
// tip, tip-1, tip-2, tip-4, tip-8 … — which is deterministic, needs no state,
// and gives dense coverage of recent behaviour with a long tail into history.
func diverseEpochs(tip int64, n int, floor int64) []int64 {
	var out []int64
	step := int64(0)
	e := tip
	for len(out) < n && e > floor {
		out = append(out, e)
		if step == 0 {
			step = 1
		} else {
			step *= 2
		}
		e = tip - step
	}
	return out
}

// FetchAKD captures up to n epochs of one AKD log.
func (f *Fetcher) FetchAKD(ctx context.Context, cfg akd.Config, n int) error {
	src, err := akd.New(cfg)
	if err != nil {
		return err
	}
	head, err := src.Fetch(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: locate tip: %w", cfg.Origin, err)
	}
	f.logf("%s: tip is epoch %d", cfg.Origin, head.Size)

	for _, epoch := range diverseEpochs(head.Size, n, 1) {
		if f.corpus.Has(KindAKD, cfg.Origin, epoch) {
			f.logf("%s: epoch %d already stored", cfg.Origin, epoch)
			continue
		}
		if err := f.fetchAKDEpoch(ctx, src, cfg, epoch); err != nil {
			// A limit reached is the run's normal end, not a failure. Anything
			// else is one artifact we could not take, and — following the
			// project's governing rule — an artifact we could not fetch is
			// evidence of nothing, so the run continues to the next epoch.
			if isLimit(err) {
				return err
			}
			f.logf("%s: epoch %d skipped: %v", cfg.Origin, epoch, err)
			continue
		}
	}
	return nil
}

func (f *Fetcher) fetchAKDEpoch(ctx context.Context, src *akd.Source, cfg akd.Config, epoch int64) error {
	// The roots come from the object key that the log itself published, which
	// is what makes the recorded expectation meaningful: it is the provider's
	// claim, not our derivation.
	ref, err := src.ResolveEpoch(ctx, epoch)
	if err != nil {
		return err
	}

	key := path.Join(fmt.Sprint(epoch), ref.PrevRoot, ref.CurrRoot)
	url := ref.LogDirectory + "/" + key

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	// Content-Length is a claim, so it is used only to refuse obviously
	// unaffordable downloads early. The real enforcement is the budget passed to
	// writeBlob, which stops mid-stream.
	if cl := resp.ContentLength; cl > 0 {
		if err := f.corpus.CheckBudget(cl); err != nil {
			return err
		}
	} else if err := f.corpus.CheckBudget(0); err != nil {
		return err
	}
	budget, err := f.corpus.Remaining()
	if err != nil {
		return err
	}

	dst := filepath.Join(f.corpus.blobDir(KindAKD, cfg.Origin), filepath.FromSlash(key))
	n, sum, err := f.corpus.writeBlob(dst, resp.Body, budget)
	if err != nil {
		return err
	}

	m := &Manifest{
		Kind:       KindAKD,
		Origin:     cfg.Origin,
		Seq:        epoch,
		Blob:       path.Join(string(KindAKD), slug(cfg.Origin), "blobs", key),
		Bytes:      n,
		SHA256:     sum,
		PrevRoot:   ref.PrevRoot,
		CurrRoot:   ref.CurrRoot,
		CapturedAt: time.Now().UTC(),
	}

	if err := f.replayer.Replay(ctx, m); err != nil {
		os.Remove(dst)
		return fmt.Errorf("captured epoch %d did not verify, discarded: %w", epoch, err)
	}
	if err := f.corpus.save(m); err != nil {
		return err
	}
	f.logf("%s: epoch %d captured and verified (%s)", cfg.Origin, epoch, human(n))
	return nil
}

// FetchSignal captures n Signal responses.
//
// These are the highest value per byte in the corpus by a wide margin: 490 KB
// buys the VRF, the prefix tree, a batch inclusion proof and a commitment
// opening, which is the newest and least settled code in the project. interval
// spaces the captures out, because two responses taken a second apart describe
// the same tree and test the same shapes.
func (f *Fetcher) FetchSignal(ctx context.Context, origin, endpoint string, n int, interval time.Duration) error {
	for i := 0; i < n; i++ {
		if i > 0 && interval > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
		if err := f.fetchSignalOnce(ctx, origin, endpoint); err != nil {
			if isLimit(err) {
				return err
			}
			f.logf("%s: capture skipped: %v", origin, err)
		}
	}
	return nil
}

func (f *Fetcher) fetchSignalOnce(ctx context.Context, origin, endpoint string) error {
	if err := f.corpus.CheckBudget(1 << 20); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+signalPath, nil)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", endpoint+signalPath, resp.StatusCode)
	}

	budget, err := f.corpus.Remaining()
	if err != nil {
		return err
	}

	// The tree size is only known once the response verifies, and the artifact
	// is named after it, so it lands under a provisional name first.
	tmp := filepath.Join(f.corpus.blobDir(KindSignal, origin), fmt.Sprintf("capture-%d.json", time.Now().UnixNano()))
	n, sum, err := f.corpus.writeBlob(tmp, resp.Body, budget)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // removed unless it is renamed into place below

	size, root, err := f.verifySignalCapture(ctx, origin, tmp)
	if err != nil {
		return fmt.Errorf("capture did not verify, discarded: %w", err)
	}
	if f.corpus.Has(KindSignal, origin, size) {
		f.logf("%s: tree size %d already stored", origin, size)
		return nil
	}

	final := filepath.Join(f.corpus.blobDir(KindSignal, origin), fmt.Sprintf("%d.json", size))
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	m := &Manifest{
		Kind:       KindSignal,
		Origin:     origin,
		Seq:        size,
		Blob:       path.Join(string(KindSignal), slug(origin), "blobs", fmt.Sprintf("%d.json", size)),
		Bytes:      n,
		SHA256:     sum,
		Root:       root,
		CapturedAt: time.Now().UTC(),
	}
	if err := f.corpus.save(m); err != nil {
		return err
	}
	f.logf("%s: tree size %d captured and verified (%s)", origin, size, human(n))
	return nil
}

// verifySignalCapture runs a freshly captured response through the production
// verifier and reports what it verified to, which becomes the manifest's
// expectation.
func (f *Fetcher) verifySignalCapture(ctx context.Context, origin, blob string) (int64, string, error) {
	f.replayer.server.setSignalBlob(blob)
	src, err := signal.New(signal.Config{Origin: origin, Endpoint: f.replayer.server.URL()})
	if err != nil {
		return 0, "", err
	}
	head, err := src.Fetch(ctx, nil)
	if err != nil {
		return 0, "", err
	}
	if s := src.LastSearch(); s == nil {
		return 0, "", fmt.Errorf("response carried no search proof")
	}
	return head.Size, hex.EncodeToString(head.Hash[:]), nil
}

// isLimit reports whether an error is one of the two safety limits, which end a
// fetch run cleanly rather than being logged and stepped over.
func isLimit(err error) bool {
	return errors.Is(err, ErrCapReached) || errors.Is(err, ErrFloorReached)
}

// witnessConfig is the sliver of deploy/witness.json this tool needs. It is
// parsed here rather than imported from cmd/kt-witness so that the corpus tool
// stays a reader of the deployment's configuration and never a second place
// where log identities are defined.
type witnessConfig struct {
	Logs []struct {
		Type              string `json:"type"`
		Origin            string `json:"origin"`
		LogDirectory      string `json:"log_directory"`
		PlexiNamespaceURL string `json:"plexi_namespace_url"`
		Endpoint          string `json:"endpoint"`
	} `json:"logs"`
}

func loadWitnessConfig(p string) (*witnessConfig, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c witnessConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("corpus: %s: %w", p, err)
	}
	return &c, nil
}
