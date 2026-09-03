// Package audit implements tier B: replaying a log's own construction proofs
// to attest the tree is correctly built.
//
// Verifying every epoch of Meta's Messenger log costs ~204 GB/day and ~24 s of
// multicore CPU per epoch, so we verify a disclosed random sample instead. That
// is sound because a Key Transparency attack only accomplishes anything if the
// forged binding persists long enough to be served to a victim: detection over
// k consecutive bad epochs is 1-(1-p)^k, so at p=0.1 an attack lasting an hour
// is caught with ~96% probability.
//
// The sample must be unpredictable to the log operator, or they would simply
// misbehave in the epochs we skip. Selection is therefore driven by a public
// randomness beacon whose value is revealed only after the epoch was published,
// and every selection is recorded with the beacon round and signature that
// produced it, so a third party can recompute exactly which epochs we should
// have audited and check that we did.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBeaconURL is drand's quicknet chain: 3-second rounds, unchained, so
// each round's randomness is independent and unpredictable until published.
const DefaultBeaconURL = "https://api.drand.sh/v2/beacons/quicknet/rounds/latest"

// quicknet's chain parameters, from
// https://api.drand.sh/v2/beacons/quicknet/info. Round n is emitted at
// genesis + (n-1)*period, which makes a round number a pure function of a
// timestamp — and that is what lets a sampling decision be pinned rather than
// chosen.
const (
	quicknetGenesis = 1692803367
	quicknetPeriod  = 3
)

// RoundAt returns the first beacon round emitted strictly AFTER t.
//
// This closes a grinding hole. Selection used to use whichever round happened
// to be current when the decision was made, and rounds are three seconds apart,
// so a dishonest witness could simply re-decide until an epoch it wanted to skip
// came up unselected — cheaply, and without leaving a trace.
//
// Pinning the round to a timestamp removes the choice. Given the observation
// time we publish alongside every decision, a third party recomputes exactly
// which round we were required to use, and any other round is visibly wrong.
//
// Strictly after, not at-or-after, because the round must not be predictable
// when the epoch was published: a round emitted at the same instant might
// already have been known.
func RoundAt(t time.Time) uint64 {
	elapsed := t.Unix() - quicknetGenesis
	if elapsed < 0 {
		return 1
	}
	return uint64(elapsed/quicknetPeriod) + 2
}

// Round is one beacon output, retained as evidence of how a sample was chosen.
type Round struct {
	Number    uint64 `json:"round"`
	Signature string `json:"signature"`

	// Randomness is SHA-256 of the signature, which is how quicknet derives it.
	// Recorded so the selection can be recomputed without re-deriving.
	Randomness string `json:"randomness"`
}

type Beacon struct {
	URL    string
	Client *http.Client
}

func NewBeacon(url string) *Beacon {
	if url == "" {
		url = DefaultBeaconURL
	}
	return &Beacon{URL: url, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Latest fetches the most recent beacon round.
//
// Callers must only use a round fetched *after* the epoch under consideration
// was observed. Using an earlier round would let the operator predict the
// selection and cheat in the epochs we skip.
// Round fetches one specific beacon round by number.
//
// This is what makes a sampling decision reproducible: the round is derived
// from a published timestamp rather than from whatever happened to be current,
// so anyone can fetch the same round and recompute the same selection.
func (b *Beacon) Round(ctx context.Context, number uint64) (*Round, error) {
	base := strings.TrimSuffix(b.URL, "/latest")
	return b.fetch(ctx, fmt.Sprintf("%s/%d", base, number))
}

func (b *Beacon) Latest(ctx context.Context) (*Round, error) {
	return b.fetch(ctx, b.URL)
}

func (b *Beacon) fetch(ctx context.Context, url string) (*Round, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("beacon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beacon: HTTP %d", resp.StatusCode)
	}
	var r Round
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return nil, fmt.Errorf("beacon: decode: %w", err)
	}
	if r.Number == 0 || r.Signature == "" {
		return nil, fmt.Errorf("beacon: incomplete round")
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return nil, fmt.Errorf("beacon: signature not hex: %w", err)
	}
	sum := sha256.Sum256(sig)
	r.Randomness = hex.EncodeToString(sum[:])
	return &r, nil
}
