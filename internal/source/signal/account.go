package signal

// Monitoring one real account alongside the distinguished entry.
//
// # What this buys, stated honestly
//
// Signal's proofs are per-label. They answer questions about identifiers the
// asker can already name, and the VRF exists precisely so a third party cannot
// enumerate the rest. Adding an account therefore moves coverage from one label
// to two, out of a directory of hundreds of millions.
//
// It does NOT raise the tier, and it is not a step towards raising it. What it
// buys is a second, independent exercise of the whole verification path — VRF,
// prefix tree, batch inclusion, commitment opening — against a different index
// in the tree. The distinguished entry is one Signal has every incentive to keep
// well-formed because every client checks it; an ordinary account is not
// special, so a proof that verifies for it is evidence the machinery works
// generally rather than for the one label everybody looks at.
//
// # Why a failure here does not withhold the cosignature
//
// The distinction matters and is deliberate:
//
//   - A TRANSPORT failure — rate limit, timeout, HTTP 5xx — is evidence of
//     nothing. The account search is an extra, obtained from a courtesy
//     endpoint, and letting it gate the witness would mean Signal could stop us
//     attesting by rate-limiting us. It is logged and the round continues.
//
//   - A CRYPTOGRAPHIC contradiction — a proof that verifies to a root other
//     than the one the signed tree head and the auditors agree on — is the same
//     class of evidence as the distinguished check, and it withholds.
//
// # The identifier is never published
//
// An ACI is a stable identifier for a real person. It is used to build the
// search key and is never written to logs, exported state, or the audit trail;
// AccountLabel is what appears instead.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Search-key prefixes, from libsignal's rust/net/chat/src/api/keytrans.rs:
//
//	const SEARCH_KEY_PREFIX_ACI: &[u8] = b"a";
//	const SEARCH_KEY_PREFIX_E164: &[u8] = b"n";
//	const SEARCH_KEY_PREFIX_USERNAME_HASH: &[u8] = b"u";
//
// The bytes are fed to the VRF unmodified, so this construction has to be exact.
const searchKeyPrefixACI = 'a'

// ACISearchKey builds the search key for an ACI: the prefix byte followed by
// the 16 raw UUID bytes.
//
// Note what is NOT here. libsignal's Aci branch calls service_id_binary(),
// which for an ACI returns the bare 16 bytes and deliberately omits the
// ServiceId kind byte that the fixed-width form would prepend. Including it
// would produce a 18-byte key that fails at the VRF with no useful diagnostic,
// so the omission is the load-bearing detail.
func ACISearchKey(aci string) ([]byte, error) {
	raw, err := parseUUID(aci)
	if err != nil {
		return nil, err
	}
	return append([]byte{searchKeyPrefixACI}, raw...), nil
}

// parseUUID accepts the hyphenated form and returns 16 bytes.
func parseUUID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("signal: %q is not a UUID", redactACI(s))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("signal: %q is not a UUID: %w", redactACI(s), err)
	}
	return b, nil
}

// searchKeyName renders a search key for logs.
//
// The distinguished key is printable and safe. Anything else is an identifier
// for a person, so it is named by shape rather than value — a log line is the
// easiest place for an identifier to escape into a bug report.
func searchKeyName(k []byte) string {
	if bytes.Equal(k, DistinguishedKey) {
		return string(DistinguishedKey)
	}
	if len(k) > 0 && k[0] == searchKeyPrefixACI {
		return "aci(redacted)"
	}
	return fmt.Sprintf("key(%d bytes)", len(k))
}

// redactACI renders an ACI as a short, stable, non-reversing tag.
//
// Enough to correlate two log lines about the same account; not enough to learn
// who it is. This is what goes anywhere the raw value must not.
func redactACI(aci string) string {
	if aci == "" {
		return "unset"
	}
	sum := sha256.Sum256([]byte(aci))
	return "aci:" + hex.EncodeToString(sum[:4])
}

// AccountLabel is the published stand-in for the monitored account.
//
// Published output names this, never the ACI. It is a hash, so two runs agree
// and an observer can confirm we kept monitoring the same account without ever
// learning which one.
func (s *Source) AccountLabel() string {
	if s.cfg.AccountACI == "" {
		return ""
	}
	return redactACI(s.cfg.AccountACI)
}

// accountEnabled reports whether both halves of the account material are set.
//
// Both are required: the ACI names the entry and the identity key is what the
// tree's commitment is over, so the opening cannot be checked without it. Half
// the configuration is a misconfiguration, and it is better to say so than to
// quietly monitor nothing.
func (s *Source) accountEnabled() bool {
	return s.cfg.AccountACI != "" && s.cfg.AccountIdentityKey != ""
}

// searchAccount searches for the configured account and verifies the proof.
//
// It returns a *source.ForkError-worthy contradiction only via err; callers
// distinguish the two cases with accountFatal.
func (s *Source) searchAccount(ctx context.Context, treeSize uint64) (*SearchResult, error) {
	key, err := ACISearchKey(s.cfg.AccountACI)
	if err != nil {
		return nil, err
	}
	raw, err := s.searchAccountRaw(ctx, treeSize)
	if err != nil {
		return nil, err
	}
	return s.verifyAccountResponse(raw, key)
}

// searchAccountRaw performs the request and returns the response protobuf.
//
// Split from verification so that a test can verify a genuine response against
// a deliberately wrong search key. That negative control cannot be built by
// asking for a different account: Signal answers HTTP 403 for an ACI that is
// not the caller's, so the proof machinery is never reached and such a test
// would only be checking Signal's authorisation rather than our verification.
func (s *Source) searchAccountRaw(ctx context.Context, treeSize uint64) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"aci":                       s.cfg.AccountACI,
		"aciIdentityKey":            s.cfg.AccountIdentityKey,
		"lastTreeHeadSize":          treeSize,
		"distinguishedTreeHeadSize": treeSize,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.Endpoint+"/v1/key-transparency/search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &transportError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Rate limiting in particular is expected: this is a courtesy endpoint
		// and we are a continuous poller.
		return nil, &transportError{fmt.Errorf("search: HTTP %d", resp.StatusCode)}
	}

	var out struct {
		SerializedResponse string `json:"serializedResponse"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, &transportError{err}
	}
	raw, err := decodeStdOrRaw(out.SerializedResponse)
	if err != nil {
		return nil, &transportError{err}
	}
	return raw, nil
}

// verifyAccountResponse runs the full check over a search response.
func (s *Source) verifyAccountResponse(raw, key []byte) (*SearchResult, error) {
	// The full three-way check, with the account's key as the one the response's
	// search proof is expected to be about. This re-verifies the tree head and
	// the auditors from scratch rather than trusting the head fetched moments
	// ago: the response is its own document, and checking it against itself is
	// what makes a contradiction here meaningful.
	size, root, _, err := s.verifyResponseFor(raw, key)
	if err != nil {
		return nil, err
	}

	condensed := first(parse(raw), 2)
	if condensed == nil {
		return nil, fmt.Errorf("signal: account search response carries no proof")
	}
	res, err := verifySearch(s.vrfPub, key, nil, parse(condensed), size)
	if err != nil {
		return nil, err
	}
	if res.Root != root {
		return nil, fmt.Errorf(
			"signal: account search proof implies root %x, but the signed tree head at "+
				"size %d says %x", res.Root[:8], size, root[:8])
	}
	return res, nil
}

// decodeStdOrRaw accepts both padded and unpadded base64.
//
// Signal serves standard base64 today. Accepting the unpadded form too costs
// nothing and avoids a witness that stops working over a padding change.
func decodeStdOrRaw(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("signal: response is not base64")
	}
	return b, nil
}

// transportError marks a failure that is evidence of nothing, so that the
// caller can continue rather than withhold. The distinction is the whole point
// of the type.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// accountFatal reports whether an account-search error should withhold the
// cosignature.
//
// Only a cryptographic contradiction should. Everything else — the endpoint
// being unreachable, rate limited, or slow — must not, or Signal could silence
// this witness by throttling it.
func accountFatal(err error) bool {
	if err == nil {
		return false
	}
	var te *transportError
	return !asTransport(err, &te)
}

func asTransport(err error, target **transportError) bool {
	for err != nil {
		if te, ok := err.(*transportError); ok {
			*target = te
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// maybeSearchAccount runs the account search when one is configured and the
// interval has elapsed.
//
// Rate limiting is why this is time-gated rather than run every round: the
// witness polls once a minute, and the endpoint is a courtesy. A witness that
// hammers it earns a block, and a blocked witness monitors nothing.
func (s *Source) maybeSearchAccount(ctx context.Context, treeSize uint64) error {
	if !s.accountEnabled() {
		return nil
	}
	interval := s.cfg.AccountInterval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if !s.lastAccountAt.IsZero() && time.Since(s.lastAccountAt) < interval {
		return nil
	}
	s.lastAccountAt = time.Now()

	res, err := s.searchAccount(ctx, treeSize)
	if err != nil {
		if accountFatal(err) {
			return fmt.Errorf("signal: monitored account %s: %w", s.AccountLabel(), err)
		}
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("signal account search unavailable; not a finding",
				"account", s.AccountLabel(), "err", err)
		}
		return nil
	}
	s.lastAccountSearch = res
	if s.cfg.Log != nil {
		s.cfg.Log.Info("signal account proof verified",
			"account", s.AccountLabel(),
			"index", hex.EncodeToString(res.Index[:8]),
			"first_position", res.Pos, "version", res.Version,
			"entries_opened", res.Entries)
	}
	return nil
}

// LastAccountSearch returns the most recent verified account proof, or nil.
func (s *Source) LastAccountSearch() *SearchResult { return s.lastAccountSearch }
