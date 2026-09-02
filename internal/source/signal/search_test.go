package signal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

// The offline tests below use libsignal's own test vectors, so they check this
// reimplementation against the reference rather than against itself. The live
// test then checks the whole chain end to end against production.

// Vectors from libsignal rust/keytrans/src/commitments.rs.
func TestCommitmentVectors(t *testing.T) {
	var nonce [16]byte
	for _, tc := range []struct {
		key, data, want string
	}{
		{"", "", "edc3f59798cd87f2f48ec8836e2b6ef425cde9ab121ffdefc93d769db7cebabf"},
		{"foo", "bar", "25df431e884358826fe66f96d65702580104240abd63fa741d9ea3f32914bbf5"},
		{"foo1", "bar", "6c31a163a7660d1467fc1c997bd78b0a70b8921ca76b7eb0c6ca077f1e5e121e"},
		{"foo", "bar1", "5de6c6c9ed4bf48122f6c851c80e6eacbf885947f02f974cdc794b14c8e975f1"},
	} {
		want, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if !verifyCommitment([]byte(tc.key), want, []byte(tc.data), nonce[:]) {
			t.Errorf("commitment for key=%q data=%q does not match libsignal's vector", tc.key, tc.data)
		}
		// The length prefixes exist precisely so that moving a byte across the
		// key/data boundary changes the commitment. Check that they do.
		if tc.key != "" && verifyCommitment([]byte(tc.key+tc.data), want, nil, nonce[:]) {
			t.Errorf("key=%q data=%q: commitment survived shifting the key/data boundary", tc.key, tc.data)
		}
	}
}

// Vectors from libsignal rust/keytrans/src/log.rs test_math.
func TestBatchCopathVectors(t *testing.T) {
	for _, tc := range []struct {
		leaves []uint64
		n      uint64
		want   []uint64
	}{
		{[]uint64{0, 2, 3, 4}, 8, []uint64{2, 10, 13}},
		{[]uint64{0, 2, 3}, 8, []uint64{2, 11}},
	} {
		got, err := batchCopath(tc.leaves, tc.n)
		if err != nil {
			t.Fatalf("batchCopath(%v, %d): %v", tc.leaves, tc.n, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("batchCopath(%v, %d) = %v, want %v", tc.leaves, tc.n, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("batchCopath(%v, %d) = %v, want %v", tc.leaves, tc.n, got, tc.want)
			}
		}
	}
}

// runGuide drives a proof guide the way libsignal's own guide tests do: every
// entry below target reports version 0, every entry at or above it reports 1.
func runGuide(t *testing.T, g *proofGuide, start, end, target uint64) (int, uint64, bool, []uint64) {
	t.Helper()
	var asked []uint64
	for {
		done, err := g.poll()
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if done {
			break
		}
		id := g.nextID()
		if id < start || id >= end {
			t.Fatalf("guide asked for id %d outside [%d, %d)", id, start, end)
		}
		asked = append(asked, id)
		if id < target {
			g.insert(id, 0)
		} else {
			g.insert(id, 1)
		}
	}
	i, id, ok := g.result()
	return i, id, ok, asked
}

// Vectors from libsignal rust/keytrans/src/guide.rs.
func TestProofGuideVectors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version *uint32
		start   uint64
		end     uint64
		target  uint64
		want    uint64
	}{
		{"version 0", ptr(uint32(0)), 100, 700, 399, 100},
		{"version 1", ptr(uint32(1)), 100, 700, 399, 399},
		{"most recent, target 701", nil, 100, 700, 701, 100},
		{"most recent, target 399", nil, 100, 700, 399, 399},
		{"most recent, target 699", nil, 100, 700, 699, 699},
		{"most recent, target 700", nil, 100, 701, 700, 700},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := newProofGuide(tc.version, tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			i, id, ok, asked := runGuide(t, g, tc.start, tc.end, tc.target)
			if !ok {
				t.Fatal("guide found no result")
			}
			if id != tc.want {
				t.Errorf("result id = %d, want %d", id, tc.want)
			}
			if asked[i] != tc.want {
				t.Errorf("asked[%d] = %d, want %d", i, asked[i], tc.want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// A server that reports fewer versions at a later entry is claiming a published
// version was withdrawn. The guide must refuse rather than search on.
func TestProofGuideRejectsNonMonotonicVersions(t *testing.T) {
	g, err := newProofGuide(nil, 100, 700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.poll(); err != nil {
		t.Fatal(err)
	}
	if len(g.ids) < 2 {
		t.Fatalf("need a frontier of at least two nodes to test monotonicity, got %d", len(g.ids))
	}
	// The frontier is read as a batch; report counters that decrease along it.
	for i, id := range g.ids {
		g.insert(id, uint32(len(g.ids)-i))
	}
	if _, err := g.poll(); err == nil {
		t.Fatal("expected a decreasing version counter to be refused")
	}
}

// A prefix proof is always exactly 256 hashes, one per bit of the index. That
// fixed length is a security property — it denies the server any choice about
// proof shape — so a short proof must be refused rather than padded.
func TestPrefixProofLengthIsFixed(t *testing.T) {
	var index hash
	if _, err := evaluatePrefixProof(index, 0, 0, make([]hash, 255)); err == nil {
		t.Fatal("expected a 255-hash prefix proof to be refused")
	}
	if _, err := evaluatePrefixProof(index, 0, 0, make([]hash, prefixTreeDepth)); err != nil {
		t.Fatalf("a full-length proof should evaluate: %v", err)
	}
}

// fetchDistinguished returns the raw DistinguishedResponse protobuf from
// production.
func fetchDistinguished(t *testing.T, s *Source) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		s.cfg.Endpoint+"/v1/key-transparency/distinguished", nil)
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	var env struct {
		SerializedResponse string `json:"serializedResponse"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	pb, err := base64.RawStdEncoding.DecodeString(env.SerializedResponse)
	if err != nil {
		t.Fatal(err)
	}
	return pb
}

// TestLiveSearchProof is the acceptance test for the search path, and like the
// tree-head one it is self-validating.
//
// The proof chains four independent mechanisms — VRF, prefix tree, batch
// inclusion, commitment — and ends at a log root. That root must equal the one
// derived separately from three auditors' consistency proofs and confirmed by
// Signal's own signature. Nothing about the search path was used to obtain that
// root, so agreement is not something a wrong implementation reaches by luck.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveSearchProof(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}

	s, err := New(Config{Origin: "signal.org/kt"})
	if err != nil {
		t.Fatal(err)
	}
	head, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	res := s.lastSearch
	if res == nil {
		t.Fatal("Fetch succeeded but recorded no verified search")
	}
	t.Logf("tree size %d, root %x", head.Size, head.Hash[:])
	t.Logf("distinguished: index %x, first seen at entry %d, version %d, %d entries opened",
		res.Index[:], res.Pos, res.Version, res.Entries)
	t.Logf("committed value: %q", res.Value)

	// The VRF output for "distinguished" is a fixed property of Signal's VRF
	// key, independent of the log's current state, so it can be pinned.
	const wantIndex = "4ce05147bfc5637c2b4d6a670bdaeae3ceb33b8a7d2cf598c8cb23da4f22e4a3"
	if got := hex.EncodeToString(res.Index[:]); got != wantIndex {
		t.Errorf("VRF index for %q = %s, want %s", DistinguishedKey, got, wantIndex)
	}
}

// TestLiveSearchProofNegativeControls corrupts one component of a genuine
// production proof at a time. Each must fail: a check that passes on mutated
// input is not checking anything.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveSearchProofNegativeControls(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}

	s, err := New(Config{Origin: "signal.org/kt"})
	if err != nil {
		t.Fatal(err)
	}
	pb := fetchDistinguished(t, s)
	top := parse(pb)
	size := varintOf(parse(first(parse(first(top, 1)), 1)), 1)
	condensed := first(top, 2)
	if condensed == nil {
		t.Fatal("no search proof in the response")
	}

	// Baseline: the untouched proof must verify.
	good, err := verifySearch(s.vrfPub, DistinguishedKey, nil, parse(condensed), size)
	if err != nil {
		t.Fatalf("the genuine proof should verify: %v", err)
	}

	for _, tc := range []struct {
		name string
		what string
	}{
		{"VRF proof", "vrf"},
		{"prefix proof", "prefix"},
		{"commitment", "commitment"},
		{"inclusion proof", "inclusion"},
		{"opening nonce", "opening"},
		{"search key", "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// parse returns sub-slices of the bytes it was given, so mutating
			// through the parsed view corrupts raw, which is what gets
			// re-parsed and verified below.
			raw := bytes.Clone(condensed)
			c := parse(raw)
			key := DistinguishedKey
			switch tc.what {
			case "vrf":
				flip(t, c[1][0], 0)
			case "prefix":
				step := parse(c[2][0])
				flip(t, parse(step[2][0])[1][0], 0)
			case "commitment":
				flip(t, parse(c[2][0])[2][0], 0)
			case "inclusion":
				sp := parse(c[2][0])
				if len(sp[3]) == 0 {
					t.Skip("proof has no inclusion hashes to corrupt")
				}
				flip(t, sp[3][0], 0)
			case "opening":
				flip(t, c[3][0], 0)
			case "key":
				key = []byte("distinguishea")
			}
			got, err := verifySearch(s.vrfPub, key, nil, parse(raw), size)
			if err == nil && got.Root == good.Root {
				t.Fatalf("corrupting the %s left the proof verifying to the same root", tc.name)
			}
		})
	}
}

func flip(t *testing.T, b []byte, i int) {
	t.Helper()
	if len(b) <= i {
		t.Fatalf("cannot flip byte %d of a %d-byte field", i, len(b))
	}
	b[i] ^= 0x01
}
