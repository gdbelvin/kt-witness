package signal

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- minimal protobuf writer, so tests can build responses the real server
// would send (and ones it would not).

func tag(field int, wire byte) []byte { return uvarintBytes(uint64(field)<<3 | uint64(wire)) }

func uvarintBytes(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func lenField(field int, v []byte) []byte {
	out := tag(field, 2)
	out = append(out, uvarintBytes(uint64(len(v)))...)
	return append(out, v...)
}

func varField(field int, v uint64) []byte {
	return append(tag(field, 0), uvarintBytes(v)...)
}

type testServer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	auditorSize uint64
	serviceSize uint64
	timestamp   int64
	root        []byte

	// tamperRoot replaces the root AFTER signing, simulating a response whose
	// signature does not cover what it claims.
	tamperRoot []byte
	// omitAuditor drops our auditor from the response entirely.
	omitAuditor bool
}

func (ts *testServer) build(t *testing.T, s *Source) []byte {
	t.Helper()

	sig := ed25519.Sign(ts.priv, s.signable(ts.auditorSize, ts.timestamp, ts.root))

	root := ts.root
	if ts.tamperRoot != nil {
		root = ts.tamperRoot
	}

	// AuditorTreeHead{1:tree_size, 2:timestamp, 3:signature}
	ah := append(varField(1, ts.auditorSize), varField(2, uint64(ts.timestamp))...)
	ah = append(ah, lenField(3, sig)...)

	// FullAuditorTreeHead{1:tree_head, 2:root_value, 4:public_key}
	fa := append(lenField(1, ah), lenField(2, root)...)
	fa = append(fa, lenField(4, ts.pub)...)

	// TreeHead{1:tree_size, 2:timestamp}
	th := append(varField(1, ts.serviceSize), varField(2, uint64(ts.timestamp))...)

	// FullTreeHead{1:tree_head, 4:full_auditor_tree_heads}
	fth := lenField(1, th)
	if !ts.omitAuditor {
		fth = append(fth, lenField(4, fa)...)
	}

	// Response{1:full_tree_head}
	return lenField(1, fth)
}

func newTestSource(t *testing.T, ts *testServer) *Source {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.pub, ts.priv = pub, priv

	// Built before the server so build() can use signable().
	s, err := New(Config{Origin: "signal.test/kt", AuditorKey: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}

	// Built once, up front, with pristine keys. Tests that mutate the Source
	// afterwards must not also change what the server signs, or they would stay
	// self-consistent and prove nothing.
	body := ts.build(t, s)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/key-transparency/distinguished") {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"serializedResponse": base64.RawStdEncoding.EncodeToString(body),
		})
	}))
	t.Cleanup(srv.Close)

	// Point at the test server, and use its plain-HTTP client rather than the
	// pinned-CA one.
	s.cfg.Endpoint = srv.URL
	s.client = srv.Client()
	return s
}

func root(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestFetchVerifiesAuditorSignature(t *testing.T) {
	ts := &testServer{auditorSize: 1000, serviceSize: 1200, timestamp: 1788307451558, root: root(7)}
	s := newTestSource(t, ts)

	head, err := s.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("a correctly signed head should verify: %v", err)
	}
	if head.Size != 1000 {
		t.Fatalf("want size 1000, got %d", head.Size)
	}
	if hex.EncodeToString(head.Hash[:]) != hex.EncodeToString(root(7)) {
		t.Fatalf("head hash should be the auditor's signed root, got %x", head.Hash)
	}
}

// The signature must actually cover the root. A response whose root was swapped
// after signing must be rejected, or the whole tier is decorative.
func TestTamperedRootIsRejected(t *testing.T) {
	ts := &testServer{
		auditorSize: 1000, serviceSize: 1200, timestamp: 1788307451558,
		root: root(7), tamperRoot: root(8),
	}
	s := newTestSource(t, ts)

	if _, err := s.Fetch(context.Background(), nil); err == nil {
		t.Fatal("a root that the signature does not cover must be rejected")
	}
}

// Every field of the preimage is load-bearing; getting the service keys wrong
// must fail closed rather than silently accept.
func TestWrongServiceKeysFailVerification(t *testing.T) {
	ts := &testServer{auditorSize: 1000, serviceSize: 1200, timestamp: 1788307451558, root: root(7)}
	s := newTestSource(t, ts)

	other := make([]byte, 32)
	other[0] = 0xAA
	s.vrfKey = other

	if _, err := s.Fetch(context.Background(), nil); err == nil {
		t.Fatal("a different VRF key changes the preimage, so verification must fail")
	}
}

func TestMissingAuditorIsReported(t *testing.T) {
	ts := &testServer{
		auditorSize: 1000, serviceSize: 1200, timestamp: 1788307451558,
		root: root(7), omitAuditor: true,
	}
	s := newTestSource(t, ts)

	_, err := s.Fetch(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no tree head from auditor") {
		t.Fatalf("want a clear missing-auditor error, got %v", err)
	}
}

// An auditor cannot have audited more of the tree than exists.
func TestAuditorAheadOfServiceIsRejected(t *testing.T) {
	ts := &testServer{auditorSize: 1500, serviceSize: 1200, timestamp: 1788307451558, root: root(7)}
	s := newTestSource(t, ts)

	_, err := s.Fetch(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds service tree size") {
		t.Fatalf("want an incoherence error, got %v", err)
	}
}

// Pinned production key material must not drift: these are what make signatures
// verify against the live service, and a typo would silently break everything.
func TestProductionKeysAreWellFormed(t *testing.T) {
	for name, k := range map[string]string{"signing": ProdSigningKey, "vrf": ProdVRFKey} {
		if _, err := decodeKey(k, name); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	if len(ProdAuditorKeys) != 3 {
		t.Fatalf("Signal deploys three auditors, config has %d", len(ProdAuditorKeys))
	}
	seen := map[string]bool{}
	for _, k := range ProdAuditorKeys {
		if _, err := decodeKey(k, "auditor"); err != nil {
			t.Errorf("auditor key %s: %v", k[:8], err)
		}
		if seen[k] {
			t.Errorf("duplicate auditor key %s", k[:8])
		}
		seen[k] = true
	}
}

func TestSignablePreimageLayout(t *testing.T) {
	s, err := New(Config{Origin: "x", AuditorKey: ProdAuditorKeys[0]})
	if err != nil {
		t.Fatal(err)
	}
	got := s.signable(1, 2, root(3))

	// 2 ciphersuite + 1 mode + 3*(2 + 32) + 8 size + 8 timestamp + 32 root
	const want = 2 + 1 + 3*(2+32) + 8 + 8 + 32
	if len(got) != want {
		t.Fatalf("preimage is %d bytes, want %d", len(got), want)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != deploymentModeThirdPartyAuditing {
		t.Fatalf("preimage must start with ciphersuite 0,0 then mode 3, got %v", got[:3])
	}
	if binary.BigEndian.Uint64(got[want-48:want-40]) != 1 {
		t.Fatal("tree size not encoded big-endian where expected")
	}
}
