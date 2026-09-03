package signal

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

// TestLiveDeriveServiceRoot is the acceptance test for the log-tree
// reimplementation, and it is deliberately self-validating: each of Signal's
// three auditors carries an independently signed root at its own tree size plus
// a consistency proof up to the service size. Running those proofs forwards must
// yield the *same* service root from all three, and Signal's own signature must
// verify over it.
//
// If any of the tree math is wrong, the three will not agree and no signature
// will verify. Getting all four checks to pass by accident is not plausible.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveDeriveServiceRoot(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}

	s, err := New(Config{Origin: "signal.org/kt"})
	if err != nil {
		t.Fatal(err)
	}

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

	fth := parse(first(parse(pb), 1))
	th := parse(first(fth, 1))
	serviceSize := varintOf(th, 1)
	serviceTS := int64(varintOf(th, 2))
	t.Logf("service tree_size=%d timestamp=%d", serviceSize, serviceTS)

	derived := map[string]hash{}
	for _, faRaw := range fth[4] {
		fa := parse(faRaw)
		pub := first(fa, 4)
		rootBytes := first(fa, 2)
		if len(rootBytes) != 32 {
			t.Fatalf("auditor root is %d bytes", len(rootBytes))
		}
		var auditorRoot hash
		copy(auditorRoot[:], rootBytes)

		ah := parse(first(fa, 1))
		auditorSize := varintOf(ah, 1)

		var proof []hash
		for _, p := range fa[3] {
			if len(p) != 32 {
				t.Fatalf("consistency hash is %d bytes", len(p))
			}
			var h hash
			copy(h[:], p)
			proof = append(proof, h)
		}

		got, err := deriveRoot(auditorSize, serviceSize, proof, auditorRoot)
		if err != nil {
			t.Fatalf("auditor %s: deriving service root failed: %v", hex.EncodeToString(pub)[:16], err)
		}
		t.Logf("auditor %s size=%d proof=%d hashes -> service root %x",
			hex.EncodeToString(pub)[:16], auditorSize, len(proof), got)
		derived[hex.EncodeToString(pub)] = got
	}

	if len(derived) < 2 {
		t.Fatalf("expected several auditors, got %d", len(derived))
	}

	// 1. All auditors must land on the same service root.
	var ref hash
	isFirst := true
	for k, v := range derived {
		if isFirst {
			ref, isFirst = v, false
			continue
		}
		if v != ref {
			t.Fatalf("auditors disagree on the service root: %s derived %x, another derived %x", k[:16], v, ref)
		}
	}
	t.Logf("all %d auditors agree on service root %x", len(derived), ref)

	// 2. Signal's own signature must verify over the derived root. There is one
	//    signature per auditor key, each binding that key into the preimage.
	sigKey, _ := hex.DecodeString(ProdSigningKey)
	verified := 0
	for _, sigRaw := range th[3] {
		sm := parse(sigRaw)
		auditorKey := first(sm, 1)
		sig := first(sm, 2)
		if len(auditorKey) != 32 || len(sig) != 64 {
			continue
		}
		src, err := New(Config{Origin: "signal.org/kt"})
		if err != nil {
			t.Fatal(err)
		}
		msg := src.signable(auditorKey, serviceSize, serviceTS, ref[:])
		if !ed25519.Verify(sigKey, msg, sig) {
			t.Errorf("service signature bound to auditor %s does NOT verify over the derived root",
				hex.EncodeToString(auditorKey)[:16])
			continue
		}
		verified++
		t.Logf("service signature (auditor %s) VERIFIES over derived root",
			hex.EncodeToString(auditorKey)[:16])
	}
	if verified == 0 {
		t.Fatal("no service signature verified over the derived root")
	}
}
