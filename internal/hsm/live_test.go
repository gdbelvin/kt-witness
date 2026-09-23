package hsm

import (
	"crypto"
	"crypto/ed25519"
	"os"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

// Against a real device. Requires a connector and the throwaway objects from
// the rehearsal; set KT_HSM_LIVE=1 to run it. CI has no hardware and never
// will, so the fake-connector tests are the ones that gate a merge — this one
// is what a person runs from the laptop with the tunnel open.
func TestLiveSignsAndVerifies(t *testing.T) {
	if os.Getenv("KT_HSM_LIVE") == "" {
		t.Skip("set KT_HSM_LIVE=1 to run against the device")
	}
	s, err := Open(Config{
		ConnectorURL: envOr("KT_HSM_CONNECTOR", "127.0.0.1:12346"),
		AuthKeyID:    0xF001,
		Password:     "pkgtest",
		KeyID:        0xF100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Alive(); err != nil {
		t.Fatalf("Alive: %v", err)
	}

	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want ed25519.PublicKey", s.Public())
	}

	msg := []byte("live probe")
	sig, err := s.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify under the key the device reported")
	}

	// The real acceptance test: torchwood must accept this as a cosigner, and
	// the note it produces must open under the verifier the same signer
	// publishes. That is the whole job.
	cs, err := torchwood.NewCosignatureSigner("witness.test", s)
	if err != nil {
		t.Fatal(err)
	}
	body := "example.com/log\n42\nqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=\n"
	signed, err := note.Sign(&note.Note{Text: body}, cs)
	if err != nil {
		t.Fatal(err)
	}
	v, err := torchwood.NewCosignatureVerifier(cs.Verifier().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(signed, note.VerifierList(v)); err != nil {
		t.Fatalf("HSM-signed note does not open under its own verifier: %v", err)
	}
	t.Logf("cosigned via HSM; verifier %s", cs.Verifier().String())
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
