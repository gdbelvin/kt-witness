package hsm

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

// fakeSession stands in for the device. It is not a YubiHSM simulator — the
// session protocol is exercised against real hardware by the KT_HSM_LIVE test.
// What it covers is this package's own logic, including the failure paths that
// cannot be produced on demand with real hardware: you cannot unplug a device
// from a CI runner.
type fakeSession struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	algorithm commands.Algorithm
	err       error // returned by every command, simulating a dead connector
	sent      int
	destroyed bool
}

func newFake(t *testing.T) *fakeSession {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSession{pub: pub, priv: priv, algorithm: commands.AlgorithmED25519}
}

func (f *fakeSession) Destroy() { f.destroyed = true }

func (f *fakeSession) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	f.sent++
	if f.err != nil {
		return nil, f.err
	}
	switch c.CommandType {
	case commands.CommandTypeGetPubKey:
		return &commands.GetPubKeyResponse{Algorithm: f.algorithm, KeyData: f.pub}, nil
	case commands.CommandTypeSignDataEddsa:
		// The payload is the key id followed by the message.
		return &commands.SignDataEddsaResponse{Signature: ed25519.Sign(f.priv, c.Data[2:])}, nil
	case commands.CommandTypeEcho:
		return &commands.EchoResponse{Data: c.Data}, nil
	}
	return nil, errors.New("fake: unexpected command")
}

func openFake(t *testing.T, f *fakeSession) *Signer {
	t.Helper()
	s, err := newSigner(Config{ConnectorURL: "x", AuthKeyID: 1, Password: "p", KeyID: 0x1100}, f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The ordinary path: the key the device reports is the key its signatures
// verify under.
func TestSignsUnderTheKeyTheDeviceReports(t *testing.T) {
	f := newFake(t)
	s := openFake(t, f)

	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Public() is %T, want ed25519.PublicKey", s.Public())
	}
	msg := []byte("cosignature/v1\ntime 1\n")
	sig, err := s.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify under the reported key")
	}
}

// The reason ErrUnavailable exists: an outage must be distinguishable from a
// log misbehaving, by errors.Is rather than by matching a string.
func TestATransportFailureIsErrUnavailable(t *testing.T) {
	f := newFake(t)
	s := openFake(t, f)

	f.err = errors.New("connection refused")

	if _, err := s.Sign(nil, []byte("x"), crypto.Hash(0)); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Sign: got %v, want ErrUnavailable", err)
	}
	if err := s.Alive(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Alive: got %v, want ErrUnavailable", err)
	}
}

// The round's pre-flight. This is what lets one dead connector skip a round
// instead of withholding from eighty logs.
func TestAliveReportsAReachableDevice(t *testing.T) {
	f := newFake(t)
	s := openFake(t, f)
	if err := s.Alive(); err != nil {
		t.Fatalf("Alive on a healthy device: %v", err)
	}
}

// A connector that dies before the first command must not yield a half-built
// signer, and must not leak the session.
func TestOpenFailsClosedWhenTheDeviceIsUnreachable(t *testing.T) {
	f := newFake(t)
	f.err = errors.New("connection refused")

	if _, err := newSigner(Config{KeyID: 0x1100}, f); !errors.Is(err, ErrUnavailable) {
		t.Errorf("got %v, want ErrUnavailable", err)
	}
	if !f.destroyed {
		t.Error("session was not destroyed after a failed Open")
	}
}

// Ed25519ph is not implemented by the YubiHSM. A caller asking for a prehash
// must be refused rather than handed a signature over the wrong bytes.
func TestSignRefusesAPrehash(t *testing.T) {
	f := newFake(t)
	s := openFake(t, f)

	before := f.sent
	if _, err := s.Sign(nil, []byte("digest"), crypto.SHA256); err == nil {
		t.Fatal("a SHA-256 prehash must be refused")
	}
	if f.sent != before {
		t.Error("refusal must happen before anything reaches the device")
	}
}

// Pointing the config at an object that is not an Ed25519 key is a
// configuration error, and it must be caught at startup rather than at the
// first cosignature.
func TestOpenRejectsAKeyThatIsNotEd25519(t *testing.T) {
	f := newFake(t)
	f.algorithm = commands.AlgorithmSecp256k1

	if _, err := newSigner(Config{KeyID: 0x1100}, f); err == nil {
		t.Fatal("a non-ed25519 object must be refused")
	}
}

// Incomplete configuration should not reach the network at all.
func TestOpenRequiresACompleteConfiguration(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no connector": {AuthKeyID: 1, Password: "p", KeyID: 2},
		"no auth key":  {ConnectorURL: "x", Password: "p", KeyID: 2},
		"no password":  {ConnectorURL: "x", AuthKeyID: 1, KeyID: 2},
		"no key id":    {ConnectorURL: "x", AuthKeyID: 1, Password: "p"},
	} {
		if _, err := Open(cfg); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: got %v, want ErrUnavailable", name, err)
		}
	}
}

// The first containerised run of this package failed here. The client builds
// "http://" + addr + "/connector/api" itself, so a config carrying a URL became
// "http://http//172.17.0.1:12346/connector/api" and the process tried to
// resolve the host "http" — an error that names DNS and never mentions the
// address being wrong.
func TestConnectorAddressAcceptsWhateverTheOperatorWrote(t *testing.T) {
	for in, want := range map[string]string{
		"172.17.0.1:12346":                      "172.17.0.1:12346",
		"http://172.17.0.1:12346":               "172.17.0.1:12346",
		"http://172.17.0.1:12346/":              "172.17.0.1:12346",
		"http://172.17.0.1:12346/connector/api": "172.17.0.1:12346",
		"127.0.0.1:12345":                       "127.0.0.1:12345",
	} {
		got, err := connectorAddr(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// https would be silently downgraded by stripping the scheme, so it is refused.
func TestConnectorAddressRefusesHTTPS(t *testing.T) {
	if _, err := connectorAddr("https://hsm.example.com:12345"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("got %v, want ErrUnavailable", err)
	}
}
