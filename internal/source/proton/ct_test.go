package proton

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// testEpoch is a real epoch as Proton served it, kept so the certificate paths
// can be exercised — including their negative controls — without the network.
func testEpoch(t *testing.T) *epoch {
	t.Helper()
	raw, err := os.ReadFile("testdata/epoch.json")
	if err != nil {
		t.Fatal(err)
	}
	var e epoch
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return &e
}

// ctLogs loads the logs this witness is configured with, which is also the list
// a wired deployment would hand the adapter.
func ctLogs(t *testing.T) []CTLog {
	t.Helper()
	raw, err := os.ReadFile("../../../deploy/ct-logs.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Type    string `json:"type"`
		Origin  string `json:"origin"`
		BaseURL string `json:"base_url"`
		LogKey  string `json:"log_key"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	var logs []CTLog
	for _, e := range entries {
		if e.Type != "staticct" {
			continue
		}
		spki, err := base64.StdEncoding.DecodeString(e.LogKey)
		if err != nil {
			t.Fatal(err)
		}
		logs = append(logs, CTLog{Origin: e.Origin, BaseURL: e.BaseURL, SPKI: spki})
	}
	if len(logs) == 0 {
		t.Fatal("no static CT logs configured")
	}
	return logs
}

func leafSCTs(t *testing.T, e *epoch) []sct {
	t.Helper()
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(oidSCTList) {
			s, err := parseSCTList(ext.Value)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatal("the epoch certificate carries no SCT list")
	return nil
}

// Proton's certificates must carry an SCT from a log that names the leaf's index
// — that is what makes an independent confirmation possible without asking any
// log for a proof.
func TestSCTsCarryLeafIndex(t *testing.T) {
	e := testEpoch(t)
	scts := leafSCTs(t, e)
	if len(scts) < 1 {
		t.Fatal("want at least one SCT")
	}
	indexed := 0
	for _, s := range scts {
		if _, ok := s.leafIndex(); ok {
			indexed++
		}
	}
	if indexed == 0 {
		t.Fatal("no SCT carries a static-ct-api leaf index")
	}
}

// A malformed SCT list must be refused rather than half-read: an SCT parsed out
// of the wrong bytes would send the inclusion check to an arbitrary index, where
// a mismatch would look like the log's fault.
func TestParseSCTListRejectsMalformed(t *testing.T) {
	e := testEpoch(t)
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	var ext []byte
	for _, x := range certs[0].Extensions {
		if x.Id.Equal(oidSCTList) {
			ext = append([]byte(nil), x.Value...)
		}
	}
	if _, err := parseSCTList(ext[:len(ext)-1]); err == nil {
		t.Fatal("a truncated SCT list must be refused")
	}
	if _, err := parseSCTList([]byte{0x04, 0x01, 0x00}); err == nil {
		t.Fatal("an SCT list too short to hold a list length must be refused")
	}
}

// precertTBS must remove the SCT list extension and change nothing else. If it
// removed more, or re-encoded a field differently, the result would still be a
// well-formed TBSCertificate — just not the one the CA signed.
func TestPrecertTBSRemovesOnlyTheSCTExtension(t *testing.T) {
	e := testEpoch(t)
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	raw := certs[0].RawTBSCertificate
	got, err := precertTBS(raw)
	if err != nil {
		t.Fatal(err)
	}

	var before, after tbsCertificate
	if _, err := asn1.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(got, &after); err != nil {
		t.Fatalf("the reconstruction does not parse as a TBSCertificate: %v", err)
	}
	if len(after.Extensions) != len(before.Extensions)-1 {
		t.Fatalf("extensions went from %d to %d, want exactly one removed",
			len(before.Extensions), len(after.Extensions))
	}
	for _, x := range after.Extensions {
		if x.ID.Equal(oidSCTList) {
			t.Fatal("the SCT list extension is still present")
		}
	}
	// Everything outside the extensions must survive byte for byte.
	if string(after.SerialNumber.FullBytes) != string(before.SerialNumber.FullBytes) ||
		string(after.Issuer.FullBytes) != string(before.Issuer.FullBytes) ||
		string(after.Subject.FullBytes) != string(before.Subject.FullBytes) ||
		string(after.Validity.FullBytes) != string(before.Validity.FullBytes) ||
		string(after.PublicKey.FullBytes) != string(before.PublicKey.FullBytes) {
		t.Fatal("a field outside the extensions changed under reconstruction")
	}

	// Negative control: running it again must fail, because the extension it
	// looks for is gone. A version that quietly succeeded would mean the removal
	// was never conditional on finding anything.
	if _, err := precertTBS(got); err == nil {
		t.Fatal("a certificate with no SCT list must not be accepted as a precertificate source")
	}
}

// The leaf hash must depend on every input. A check that survives a mutated TBS,
// issuer key or timestamp is confirming nothing.
func TestMerkleLeafIsSensitiveToItsInputs(t *testing.T) {
	e := testEpoch(t)
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := precertTBS(certs[0].RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	s := leafSCTs(t, e)[0]
	issuerKeyHash := sha256.Sum256(certs[1].RawSubjectPublicKeyInfo)

	base, err := merkleLeaf(s, issuerKeyHash, tbs)
	if err != nil {
		t.Fatal(err)
	}
	baseHash := sha256.Sum256(base)

	mutTBS := append([]byte(nil), tbs...)
	mutTBS[len(mutTBS)/2] ^= 1
	mutated, _ := merkleLeaf(s, issuerKeyHash, mutTBS)
	if sha256.Sum256(mutated) == baseHash {
		t.Fatal("flipping a bit in the TBSCertificate did not change the leaf")
	}

	badIssuer := issuerKeyHash
	badIssuer[0] ^= 1
	mutated, _ = merkleLeaf(s, badIssuer, tbs)
	if sha256.Sum256(mutated) == baseHash {
		t.Fatal("changing the issuer key hash did not change the leaf")
	}

	badTime := s
	badTime.Timestamp++
	mutated, _ = merkleLeaf(badTime, issuerKeyHash, tbs)
	if sha256.Sum256(mutated) == baseHash {
		t.Fatal("changing the SCT timestamp did not change the leaf")
	}
}

// With no log we recognise, the answer is "could not confirm" — an absence, and
// never a finding about Proton.
func TestConfirmInCTWithNoKnownLog(t *testing.T) {
	e := testEpoch(t)
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ConfirmInCT(context.Background(), certs, []CTLog{{
		Origin: "nobody.example", BaseURL: "https://nobody.example/", SPKI: []byte("not a key"),
	}})
	if !errors.Is(err, ErrNoKnownLog) {
		t.Fatalf("want ErrNoKnownLog, got %v", err)
	}
}

// Live: the whole loop, against production. The epoch certificate is rebuilt
// into the Merkle leaf a CT log would have committed to and matched against the
// hash that log's own signed checkpoint carries at the index its SCT named.
//
// This is also what validates the ASN.1 reconstruction: nothing else in the
// project can tell a correct TBSCertificate from a merely well-formed one, and a
// wrong one fails here rather than passing quietly.
func TestLiveConfirmEpochCertificateInCT(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	ctx := context.Background()
	s, err := New(Config{Origin: "proton.me/kt/v1", CTLogs: ctLogs(t)})
	if err != nil {
		t.Fatal(err)
	}

	var resp struct {
		Epochs []epoch `json:"Epochs"`
	}
	if err := s.get(ctx, "/kt/v1/epochs", &resp); err != nil {
		t.Fatal(err)
	}
	e := resp.Epochs[0]
	for _, c := range resp.Epochs {
		if c.EpochID > e.EpochID {
			e = c
		}
	}

	conf, err := s.ConfirmCertificate(ctx, &e)
	if err != nil {
		t.Fatalf("epoch %d: %v", e.EpochID, err)
	}
	if conf == nil {
		t.Fatal("no confirmation and no error")
	}
	t.Logf("epoch %d: %s", e.EpochID, conf)

	// Negative control: the same certificate must NOT confirm at a neighbouring
	// index. Without this, a check that returned success regardless of what the
	// log holds would look identical.
	certs, err := e.certificates()
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := precertTBS(certs[0].RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	issuerKeyHash := sha256.Sum256(certs[1].RawSubjectPublicKeyInfo)
	for _, sc := range leafSCTs(t, &e) {
		if sc.LogID != logByOrigin(t, ctLogs(t), conf.Origin).LogID() {
			continue
		}
		leafBytes, err := merkleLeaf(sc, issuerKeyHash, tbs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := confirmInLog(ctx, logByOrigin(t, ctLogs(t), conf.Origin), conf.LeafIndex+1, leafBytes); err == nil {
			t.Fatal("the certificate confirmed at the wrong index; the check is not reading the log")
		}
		// And a mutated certificate must not confirm at the right index.
		bad := append([]byte(nil), tbs...)
		bad[len(bad)/2] ^= 1
		badLeaf, err := merkleLeaf(sc, issuerKeyHash, bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := confirmInLog(ctx, logByOrigin(t, ctLogs(t), conf.Origin), conf.LeafIndex, badLeaf); err == nil {
			t.Fatal("a mutated certificate confirmed; the leaf hash is not being compared")
		}
	}
}

func logByOrigin(t *testing.T, logs []CTLog, origin string) CTLog {
	t.Helper()
	for _, l := range logs {
		if l.Origin == origin {
			return l
		}
	}
	t.Fatalf("no configured log named %s", origin)
	return CTLog{}
}
