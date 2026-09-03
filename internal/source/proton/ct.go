package proton

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/staticct"
	"golang.org/x/mod/sumdb/tlog"
)

// Confirming a Proton epoch certificate in a Certificate Transparency log.
//
// # Why this is the check that matters for Proton
//
// Proton signs no roots. What makes an epoch non-repudiable is a WebPKI
// certificate whose SAN encodes the chain hash, and what is supposed to make
// equivocation *visible* is that the certificate lands in CT: two chain hashes
// for one epoch would mean two logged certificates, in logs Proton does not
// control. Verifying the certificate's chain alone does not use that channel at
// all — it accepts the log's promise, in the form of an embedded SCT, that the
// certificate was submitted. An SCT is a promise; inclusion is the fact.
//
// # How the loop closes with what this witness already has
//
// Proton's certificates carry SCTs from static CT logs (c2sp.org/static-ct-api),
// and this witness already fetches and verifies those logs' checkpoints. Two
// properties of static-ct-api make an independent confirmation cheap:
//
//   - the SCT's extensions carry the leaf's index in the log, so there is no
//     need to ask anyone where the certificate is;
//   - the tree is served as tiles, so an inclusion proof is *computed locally*
//     from tile data that tlog.TileHashReader authenticates against the signed
//     root. The log is never asked for a proof it could have fabricated.
//
// So the confirmation is: rebuild the Merkle leaf the log would have committed
// to when it logged this certificate, and require it to equal the hash the log's
// own signed checkpoint puts at that index. If it does, this certificate — and
// therefore this epoch's chain hash — is in a CT log at a position the log has
// signed for, and Proton cannot show a different one to anyone else without a
// second logged certificate that anyone can find.
//
// # What it may conclude
//
// Nothing here can ever produce a fork. A log we cannot reach, a checkpoint too
// short to cover the index, a certificate with no SCT from a log we know: these
// mean *we could not confirm*, which withholds. Even a leaf-hash mismatch is
// reported rather than accused — it is far more likely to mean this
// reconstruction is wrong than that a CA, a CT log and Proton all are.

// CTLog is one log this witness can confirm a certificate in.
type CTLog struct {
	// Origin is the checkpoint origin, per static-ct-api the submission prefix.
	Origin string
	// BaseURL serves "checkpoint" and "tile/...".
	BaseURL string
	// SPKI is the log's DER SubjectPublicKeyInfo, exactly as the CT log list
	// publishes it. Its SHA-256 is the log ID an SCT names.
	SPKI []byte
}

// LogID is the identifier an SCT carries: SHA-256 over the log's SPKI.
func (l CTLog) LogID() [32]byte { return sha256.Sum256(l.SPKI) }

// ErrNoKnownLog reports that the certificate carries no SCT from a log we were
// configured with. That is an absence, not a finding.
var ErrNoKnownLog = errors.New("proton: certificate carries no SCT from a configured CT log")

// oidSCTList is the CT poison-free SCT list extension, RFC 6962 §3.3.
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// oidPoison is the precertificate poison extension, which is present in what the
// CA signed as a precertificate and absent from the issued certificate.
var oidPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// sct is one Signed Certificate Timestamp, as embedded in a certificate.
type sct struct {
	LogID      [32]byte
	Timestamp  uint64
	Extensions []byte
}

// leafIndex reads the log-assigned index from the SCT extensions.
//
// static-ct-api defines extension type 0 as a five-byte big-endian leaf index.
// This is what removes the need for an RFC 6962 get-proof-by-hash call: the log
// told us where it put the entry at submission time, and it is then held to that
// by the inclusion check.
func (s sct) leafIndex() (int64, bool) {
	rest := s.Extensions
	for len(rest) >= 3 {
		typ := rest[0]
		length := int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest) < 3+length {
			return 0, false
		}
		body := rest[3 : 3+length]
		if typ == 0 && length == 5 {
			var idx int64
			for _, b := range body {
				idx = idx<<8 | int64(b)
			}
			return idx, true
		}
		rest = rest[3+length:]
	}
	return 0, false
}

// parseSCTList pulls the SCTs out of a certificate's SCT list extension.
func parseSCTList(ext []byte) ([]sct, error) {
	// The extension value is a DER OCTET STRING wrapping a TLS SignedCertificate
	// TimestampList: uint16 total length, then uint16-framed SCTs.
	var raw []byte
	if _, err := asn1.Unmarshal(ext, &raw); err != nil {
		return nil, fmt.Errorf("proton: SCT list is not an OCTET STRING: %w", err)
	}
	if len(raw) < 2 {
		return nil, fmt.Errorf("proton: SCT list is %d bytes", len(raw))
	}
	if int(binary.BigEndian.Uint16(raw[:2])) != len(raw)-2 {
		return nil, fmt.Errorf("proton: SCT list length field does not match its contents")
	}
	rest := raw[2:]

	var out []sct
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("proton: truncated SCT list")
		}
		n := int(binary.BigEndian.Uint16(rest[:2]))
		if len(rest) < 2+n {
			return nil, fmt.Errorf("proton: truncated SCT")
		}
		body := rest[2 : 2+n]
		rest = rest[2+n:]

		// struct { version(1) | log_id(32) | timestamp(8) | extensions(uint16) |
		// signature } — the signature is not needed here: the inclusion check is
		// strictly stronger than the promise the signature makes.
		if len(body) < 1+32+8+2 {
			return nil, fmt.Errorf("proton: SCT is %d bytes, too short", len(body))
		}
		if body[0] != 0 {
			return nil, fmt.Errorf("proton: SCT version %d, want v1", body[0])
		}
		var s sct
		copy(s.LogID[:], body[1:33])
		s.Timestamp = binary.BigEndian.Uint64(body[33:41])
		extLen := int(binary.BigEndian.Uint16(body[41:43]))
		if len(body) < 43+extLen {
			return nil, fmt.Errorf("proton: SCT extensions run past the end")
		}
		s.Extensions = body[43 : 43+extLen]
		out = append(out, s)
	}
	return out, nil
}

// tbsCertificate is enough of RFC 5280's TBSCertificate to reach the extensions
// and put them back. Every field is kept as a raw value, so the parts that are
// not being changed are re-emitted byte for byte rather than re-encoded from an
// interpretation of them — which is what makes the result the same bytes the CA
// signed.
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.RawValue `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.RawValue `asn1:"optional,tag:2"`
	Extensions         []extension   `asn1:"optional,explicit,tag:3"`
}

type extension struct {
	Raw      asn1.RawContent
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// precertTBS rebuilds the TBSCertificate the CA signed as a precertificate: the
// issued certificate's, with the SCT list extension removed.
//
// RFC 6962 §3.2 requires the poison extension to be removed as well, but the
// issued certificate never carries one, so its absence is expected rather than
// something to strip.
//
// This surgery is the one step here that could silently produce plausible
// nonsense, and it is deliberately self-validating: a byte wrong anywhere in the
// result gives a Merkle leaf hash that matches nothing in the log, so
// ConfirmInCT fails rather than passing on a reconstruction that is merely
// well-formed.
func precertTBS(rawTBS []byte) ([]byte, error) {
	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(rawTBS, &tbs); err != nil {
		return nil, fmt.Errorf("proton: parse TBSCertificate: %w", err)
	}
	kept := make([]extension, 0, len(tbs.Extensions))
	found := false
	for _, e := range tbs.Extensions {
		if e.ID.Equal(oidSCTList) {
			found = true
			continue
		}
		if e.ID.Equal(oidPoison) {
			return nil, fmt.Errorf("proton: certificate carries the precertificate poison extension")
		}
		kept = append(kept, e)
	}
	if !found {
		return nil, fmt.Errorf("proton: certificate has no SCT list extension")
	}
	tbs.Extensions = kept
	// Raw must be cleared, or asn1 re-emits the original bytes — including the
	// extension just removed — and the reconstruction would silently be a no-op.
	tbs.Raw = nil
	out, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("proton: re-encode TBSCertificate: %w", err)
	}
	return out, nil
}

// merkleLeaf builds the RFC 6962 MerkleTreeLeaf for a logged precertificate:
//
//	version(0) | leaf_type(0) | timestamp | entry_type(1) | issuer_key_hash |
//	uint24 tbs | extensions(uint16)
//
// The SCT's extensions are reused verbatim because the leaf commits to them —
// which is also what binds the leaf index the log handed out into the hash the
// log's tree carries.
func merkleLeaf(s sct, issuerKeyHash [32]byte, tbs []byte) ([]byte, error) {
	if len(tbs) >= 1<<24 {
		return nil, fmt.Errorf("proton: TBSCertificate is %d bytes, too large for a CT leaf", len(tbs))
	}
	var b []byte
	b = append(b, 0, 0) // version v1, leaf type timestamped_entry
	b = binary.BigEndian.AppendUint64(b, s.Timestamp)
	b = append(b, 0, 1) // entry type precert_entry
	b = append(b, issuerKeyHash[:]...)
	b = append(b, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
	b = append(b, tbs...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(s.Extensions)))
	b = append(b, s.Extensions...)
	return b, nil
}

// CTConfirmation records what a successful confirmation established.
type CTConfirmation struct {
	Origin    string
	LeafIndex int64
	TreeSize  int64
	Root      tlog.Hash
	LeafHash  tlog.Hash
}

func (c *CTConfirmation) String() string {
	return fmt.Sprintf("epoch certificate is entry %d of %s, under the root that log signed at size %d",
		c.LeafIndex, c.Origin, c.TreeSize)
}

// ConfirmInCT confirms that the leaf certificate is present in one of the given
// CT logs, using the log's own signed checkpoint and locally verified tiles.
//
// certs is the epoch's chain, leaf first; the second entry is the issuer, whose
// public key hash the CT leaf commits to. The first log that can be reached and
// that confirms the certificate ends the search — one confirmation is the whole
// claim, and Proton's certificates come from CAs whose log choices rotate.
func ConfirmInCT(ctx context.Context, certs []*x509.Certificate, logs []CTLog) (*CTConfirmation, error) {
	if len(certs) < 2 {
		return nil, fmt.Errorf("proton: need the issuer certificate to rebuild a CT leaf, got %d certificates", len(certs))
	}
	leaf, issuer := certs[0], certs[1]

	var sctExt []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSCTList) {
			sctExt = e.Value
		}
	}
	if sctExt == nil {
		return nil, fmt.Errorf("proton: certificate carries no SCTs")
	}
	scts, err := parseSCTList(sctExt)
	if err != nil {
		return nil, err
	}

	tbs, err := precertTBS(leaf.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	byID := make(map[[32]byte]CTLog, len(logs))
	for _, l := range logs {
		byID[l.LogID()] = l
	}

	var errs []error
	for _, s := range scts {
		l, ok := byID[s.LogID]
		if !ok {
			continue
		}
		idx, ok := s.leafIndex()
		if !ok {
			// An RFC 6962 log's SCT carries no index. Finding the entry would
			// need get-proof-by-hash, which tiled logs do not serve; skip it
			// rather than pretending the log was checked.
			errs = append(errs, fmt.Errorf("%s: SCT carries no leaf index", l.Origin))
			continue
		}
		leafBytes, err := merkleLeaf(s, issuerKeyHash, tbs)
		if err != nil {
			return nil, err
		}
		conf, err := confirmInLog(ctx, l, idx, leafBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.Origin, err))
			continue
		}
		return conf, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("proton: could not confirm the epoch certificate in CT: %w", errors.Join(errs...))
	}
	return nil, ErrNoKnownLog
}

// confirmInLog fetches the log's signed checkpoint and requires the hash it
// carries at idx to be the leaf we rebuilt.
func confirmInLog(ctx context.Context, l CTLog, idx int64, leafBytes []byte) (*CTConfirmation, error) {
	v, err := staticct.NewVerifier(l.Origin, l.SPKI)
	if err != nil {
		return nil, err
	}
	f, err := torchwood.NewTileFetcher(l.BaseURL,
		torchwood.WithUserAgent("kt-witness/0.1 (+https://github.com/gdbsecurity/kt-witness)"))
	if err != nil {
		return nil, err
	}
	raw, err := f.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("fetch checkpoint: %w", err)
	}
	cp, _, err := torchwood.VerifyCheckpoint(raw, torchwood.ThresholdPolicy(2,
		torchwood.OriginPolicy(l.Origin),
		torchwood.SingleVerifierPolicy(v),
	))
	if err != nil {
		return nil, fmt.Errorf("verify checkpoint: %w", err)
	}
	if idx >= cp.N {
		// The certificate is newer than the checkpoint we can see. That is
		// ordinary — logs merge on a schedule — and it means "not yet", not
		// "not there".
		return nil, fmt.Errorf("entry %d is beyond the signed size %d; the log has not merged it yet", idx, cp.N)
	}

	// TileHashReader authenticates every tile it returns against cp.Hash, so a
	// hash it yields is already bound to the root the log signed. That is why no
	// proof is requested from the log: there is nothing for it to forge.
	hr := torchwood.TileHashReaderWithContext(ctx, tlog.Tree{N: cp.N, Hash: cp.Hash}, f)
	hashes, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, idx)})
	if err != nil {
		return nil, fmt.Errorf("read entry %d: %w", idx, err)
	}
	want := tlog.RecordHash(leafBytes)
	if hashes[0] != want {
		return nil, fmt.Errorf("entry %d hashes to %x, but this certificate builds %x",
			idx, hashes[0][:], want[:])
	}
	return &CTConfirmation{
		Origin:    l.Origin,
		LeafIndex: idx,
		TreeSize:  cp.N,
		Root:      cp.Hash,
		LeafHash:  want,
	}, nil
}
