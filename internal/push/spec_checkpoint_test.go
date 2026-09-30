package push

// Conformance tests against the "Signatures" section of c2sp.org/tlog-checkpoint,
// read from the client's side: the witness is the client that must refuse to
// cosign what the section says a log must not produce, and must tolerate what
// the section says a client must accept.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// growWith appends k leaves whose contents are prefix-derived, so two logs
// grown with different prefixes have different trees at every size >= 1.
func (l *testLog) growWith(prefix string, k int) {
	for range k {
		hs, err := tlog.StoredHashes(l.n, []byte(fmt.Sprintf("%s %d", prefix, l.n)), l.hashes)
		if err != nil {
			l.t.Fatal(err)
		}
		l.hashes = append(l.hashes, hs...)
		l.n++
	}
}

// divergent returns a log that signs with f.log's key but whose tree is built
// from different leaves: the same log, telling a different story.
func (f *fixture) divergent(prefix string, n int) *testLog {
	f.t.Helper()
	d := &testLog{t: f.t, signer: f.log.signer, vkey: f.log.vkey}
	d.growWith(prefix, n)
	return d
}

// register adds or replaces a log in the fixture's registry.
func (f *fixture) register(l *Log) {
	reg := f.h.cfg.Registry.(*mapRegistry)
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.logs[l.Origin] = l
}

// newNamedKey returns a signer and verifier for a fresh key called name.
func newNamedKey(t *testing.T, name string) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

// expectNoCosignature fails if rec's body carries any signature line at all,
// ours or anybody's.
func expectNoCosignature(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rec.Body.String(), "— ") {
		t.Fatalf("a refusal carried a signature line: %q", rec.Body.String())
	}
}

func (f *fixture) expectHead(size int64, hash tlog.Hash) {
	f.t.Helper()
	rec, err := f.db.Get(testOrigin)
	if err != nil {
		f.t.Fatal(err)
	}
	if rec == nil || rec.Size != size || rec.Hash != hash {
		f.t.Fatalf("stored head %+v, want size %d hash %v", rec, size, hash)
	}
}

func (f *fixture) expectNotForked() {
	f.t.Helper()
	if forked, _ := f.db.IsForked(testOrigin); forked {
		f.t.Fatal("recorded a fork")
	}
}

func treeHash(t *testing.T, l *testLog, n int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(n, l.hashes)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Spec: "A log MUST not sign any checkpoint which is inconsistent with any
// checkpoint it previously signed. Two checkpoints are inconsistent if a
// consistency proof can't be constructed from one to the other."
//
// The witness exists to catch a log breaking this. Each subtest is one shape
// of inconsistency, and in none of them may the witness cosign the second
// checkpoint.
func TestSpecCheckpointInconsistentCheckpointsAreNotCosigned(t *testing.T) {
	// Two different roots at one size: no consistency proof can exist between
	// them in either direction, and both carry the log's signature, so this is
	// conclusive, persisted as a fork, and answered with the tlog-witness 409.
	t.Run("same size, different root", func(t *testing.T) {
		f := newFixture(t, 0)
		f.seed(3)
		honest := treeHash(t, f.log, 3)
		first := f.log.checkpoint(3)

		other := f.divergent("other", 3)
		second := other.checkpoint(3)
		rec := f.post(body(3, nil, second))
		f.expectConflict(rec, 3)
		expectNoCosignature(t, rec)

		if forked, _ := f.db.IsForked(testOrigin); !forked {
			t.Fatal("a signed split view was not recorded as a fork")
		}
		f.expectHead(3, honest)

		forks, err := f.db.Forks()
		if err != nil {
			t.Fatal(err)
		}
		if len(forks) != 1 {
			t.Fatalf("%d forks recorded, want 1", len(forks))
		}
		// The evidence must stand on its own: both notes, each verifying under
		// the log's key, same size, different roots.
		ev := forks[0]
		var cps [2]torchwood.Checkpoint
		for i, signed := range [][]byte{ev.PrevSigned, ev.NextSigned} {
			n, err := note.Open(signed, note.VerifierList(f.log.vkey))
			if err != nil {
				t.Fatalf("fork evidence note %d does not verify under the log's key: %v", i, err)
			}
			cp, err := torchwood.ParseCheckpoint(n.Text)
			if err != nil {
				t.Fatal(err)
			}
			cps[i] = cp
		}
		if cps[0].N != 3 || cps[1].N != 3 || cps[0].Hash == cps[1].Hash {
			t.Fatalf("evidence is not a same-size contradiction: %v vs %v", cps[0].Tree, cps[1].Tree)
		}
		if cps[0].Hash != honest || cps[1].Hash != treeHash(t, other, 3) {
			t.Fatal("evidence does not name the two roots the log signed")
		}
		if !bytes.Equal(ev.NextSigned, second) {
			t.Fatal("evidence does not hold the second checkpoint exactly as the log sent it")
		}
		n, _ := note.Open(ev.PrevSigned, note.VerifierList(f.log.vkey))
		if want, _ := note.Open(first, note.VerifierList(f.log.vkey)); n.Text != want.Text {
			t.Fatal("prev evidence is not the checkpoint we witnessed")
		}

		// Asked again, the witness still never cosigns the second root, and now
		// answers as for any forked log: 403, not a 409 that would invite the
		// log to retry forever.
		rec = f.post(body(3, nil, second))
		expect(t, rec, http.StatusForbidden)
		expectNoCosignature(t, rec)
		// And the honest log gets nothing more from us either.
		f.log.grow(2)
		rec = f.post(body(3, f.log.proof(3, 5), f.log.checkpoint(5)))
		expect(t, rec, http.StatusForbidden)
		expectNoCosignature(t, rec)
		f.expectHead(3, honest)
	})

	// A larger checkpoint whose tree does not extend the one we witnessed. The
	// log can hand us only the proof it can build from its own (divergent)
	// tree, and that proof does not check against the root we hold.
	//
	// This is a 422 and NOT a fork on the push path: the proof is supplied by
	// the client, not signed by the log, so its failing proves only that this
	// proof is wrong — a buggy client sending a bad proof for an honest log
	// looks identical (TestInvalidProofIsNotAFork). Poisoning the log on it would
	// let any client get any log permanently refused. What the spec requires of
	// us — never cosign it — holds either way.
	t.Run("larger size, does not extend", func(t *testing.T) {
		f := newFixture(t, 0)
		f.seed(3)
		honest := treeHash(t, f.log, 3)

		// Shares leaf 0 with the honest tree, diverges from leaf 1 on, so no
		// proof from the honest size-3 tree to it exists.
		div := &testLog{t: t, signer: f.log.signer, vkey: f.log.vkey}
		div.growWith("leaf", 1)
		div.growWith("divergent", 7)
		if treeHash(t, div, 3) == honest {
			t.Fatal("test setup: trees did not diverge")
		}
		rec := f.post(body(3, div.proof(3, 8), div.checkpoint(8)))
		expect(t, rec, http.StatusUnprocessableEntity)
		expectNoCosignature(t, rec)
		f.expectHead(3, honest)
		f.expectNotForked()

		// Nor is any other proof accepted in its place: an empty one, or the
		// honest log's proof to its own size 8 paired with the divergent root.
		expect(t, f.post(body(3, nil, div.checkpoint(8))), http.StatusUnprocessableEntity)
		f.log.grow(5)
		expect(t, f.post(body(3, f.log.proof(3, 8), div.checkpoint(8))), http.StatusUnprocessableEntity)
		f.expectHead(3, honest)
	})

	// A checkpoint smaller than one we cosigned. Whether or not it is a prefix
	// of the larger one, the witness never re-signs history. On the push path
	// it never reaches the core: tlog-witness fixes old to our size, so a
	// rollback is either old > checkpoint size (400) or a stale old (409).
	t.Run("rollback", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			signed func(f *fixture) []byte
		}{
			{"prefix of what we witnessed", func(f *fixture) []byte { return f.log.checkpoint(3) }},
			{"not a prefix", func(f *fixture) []byte { return f.divergent("rolled", 3).checkpoint(3) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, 0)
				f.seed(3)
				f.log.grow(5)
				f.expectCosigned(f.post(body(3, f.log.proof(3, 8), f.log.checkpoint(8))), f.log.text(8, ""))
				head := treeHash(t, f.log, 8)
				small := tc.signed(f)

				rec := f.post(body(8, nil, small))
				expect(t, rec, http.StatusBadRequest)
				expectNoCosignature(t, rec)
				for _, old := range []int64{0, 3} {
					rec := f.post(body(old, nil, small))
					f.expectConflict(rec, 8)
				}
				f.expectHead(8, head)
				// Not a fork: the push path has no proof either way about a
				// smaller tree, and absence of a proof is not evidence.
				f.expectNotForked()
			})
		}
	})
}

// Spec: "The log's key name in its signature line SHOULD match the origin
// line."
//
// SHOULD, not MUST: a client may not reject a log for it. witness-network
// lists allow exactly this via an explicit `origin` line.
func TestSpecCheckpointKeyNameNeedNotMatchOrigin(t *testing.T) {
	f := newFixture(t, 0)
	s, v := newNamedKey(t, "signer.example/some-other-name")
	if v.Name() == testOrigin {
		t.Fatal("test setup: key name matches origin")
	}
	f.log.signer, f.log.vkey = s, v
	f.register(&Log{Origin: testOrigin, Verifier: v})

	f.seed(3) // cosigned
	f.log.grow(2)
	f.expectCosigned(f.post(body(3, f.log.proof(3, 5), f.log.checkpoint(5))), f.log.text(5, ""))

	// The line itself does carry the key's name, not the origin.
	if !bytes.Contains(f.log.checkpoint(5), []byte("\n— signer.example/some-other-name ")) {
		t.Fatal("test setup: signature line is not under the key's own name")
	}
}

// The flip side of the clause above: what binds a key to an origin is the
// registry, not the name on the signature line. A checkpoint that claims
// another registered log's origin but is signed with this log's key is
// verified against the other log's key, and fails.
func TestSpecCheckpointOriginIsBoundToItsOwnKey(t *testing.T) {
	f := newFixture(t, 0)
	const otherOrigin = "example.com/other"
	otherSigner, otherV := newNamedKey(t, otherOrigin)
	f.register(&Log{Origin: otherOrigin, Verifier: otherV})

	f.log.grow(2)
	claimOther := strings.Replace(f.log.text(2, ""), testOrigin, otherOrigin, 1)
	rec := f.post(body(0, nil, signNote(t, claimOther, f.log.signer)))
	expect(t, rec, http.StatusForbidden)
	expectNoCosignature(t, rec)

	claimOurs := f.log.text(2, "")
	rec = f.post(body(0, nil, signNote(t, claimOurs, otherSigner)))
	expect(t, rec, http.StatusForbidden)
	expectNoCosignature(t, rec)

	for _, o := range []string{testOrigin, otherOrigin} {
		if r, _ := f.db.Get(o); r != nil {
			t.Fatalf("stored a head for %s from a checkpoint its key did not sign", o)
		}
	}
}

// Spec: "Logs SHOULD use ML-DSA-44 cosignatures to sign the checkpoint, but
// MAY use any note signature algorithm based on the ecosystem they operate in.
// Note that the ML-DSA-44 cosignature format doesn't sign the extension lines,
// which SHOULD be empty."
//
// That is the draft wording this test was written against. The published
// c2sp.org/tlog-checkpoint (2026-09-30) instead says logs "SHOULD use Ed25519
// signatures … but MAY use any note signature algorithm", and calls extension
// lines NOT RECOMMENDED. Nothing tested here depends on the difference.
//
// Our own cosignature is cosignature/v1 (Ed25519), which signs the whole
// checkpoint body, extension lines included. So a checkpoint with extension
// lines is cosigned, and our cosignature commits to them: change one and it no
// longer verifies.
func TestSpecCheckpointCosignatureCoversExtensionLines(t *testing.T) {
	f := newFixture(t, 0)
	f.log.grow(3)
	text := f.log.text(3, "ext-a\next-b\n")
	rec := f.post(body(0, nil, signNote(t, text, f.log.signer)))
	f.expectCosigned(rec, text)
	ours := rec.Body.String()

	for name, altered := range map[string]string{
		"extension changed": f.log.text(3, "ext-a\next-c\n"),
		"extension dropped": f.log.text(3, "ext-a\n"),
		"extensions gone":   f.log.text(3, ""),
		"extension added":   f.log.text(3, "ext-a\next-b\next-d\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := note.Open([]byte(altered+"\n"+ours), note.VerifierList(f.signer.Verifier())); err == nil {
				t.Fatalf("our cosignature still verifies over altered text %q", altered)
			}
		})
	}
}

// mldsaVKey mirrors the loglist test helper: a syntactically valid ML-DSA-44
// vkey (type 0x06, 1312-byte key) with a correct key ID.
func mldsaVKey(t *testing.T, name string) string {
	t.Helper()
	key := make([]byte, 1+1312)
	key[0] = 0x06
	if _, err := rand.Read(key[1:]); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte(name+"\n"), key...))
	return name + "+" + hex.EncodeToString(h[:4]) + "+" + base64.StdEncoding.EncodeToString(key)
}

// Same clause, the log's side: a log signing with ML-DSA-44 is one we cannot
// verify today, since note.NewVerifier has no ML-DSA-44 support. The list
// fetcher skips such logs (loglist.TestFetchSkipsUnverifiableKeys, and
// Registry.Load for stored ones — both refuse to build a push.Log without a
// verifier). Here, at the push boundary: even if one reached the registry
// without a verifier, it is refused as unknown rather than cosigned on the
// strength of nothing.
func TestSpecCheckpointUnverifiableKeyIsNeverCosigned(t *testing.T) {
	const pqOrigin = "pq.example/log"
	vkey := mldsaVKey(t, pqOrigin)
	if _, err := note.NewVerifier(vkey); err == nil {
		t.Fatal("note.NewVerifier now accepts ML-DSA-44 keys; revisit loglist's skip and this test")
	}

	f := newFixture(t, 0)
	f.register(&Log{Origin: pqOrigin, VKey: vkey})
	f.log.grow(1)
	text := strings.Replace(f.log.text(1, ""), testOrigin, pqOrigin, 1)
	// Whatever signature it carries — here a plausible Ed25519 one under the
	// same name — it must not be cosigned.
	s, _ := newNamedKey(t, pqOrigin)
	rec := f.post(body(0, nil, signNote(t, text, s)))
	expect(t, rec, http.StatusNotFound)
	expectNoCosignature(t, rec)
	if r, _ := f.db.Get(pqOrigin); r != nil {
		t.Fatal("stored a head for a log whose key we cannot verify")
	}
}

// Spec: "According to the note specification, clients MUST ignore unknown
// signatures. This enables, for example, log key rotation, and witness
// cosigning."
//
// Ignored in both senses: they neither block the cosignature nor get echoed
// back. Our 200 body is our line alone.
func TestSpecCheckpointUnknownSignaturesAreIgnored(t *testing.T) {
	unknown, _ := newNamedKey(t, "unknown.example/key")
	rotated, _ := newNamedKey(t, testOrigin) // same name, different key hash
	_, peerPriv, _ := ed25519.GenerateKey(nil)
	peer, err := torchwood.NewCosignatureSigner("peer.test", peerPriv)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		signers func(f *fixture) []note.Signer
		first   string // the name expected on the note's first signature line
	}{
		{"unknown key after the log's", func(f *fixture) []note.Signer {
			return []note.Signer{f.log.signer, unknown}
		}, testOrigin},
		{"another witness's cosignature", func(f *fixture) []note.Signer {
			return []note.Signer{f.log.signer, peer}
		}, testOrigin},
		{"rotated-out log key before the log's", func(f *fixture) []note.Signer {
			return []note.Signer{rotated, f.log.signer}
		}, testOrigin},
		{"unknown key before the log's", func(f *fixture) []note.Signer {
			return []note.Signer{unknown, f.log.signer}
		}, "unknown.example/key"},
		{"all of them, log's last", func(f *fixture) []note.Signer {
			return []note.Signer{unknown, peer, rotated, f.log.signer}
		}, "unknown.example/key"},
		// A note that already carries a cosignature of ours (the log re-pushing
		// what we returned last time) gets exactly one line of ours back, not
		// the stale one alongside a fresh one.
		{"our own earlier cosignature", func(f *fixture) []note.Signer {
			return []note.Signer{f.log.signer, f.signer}
		}, testOrigin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 0)
			f.log.grow(2)
			text := f.log.text(2, "")
			signed, err := note.Sign(&note.Note{Text: text}, tc.signers(f)...)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(signed, []byte("\n\n— "+tc.first+" ")) {
				t.Fatalf("test setup: signature order not as intended:\n%s", signed)
			}
			rec := f.post(body(0, nil, signed))
			f.expectCosigned(rec, text) // exactly one line, ours, verifying
			for _, other := range []string{"unknown.example/key", "peer.test", testOrigin} {
				if strings.Contains(rec.Body.String(), "— "+other+" ") {
					t.Fatalf("echoed %s's signature: %q", other, rec.Body.String())
				}
			}
		})
	}

	// Ignoring unknown signatures does not mean accepting a note that has
	// nothing but: the log's own must be there.
	t.Run("only unknown signatures", func(t *testing.T) {
		f := newFixture(t, 0)
		f.log.grow(2)
		signed, err := note.Sign(&note.Note{Text: f.log.text(2, "")}, unknown, rotated, peer)
		if err != nil {
			t.Fatal(err)
		}
		rec := f.post(body(0, nil, signed))
		expect(t, rec, http.StatusForbidden)
		expectNoCosignature(t, rec)
		if r, _ := f.db.Get(testOrigin); r != nil {
			t.Fatal("stored a head from a checkpoint the log did not sign")
		}
	})
}
