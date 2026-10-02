package signalaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/pbwire"
	"github.com/gdbsecurity/kt-witness/internal/source/signal"
)

func snapshot(t testing.TB, s *State) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A generated stream, through the wire and back, replays to the generator's
// independently computed log root at every step.
func TestGeneratedSequence(t *testing.T) {
	ups, roots := sequence(1, 400)
	var s State
	kinds := map[ProofKind]int{}
	maxCopath := 0
	for i, u := range ups {
		d, err := DecodeUpdate(EncodeUpdate(u))
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		if !reflect.DeepEqual(d, u) && !(len(u.Copath) == 0 && d.Copath == nil) {
			t.Fatalf("update %d: wire round trip changed it:\n%+v\n%+v", i, u, d)
		}
		if err := s.Apply(d); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		got, err := s.LogRoot()
		if err != nil || got != roots[i] {
			t.Fatalf("update %d (%v): log root %x, want %x (%v)", i, u.Proof, got, roots[i], err)
		}
		kinds[u.Proof]++
		maxCopath = max(maxCopath, len(u.Copath))
	}
	t.Logf("%d updates: %v; deepest copath %d", len(ups), kinds, maxCopath)
	for _, k := range []ProofKind{NewTree, DifferentKey, SameKey} {
		if kinds[k] == 0 {
			t.Fatalf("generator produced no %v updates", k)
		}
	}
}

// --- malformed input --------------------------------------------------------

type rawField struct {
	num  int
	wire byte
	v    uint64
	b    []byte
}

func raw(fs ...rawField) []byte {
	var out []byte
	for _, f := range fs {
		out = pbwire.AppendTag(out, f.num, f.wire)
		if f.wire == 0 {
			out = pbwire.AppendVarint(out, f.v)
		} else {
			out = pbwire.AppendVarint(out, uint64(len(f.b)))
			out = append(out, f.b...)
		}
	}
	return out
}

func vb(num int, v uint64) rawField { return rawField{num: num, wire: 0, v: v} }
func bb(num int, b []byte) rawField { return rawField{num: num, wire: 2, b: b} }
func n(k int) []byte                { return make([]byte, k) }
func copathN(k, size int) []rawField {
	out := make([]rawField, k)
	for i := range out {
		out[i] = bb(1, n(size))
	}
	return out
}

func TestDecodeRejectsMalformed(t *testing.T) {
	dk := raw(append(copathN(2, 32), bb(2, n(16)))...)
	sk := raw(append(copathN(2, 32), vb(2, 3), vb(3, 1))...)
	head := []rawField{vb(1, 1), bb(2, n(32)), bb(3, n(16)), bb(4, n(32))}
	upd := func(proof []byte, extra ...rawField) []byte {
		return raw(append(append(append([]rawField{}, head...), bb(5, proof)), extra...)...)
	}
	good := upd(raw(bb(3, dk)))
	if _, err := DecodeUpdate(good); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	if _, err := DecodeUpdate(upd(raw(bb(4, sk)))); err != nil {
		t.Fatalf("same_key baseline rejected: %v", err)
	}

	cases := map[string][]byte{
		"empty":                    nil,
		"truncated":                good[:len(good)-1],
		"trailing garbage":         append(append([]byte{}, good...), 0xff),
		"field number 0":           append([]byte{0x00, 0x00}, good...),
		"group wire type":          append([]byte{0x0b}, good...),
		"varint overflow":          append([]byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, good...),
		"length past end":          append(append([]byte{}, good...), 0x12, 0x40, 0x00),
		"index 31 bytes":           raw(vb(1, 1), bb(2, n(31)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"index 33 bytes":           raw(vb(1, 1), bb(2, n(33)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"index missing":            raw(vb(1, 1), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"seed 32 bytes":            raw(vb(1, 1), bb(2, n(32)), bb(3, n(32)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"seed missing":             raw(vb(1, 1), bb(2, n(32)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"commitment 16 bytes":      raw(vb(1, 1), bb(2, n(32)), bb(3, n(16)), bb(4, n(16)), bb(5, raw(bb(3, dk)))),
		"proof missing":            raw(head...),
		"proof empty":              upd(nil),
		"proof unknown variant":    upd(raw(bb(2, nil))),
		"proof two variants":       upd(raw(bb(1, nil), bb(3, dk))),
		"proof variant not bytes":  upd(raw(vb(3, 1))),
		"proof twice":              upd(raw(bb(3, dk)), bb(5, raw(bb(3, dk)))),
		"index twice":              upd(raw(bb(3, dk)), bb(2, n(32))),
		"real twice":               upd(raw(bb(3, dk)), vb(1, 1)),
		"real = 2":                 raw(vb(1, 2), bb(2, n(32)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"real as bytes":            raw(bb(1, []byte{1}), bb(2, n(32)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"index as varint":          raw(vb(1, 1), vb(2, 7), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(3, dk)))),
		"fake new_tree":            raw(bb(2, n(32)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(1, nil)))),
		"fake same_key":            raw(bb(2, n(32)), bb(3, n(16)), bb(4, n(32)), bb(5, raw(bb(4, sk)))),
		"dk copath empty":          upd(raw(bb(3, raw(bb(2, n(16)))))),
		"dk copath 257":            upd(raw(bb(3, raw(append(copathN(257, 32), bb(2, n(16)))...)))),
		"sk copath 257":            upd(raw(bb(4, raw(copathN(257, 32)...)))),
		"copath entry 31 bytes":    upd(raw(bb(3, raw(bb(1, n(32)), bb(1, n(31)), bb(2, n(16)))))),
		"copath entry 33 bytes":    upd(raw(bb(3, raw(bb(1, n(33)), bb(2, n(16)))))),
		"copath entry as varint":   upd(raw(bb(3, raw(vb(1, 5), bb(2, n(16)))))),
		"old_seed missing":         upd(raw(bb(3, raw(copathN(1, 32)...)))),
		"old_seed 32 bytes":        upd(raw(bb(3, raw(bb(1, n(32)), bb(2, n(32)))))),
		"old_seed twice":           upd(raw(bb(3, raw(bb(1, n(32)), bb(2, n(16)), bb(2, n(16)))))),
		"counter over uint32":      upd(raw(bb(4, raw(vb(2, math.MaxUint32+1))))),
		"counter as bytes":         upd(raw(bb(4, raw(bb(2, n(4)))))),
		"position twice":           upd(raw(bb(4, raw(vb(3, 1), vb(3, 2))))),
		"truncated proof body":     upd(raw(bb(3, dk[:len(dk)-1]))),
		"garbage in new_tree body": upd(raw(bb(1, []byte{0xff}))),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeUpdate(b)
			var me *MalformedError
			if !errors.As(err, &me) {
				t.Fatalf("got %v, want *MalformedError", err)
			}
		})
	}

	// Unknown fields are skipped, at every level, as protobuf requires.
	ext := upd(raw(bb(3, raw(append(copathN(2, 32), bb(2, n(16)), vb(9, 1))...)), bb(7, n(3))), vb(15, 4))
	got, err := DecodeUpdate(ext)
	if err != nil {
		t.Fatalf("unknown fields rejected: %v", err)
	}
	want, _ := DecodeUpdate(good)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("unknown fields changed the decoded update")
	}
}

// A hand-built Update gets the same rules as a decoded one.
func TestApplyRejectsMalformedStruct(t *testing.T) {
	ups, _ := sequence(2, 5)
	var s State
	if err := s.Apply(ups[0]); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, &s)
	bad := map[string]Update{
		"no proof kind":      {Real: true},
		"unknown proof kind": {Real: true, Proof: 2},
		"dk empty copath":    {Real: true, Proof: DifferentKey},
		"dk 257 copath":      {Real: true, Proof: DifferentKey, Copath: make([][32]byte, 257)},
		"sk 257 copath":      {Real: true, Proof: SameKey, Copath: make([][32]byte, 257)},
		"new_tree copath":    {Real: true, Proof: NewTree, Copath: make([][32]byte, 1)},
		"fake new_tree":      {Proof: NewTree},
		"fake same_key":      {Proof: SameKey},
	}
	for name, u := range bad {
		err := s.Apply(u)
		var me *MalformedError
		if !errors.As(err, &me) {
			t.Errorf("%s: got %v, want *MalformedError", name, err)
		}
		if !bytes.Equal(before, snapshot(t, &s)) {
			t.Fatalf("%s: state changed", name)
		}
	}
}

// --- transitions refused by state ------------------------------------------

func TestProofErrors(t *testing.T) {
	ups, _ := sequence(3, 40)
	var firstDK, firstSK Update
	for _, u := range ups {
		if u.Proof == DifferentKey && firstDK.Proof == 0 {
			firstDK = u
		}
		if u.Proof == SameKey && firstSK.Proof == 0 {
			firstSK = u
		}
	}

	expectProof := func(t *testing.T, s *State, u Update) {
		t.Helper()
		before := snapshot(t, s)
		err := s.Apply(u)
		var pe *ProofError
		if !errors.As(err, &pe) {
			t.Fatalf("got %v, want *ProofError", err)
		}
		if pe.Pos != s.Size() {
			t.Fatalf("ProofError.Pos %d, state size %d", pe.Pos, s.Size())
		}
		if !bytes.Equal(before, snapshot(t, s)) {
			t.Fatal("state changed after a rejected update")
		}
	}

	t.Run("different_key on empty", func(t *testing.T) { expectProof(t, &State{}, firstDK) })
	t.Run("same_key on empty", func(t *testing.T) { expectProof(t, &State{}, firstSK) })
	t.Run("second new_tree", func(t *testing.T) {
		var s State
		if err := s.Apply(ups[0]); err != nil {
			t.Fatal(err)
		}
		expectProof(t, &s, ups[0])
	})
	t.Run("replay of an applied update", func(t *testing.T) {
		// Re-sending an update after it applied: its proof was against the
		// previous root, so it no longer verifies.
		var s State
		for i, u := range ups {
			if err := s.Apply(u); err != nil {
				t.Fatal(err)
			}
			if i > 0 {
				expectProof(t, &s, u)
			}
		}
	})
	t.Run("counter overflow", func(t *testing.T) {
		// A tree whose only key is already at the maximum counter.
		var idx [32]byte
		var seed [16]byte
		s := State{prefixRoot: realRoot(idx, math.MaxUint32, 0, nil, seed)}
		if err := s.log.Append([32]byte{}); err != nil {
			t.Fatal(err)
		}
		u := Update{Real: true, Index: idx, Seed: seed, Proof: SameKey, Counter: math.MaxUint32}
		expectProof(t, &s, u)
		// The same key one below the limit is fine, which shows the proof
		// itself was valid and the overflow is what was refused.
		s.prefixRoot = realRoot(idx, math.MaxUint32-1, 0, nil, seed)
		u.Counter = math.MaxUint32 - 1
		if err := s.Apply(u); err != nil {
			t.Fatal(err)
		}
	})
}

// --- mutation ---------------------------------------------------------------

type mutOutcome struct{ rejected, changed, inert int }

// scaled trims the mutation tests' sequence length under -short; they apply
// hundreds of thousands of updates, which -race makes slow.
func scaled(n int) int {
	if testing.Short() {
		return n / 5
	}
	return n
}

// inert reports whether mut differs from orig only in bits the protocol does
// not bind, so that accepting it with an unchanged root is correct rather than
// a missed check. There are exactly two such cases:
//
//   - a fake DifferentKey's index beyond the copath: a fake update replaces a
//     stand-in at depth len(copath), and only the first len(copath) bits of the
//     index say where that is. The rest of a fake index is random filler.
//   - the seed, when the copath is a full 256 entries: no stand-in is
//     generated, so the seed is never used.
func inert(orig, mut Update) bool {
	o, m := orig, mut
	if o.Proof == DifferentKey && !o.Real && m.Proof == DifferentKey && !m.Real && len(m.Copath) == len(o.Copath) {
		for i := len(o.Copath); i < 256; i++ {
			mask := byte(1) << (7 - i%8)
			o.Index[i/8] &^= mask
			m.Index[i/8] &^= mask
		}
	}
	if len(o.Copath) == MaxCopath && len(m.Copath) == MaxCopath && o.Proof != NewTree {
		o.Seed, m.Seed = [16]byte{}, [16]byte{}
	}
	return reflect.DeepEqual(o, m)
}

// mutate applies mut to a copy of before and classifies what happened. Any
// acceptance that leaves the log root where an honest update would have put it
// is a failure unless the change is inert.
func mutate(t *testing.T, before *State, before0 []byte, orig, mut Update, want [32]byte, out *mutOutcome) {
	t.Helper()
	s := before.Clone()
	if err := s.Apply(mut); err != nil {
		var pe *ProofError
		var me *MalformedError
		if !errors.As(err, &pe) && !errors.As(err, &me) {
			t.Fatalf("untyped error %v", err)
		}
		if !bytes.Equal(before0, snapshot(t, &s)) {
			t.Fatalf("rejected update changed the state")
		}
		out.rejected++
		return
	}
	got, err := s.LogRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		out.changed++
		return
	}
	if !inert(orig, mut) {
		t.Fatalf("mutated %v update accepted with the honest root:\norig %+v\nmut  %+v", orig.Proof, orig, mut)
	}
	out.inert++
}

func flipEach(b []byte, f func()) {
	for i := range b {
		m := byte(1) << (i % 8)
		b[i] ^= m
		f()
		b[i] ^= m
	}
}

// Every byte of every field of every update in a generated stream, one bit at
// a time, plus structural changes: a mutated update must be rejected or move
// the log root, and a rejected one must leave the state untouched.
func TestMutationGenerated(t *testing.T) {
	ups, roots := sequence(4, scaled(150))
	var s State
	var out mutOutcome
	for i, u := range ups {
		before0 := snapshot(t, &s)
		try := func(m Update) { mutate(t, &s, before0, u, m, roots[i], &out) }

		m := u
		m.Copath = append([][32]byte(nil), u.Copath...)
		flipEach(m.Index[:], func() { try(m) })
		flipEach(m.Seed[:], func() { try(m) })
		flipEach(m.Commitment[:], func() { try(m) })
		if u.Proof == DifferentKey {
			flipEach(m.OldSeed[:], func() { try(m) })
		}
		for j := range m.Copath {
			flipEach(m.Copath[j][:], func() { try(m) })
		}
		if u.Proof == SameKey {
			for b := 0; b < 32; b++ {
				m.Counter ^= 1 << b
				try(m)
				m.Counter ^= 1 << b
			}
			for b := 0; b < 64; b++ {
				m.Position ^= 1 << b
				try(m)
				m.Position ^= 1 << b
			}
		}
		// Structural: real flag, proof kind, copath one shorter / longer.
		m.Real = !m.Real
		try(m)
		m.Real = u.Real
		for _, k := range []ProofKind{NewTree, DifferentKey, SameKey} {
			if k != u.Proof {
				m.Proof = k
				try(m)
			}
		}
		m.Proof = u.Proof
		if len(u.Copath) > 0 {
			m.Copath = u.Copath[:len(u.Copath)-1]
			try(m)
		}
		if len(u.Copath) < MaxCopath && u.Proof != NewTree {
			m.Copath = append(append([][32]byte(nil), u.Copath...), [32]byte{1})
			try(m)
		}

		if err := s.Apply(u); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}
	t.Logf("struct mutations over %d updates: %d rejected, %d changed the root, %d inert (fake-index tail / unused seed), 0 undetected",
		len(ups), out.rejected, out.changed, out.inert)
}

// One bit of every byte of the wire encoding of every update (rotating which
// bit, so all eight positions are hit across a field). Flips also land on tags
// and lengths, so this exercises the decoder's strictness as well as the
// proofs. TestMutationWireVectors flips every bit of Signal's own updates.
func TestMutationWireGenerated(t *testing.T) {
	ups, roots := sequence(5, scaled(50))
	var s State
	var out mutOutcome
	identical := 0
	for i, u := range ups {
		before0 := snapshot(t, &s)
		w := EncodeUpdate(u)
		for j := range w {
			b := (i + j) % 8
			w[j] ^= 1 << b
			d, err := DecodeUpdate(w)
			switch {
			case err != nil:
				var me *MalformedError
				if !errors.As(err, &me) {
					t.Fatalf("untyped decode error %v", err)
				}
				out.rejected++
			case reflect.DeepEqual(d, u):
				identical++ // a different encoding of the same update
			default:
				mutate(t, &s, before0, u, d, roots[i], &out)
			}
			w[j] ^= 1 << b
		}
		if err := s.Apply(u); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}
	t.Logf("wire bit flips over %d updates: %d rejected, %d changed the root, %d inert, %d decoded to the identical update, 0 undetected",
		len(ups), out.rejected, out.changed, out.inert, identical)
}

// --- persistence ------------------------------------------------------------

func TestStateJSONRoundTrip(t *testing.T) {
	ups, roots := sequence(6, 200)
	var s State
	for i, u := range ups {
		if err := s.Apply(u); err != nil {
			t.Fatal(err)
		}
		// Save and restore at every step; the restored state must carry on
		// to the same roots.
		var r State
		if err := json.Unmarshal(snapshot(t, &s), &r); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		s = r
		if got, _ := s.LogRoot(); got != roots[i] {
			t.Fatalf("step %d: restored root %x, want %x", i, got, roots[i])
		}
	}
	b := snapshot(t, &s)
	t.Logf("state after %d updates: %d bytes of JSON", s.Size(), len(b))

	var empty State
	if err := json.Unmarshal(snapshot(t, &empty), &empty); err != nil || empty.Size() != 0 {
		t.Fatalf("empty state round trip: %v", err)
	}

	bad := []string{
		`{"size":3,"prefix_root":"` + hex64 + `","log_frontier":["` + hex64 + `"]}`,       // 3 needs two subtrees
		`{"size":1,"prefix_root":"` + hex64[:62] + `","log_frontier":["` + hex64 + `"]}`,  // short root
		`{"size":1,"prefix_root":"` + hex64 + `","log_frontier":["zz` + hex64[2:] + `"]}`, // bad hex
		`{"size":1,"log_frontier":["` + hex64 + `"]}`,                                     // missing root
		`{"size":0,"prefix_root":"` + hex64 + `"}`,                                        // root on empty log
		`{"size":"1"}`, // wrong type
	}
	for _, j := range bad {
		var r State
		if err := json.Unmarshal([]byte(j), &r); err == nil {
			t.Errorf("accepted %s", j)
		}
	}
}

const hex64 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// The frontier the state keeps is the one the client-side code verifies
// against: one leaf per update, hashed with signal.LogLeafHash.
func TestLogLeafIsPrefixRootAndCommitment(t *testing.T) {
	ups, _ := sequence(7, 10)
	var s State
	var f signal.LogFrontier
	for _, u := range ups {
		if err := s.Apply(u); err != nil {
			t.Fatal(err)
		}
		p, _ := s.PrefixRoot()
		if err := f.Append(sum(p[:], u.Commitment[:])); err != nil {
			t.Fatal(err)
		}
		a, _ := s.LogRoot()
		b, _ := f.Root()
		if a != b {
			t.Fatal("log root is not the frontier over SHA-256(prefix root || commitment)")
		}
	}
}

// --- benchmarks -------------------------------------------------------------

func benchReplay(b *testing.B, ups []Update) {
	b.ReportAllocs()
	for b.Loop() {
		var s State
		for _, u := range ups {
			if err := s.Apply(u); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.N*len(ups))/b.Elapsed().Seconds(), "updates/s")
}

// BenchmarkApply replays a generated stream with the generator's 40/35/25 mix
// of new keys, fake updates and re-registrations.
func BenchmarkApply(b *testing.B) {
	benchReplay(b, updates(8, 5000))
}

// BenchmarkApplyKind isolates each kind's cost. Copath depth barely matters
// for real updates (the full 256-level path is hashed regardless) and is
// everything for fake ones (only the explored path is hashed).
func BenchmarkApplyKind(b *testing.B) {
	ups := updates(9, 5000)
	for _, k := range []struct {
		name string
		ok   func(Update) bool
	}{
		{"real_different_key", func(u Update) bool { return u.Proof == DifferentKey && u.Real }},
		{"fake_different_key", func(u Update) bool { return u.Proof == DifferentKey && !u.Real }},
		{"same_key", func(u Update) bool { return u.Proof == SameKey }},
	} {
		b.Run(k.name, func(b *testing.B) {
			// Apply each selected update to the state just before it.
			var s State
			var pre []State
			var sel []Update
			for _, u := range ups {
				if k.ok(u) {
					pre = append(pre, s.Clone())
					sel = append(sel, u)
				}
				if err := s.Apply(u); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			i := 0
			for b.Loop() {
				st := pre[i%len(pre)]
				st.log = st.log.Clone()
				if err := st.Apply(sel[i%len(sel)]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

// BenchmarkDecodeApplyVectors replays Signal's own vectors from wire bytes.
func BenchmarkDecodeApplyVectors(b *testing.B) {
	v := loadVectors(b)
	b.ReportAllocs()
	for b.Loop() {
		var s State
		for _, st := range v.ShouldSucceed {
			u, err := DecodeUpdate(st.Update)
			if err != nil {
				b.Fatal(err)
			}
			if err := s.Apply(u); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.N*len(v.ShouldSucceed))/b.Elapsed().Seconds(), "updates/s")
}
