package signalaudit

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
)

// gen is a test-only *writer* of auditor streams: it keeps the whole prefix
// tree in memory, as Signal's service does, and emits the AuditorUpdate an
// honest service would send for each change. It lets every property below be
// checked on long sequences without the AGPL vectors.
//
// Its hashing is written out longhand from the spec rather than calling the
// functions under test, so a shared mistake in a hash preimage would show up as
// a disagreement rather than cancel out.
type gen struct {
	rng  *rand.Rand
	root *gnode
	size uint64
	keys [][32]byte            // real indices, in insertion order
	seed map[[32]byte][16]byte // each real index's insertion seed
	leaf [][32]byte            // log leaves, for the independent log root
}

type gkind uint8

const (
	standIn gkind = iota
	inner
	leafNode
)

type gnode struct {
	kind        gkind
	seed        [16]byte // standIn
	depth       int      // standIn
	left, right *gnode   // inner
	index       [32]byte // leafNode
	ctr         uint32   // leafNode
	pos         uint64   // leafNode

	cached bool
	h      [32]byte
}

func newGen(seed uint64) *gen {
	return &gen{rng: rand.New(rand.NewPCG(seed, seed^0x5eed)), seed: map[[32]byte][16]byte{}}
}

func sum(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return [32]byte(h.Sum(nil))
}

func (n *gnode) hash() [32]byte {
	if n.cached {
		return n.h
	}
	switch n.kind {
	case standIn: // spec: sha256(0x02 || seed || level-1)
		n.h = sum([]byte{2}, n.seed[:], []byte{byte(n.depth - 1)})
	case leafNode: // spec: sha256(0x00 || index || counter || position)
		var c [4]byte
		var p [8]byte
		binary.BigEndian.PutUint32(c[:], n.ctr)
		binary.BigEndian.PutUint64(p[:], n.pos)
		n.h = sum([]byte{0}, n.index[:], c[:], p[:])
	case inner: // spec: sha256(0x01 || left || right)
		l, r := n.left.hash(), n.right.hash()
		n.h = sum([]byte{1}, l[:], r[:])
	}
	n.cached = true
	return n.h
}

func gbit(index [32]byte, d int) int { return int(index[d/8]>>(7-d%8)) & 1 }

func (n *gnode) child(b int) **gnode {
	if b == 0 {
		return &n.left
	}
	return &n.right
}

// subtree is the node at depth d on index's path in a freshly explored region:
// inner nodes down to a leaf at 256, every sibling a stand-in from seed.
func subtree(d int, index [32]byte, seed [16]byte, ctr uint32, pos uint64) *gnode {
	if d == 256 {
		return &gnode{kind: leafNode, index: index, ctr: ctr, pos: pos}
	}
	n := &gnode{kind: inner}
	b := gbit(index, d)
	*n.child(b) = subtree(d+1, index, seed, ctr, pos)
	*n.child(1 - b) = &gnode{kind: standIn, seed: seed, depth: d + 1}
	return n
}

func (g *gen) rand32() (out [32]byte) {
	for i := range out {
		out[i] = byte(g.rng.Uint32())
	}
	return out
}

func (g *gen) rand16() (out [16]byte) {
	for i := range out {
		out[i] = byte(g.rng.Uint32())
	}
	return out
}

// walk follows index from the root, invalidating cached hashes on the way (the
// caller is about to change something below), and returns the copath and the
// slot holding the first non-inner node.
func (g *gen) walk(index [32]byte) ([][32]byte, **gnode) {
	var copath [][32]byte
	slot := &g.root
	for d := 0; (*slot).kind == inner; d++ {
		n := *slot
		n.cached = false
		b := gbit(index, d)
		copath = append(copath, (*n.child(1 - b)).hash())
		slot = n.child(b)
	}
	return copath, slot
}

// freshIndex returns an index not yet in the tree. Half the time it shares a
// long prefix with an existing key, so copaths reach deep into explored
// territory rather than diverging near the root.
func (g *gen) freshIndex() [32]byte {
	for {
		x := g.rand32()
		if len(g.keys) > 0 && g.rng.IntN(2) == 0 {
			x = g.keys[g.rng.IntN(len(g.keys))]
			d := 1 + g.rng.IntN(255)
			x[d/8] ^= 1 << (7 - d%8)
		}
		if _, ok := g.seed[x]; !ok {
			return x
		}
	}
}

func (g *gen) record(u Update) Update {
	g.size++
	r := g.root.hash()
	g.leaf = append(g.leaf, sum(r[:], u.Commitment[:]))
	return u
}

func (g *gen) newTree() Update {
	u := Update{Real: true, Index: g.freshIndex(), Seed: g.rand16(), Commitment: g.rand32(), Proof: NewTree}
	g.root = subtree(0, u.Index, u.Seed, 0, 0)
	g.keys = append(g.keys, u.Index)
	g.seed[u.Index] = u.Seed
	return g.record(u)
}

func (g *gen) differentKey(real bool) Update {
	u := Update{Real: real, Index: g.freshIndex(), Seed: g.rand16(), Commitment: g.rand32(), Proof: DifferentKey}
	copath, slot := g.walk(u.Index)
	old := *slot
	if old.kind != standIn {
		panic("gen: fresh index reached a leaf")
	}
	u.Copath, u.OldSeed = copath, old.seed
	if real {
		*slot = subtree(old.depth, u.Index, u.Seed, 0, g.size)
		g.keys = append(g.keys, u.Index)
		g.seed[u.Index] = u.Seed
	} else {
		*slot = &gnode{kind: standIn, seed: u.Seed, depth: old.depth}
	}
	return g.record(u)
}

func (g *gen) sameKey() Update {
	index := g.keys[g.rng.IntN(len(g.keys))]
	seed := g.seed[index]
	copath, slot := g.walk(index)
	l := *slot
	if l.kind != leafNode || len(copath) != 256 {
		panic("gen: existing key did not reach its leaf")
	}
	// Signal sends only the explored part; trailing siblings that are still
	// this key's own stand-ins are left for the auditor to regenerate.
	n := len(copath)
	for n > 0 && copath[n-1] == sum([]byte{2}, seed[:], []byte{byte(n - 1)}) {
		n--
	}
	u := Update{Real: true, Index: index, Seed: seed, Commitment: g.rand32(), Proof: SameKey,
		Copath: copath[:n], Counter: l.ctr, Position: l.pos}
	l.ctr++
	l.cached = false
	return g.record(u)
}

// next emits a plausible mix: after the first NewTree, new keys, fake updates
// and re-registrations in roughly 40/35/25 proportion.
func (g *gen) next() Update {
	if g.root == nil {
		return g.newTree()
	}
	switch r := g.rng.IntN(100); {
	case r < 40:
		return g.differentKey(true)
	case r < 75:
		return g.differentKey(false)
	default:
		return g.sameKey()
	}
}

// logRoot is the left-balanced root over every leaf so far, by the recursive
// definition (split at the largest power of two below n) rather than a
// frontier, and with the 33-byte node encoding spelled out.
func (g *gen) logRoot() [32]byte {
	var rec func(l [][32]byte) [32]byte
	rec = func(l [][32]byte) [32]byte {
		if len(l) == 1 {
			return l[0]
		}
		k := 1
		for k*2 < len(l) {
			k *= 2
		}
		flag := func(n int) []byte {
			if n > 1 {
				return []byte{1}
			}
			return []byte{0}
		}
		a, b := rec(l[:k]), rec(l[k:])
		return sum(flag(k), a[:], flag(len(l)-k), b[:])
	}
	return rec(g.leaf)
}

// updates generates n updates without computing roots, for benchmarks.
func updates(seed uint64, n int) []Update {
	g := newGen(seed)
	ups := make([]Update, n)
	for i := range ups {
		ups[i] = g.next()
	}
	return ups
}

// sequence generates n updates with the log root expected after each.
func sequence(seed uint64, n int) ([]Update, [][32]byte) {
	g := newGen(seed)
	ups := make([]Update, n)
	roots := make([][32]byte, n)
	for i := range ups {
		ups[i] = g.next()
		roots[i] = g.logRoot()
	}
	return ups, roots
}
