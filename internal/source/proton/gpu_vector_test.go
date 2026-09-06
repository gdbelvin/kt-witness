package proton

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"os"
	"sort"
	"testing"
)

// TestWriteGPUVector emits a synthetic tree dump and the root this package
// computes for it, so an independent implementation can be checked against the
// one that is already trusted in production.
//
// Skipped unless KT_GPU_VECTOR names an output path: it exists to produce
// evidence for a cross-implementation comparison, not to test this package.
//
// Random labels are the right input despite looking lazy. The expensive and
// error-prone part of the construction is the fold from depth 256 up to
// wherever a leaf stops being alone, and random labels put that boundary at a
// different depth for every leaf — including, at these sizes, occasional deep
// collisions that exercise the recursion rather than the shortcut.
func TestWriteGPUVector(t *testing.T) {
	path := os.Getenv("KT_GPU_VECTOR")
	if path == "" {
		t.Skip("set KT_GPU_VECTOR=<path> to emit a vector")
	}
	n := 20000
	if v := os.Getenv("KT_GPU_VECTOR_N"); v != "" {
		if _, err := os.Stat(v); err != nil { // not a path; treat as a count
			var parsed int
			for _, c := range v {
				parsed = parsed*10 + int(c-'0')
			}
			if parsed > 0 {
				n = parsed
			}
		}
	}

	rng := rand.New(rand.NewSource(20260906))
	buf := make([]byte, n*entrySize)
	for i := 0; i < n; i++ {
		rec := buf[i*entrySize:]
		rng.Read(rec[:labelSize])
		// A realistic label is VRF(email)[0:28] || uint32be(revision), so the
		// last four bytes are small and highly repetitive across the corpus.
		// Reproduce that: it is what makes deep common prefixes possible.
		binary.BigEndian.PutUint32(rec[labelSize-4:labelSize], uint32(rng.Intn(3)))
		rng.Read(rec[labelSize : labelSize+valueSize])
	}
	recs := make([][]byte, n)
	for i := range recs {
		recs[i] = buf[i*entrySize : (i+1)*entrySize]
	}
	sort.Slice(recs, func(a, b int) bool {
		return string(recs[a][:labelSize]) < string(recs[b][:labelSize])
	})
	out := make([]byte, 0, len(buf))
	for _, r := range recs {
		out = append(out, r...)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}

	root, err := TreeRootParallel(SliceLeaves(out), 4)
	if err != nil {
		t.Fatal(err)
	}
	// Sharded and unsharded must already agree; if they do not, the vector is
	// worthless and the bug is here rather than in whatever reads it.
	plain, err := TreeRoot(SliceLeaves(out))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(root) != hex.EncodeToString(plain) {
		t.Fatalf("sharded %x != unsharded %x", root, plain)
	}
	t.Logf("leaves=%d file=%s root=%s", n, path, hex.EncodeToString(root))
}
