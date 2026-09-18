package c2sp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/torchwood"
	"github.com/gdbsecurity/kt-witness/internal/source"
	"golang.org/x/mod/sumdb/tlog"
)

// memLog is a tlog-tiles log held in memory: its stored hashes, and the entries
// they were built from, served over HTTP in the layout the fetcher expects.
type memLog struct {
	entries [][]byte
	hashes  []tlog.Hash
}

func newMemLog(n int) *memLog {
	m := &memLog{}
	for i := 0; i < n; i++ {
		entry := fmt.Appendf(nil, "entry %d", i)
		stored, err := tlog.StoredHashes(int64(i), entry, m)
		if err != nil {
			panic(err)
		}
		m.entries = append(m.entries, entry)
		m.hashes = append(m.hashes, stored...)
	}
	return m
}

func (m *memLog) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, ix := range indexes {
		if ix < 0 || ix >= int64(len(m.hashes)) {
			return nil, fmt.Errorf("hash %d not stored", ix)
		}
		out[i] = m.hashes[ix]
	}
	return out, nil
}

func (m *memLog) root(t *testing.T, size int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(size, m)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// serve answers tile requests from the in-memory tree. Tiles are generated on
// demand from whatever coordinates the reader asks for, so the test does not
// depend on guessing which partial widths tlog.TileHashReader will request.
func (m *memLog) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tile, err := torchwood.ParseTilePath(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if tile.L == -1 {
			// Data tile: length-prefixed entries.
			start := tile.N * torchwood.TileWidth
			for i := start; i < start+int64(tile.W) && i < int64(len(m.entries)); i++ {
				var n [2]byte
				binary.BigEndian.PutUint16(n[:], uint16(len(m.entries[i])))
				w.Write(n[:])
				w.Write(m.entries[i])
			}
			return
		}
		data, err := tlog.ReadTileData(tile, m)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newMemSource(t *testing.T, base string, verifyEntries bool) *Source {
	t.Helper()
	// The verifier is only consulted by Fetch; VerifyConsistency works from
	// heads already parsed, so any well-formed key will do.
	const vkey = "thelemail.com/keys+76ead63c+ASduViYkPgYHzuTuDnuTdEkjR/DIprnavuFA3vom4YZT"
	s, err := New(Config{
		Origin:        "test.invalid/log",
		BaseURL:       base + "/",
		VKey:          vkey,
		VerifyEntries: verifyEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// emptyRoot is the hash a checkpoint carries at size 0: SHA-256 of nothing.
func emptyRoot() tlog.Hash { return tlog.Hash(sha256.Sum256(nil)) }

// A log first witnessed empty must be cosignable once it has entries. Every
// tree extends the empty tree, so there is nothing to prove — but the tlog
// library refuses to build a proof from size 0, and treating that refusal as
// "unproven" withheld three real CT shards from the hour they got their first
// entry onward.
func TestGrowthFromEmptyTreeIsConsistent(t *testing.T) {
	log := newMemLog(5)
	srv := log.serve(t)

	for _, verifyEntries := range []bool{false, true} {
		s := newMemSource(t, srv.URL, verifyEntries)
		prev := &source.Head{Origin: s.origin, Size: 0, Hash: emptyRoot()}
		next := &source.Head{Origin: s.origin, Size: 5, Hash: log.root(t, 5)}
		if err := s.VerifyConsistency(context.Background(), prev, next); err != nil {
			t.Errorf("verifyEntries=%v: growth 0->5 must verify, got: %v", verifyEntries, err)
		}
	}
}

// Empty to empty is the hourly refresh of a shard nobody has submitted to yet.
// The witness core skips the proof on a refresh, but the adapter should not
// fail it if asked.
func TestEmptyToEmptyIsConsistent(t *testing.T) {
	s := newMemSource(t, "http://unreachable.invalid", false)
	head := &source.Head{Origin: s.origin, Size: 0, Hash: emptyRoot()}
	if err := s.VerifyConsistency(context.Background(), head, head); err != nil {
		t.Fatalf("0->0 must verify without fetching anything, got: %v", err)
	}
}

// Skipping the proof is not skipping the check: a root the log's own tiles do
// not build to is still refused, exactly as it is on first use.
func TestGrowthFromEmptyTreeStillChecksTiles(t *testing.T) {
	log := newMemLog(5)
	srv := log.serve(t)
	s := newMemSource(t, srv.URL, false)

	prev := &source.Head{Origin: s.origin, Size: 0, Hash: emptyRoot()}
	bogus := log.root(t, 5)
	bogus[0] ^= 0xff
	next := &source.Head{Origin: s.origin, Size: 5, Hash: bogus}
	if err := s.VerifyConsistency(context.Background(), prev, next); err == nil {
		t.Fatal("a root the tiles cannot back must not verify")
	}
}

// The ordinary path is unchanged: a real proof between two non-empty sizes.
func TestGrowthBetweenNonEmptySizesIsConsistent(t *testing.T) {
	log := newMemLog(5)
	srv := log.serve(t)
	s := newMemSource(t, srv.URL, false)

	prev := &source.Head{Origin: s.origin, Size: 2, Hash: log.root(t, 2)}
	next := &source.Head{Origin: s.origin, Size: 5, Hash: log.root(t, 5)}
	if err := s.VerifyConsistency(context.Background(), prev, next); err != nil {
		t.Fatalf("growth 2->5 must verify, got: %v", err)
	}

	// And a genuine contradiction is still a fork, not a plain error.
	wrong := log.root(t, 3)
	prev = &source.Head{Origin: s.origin, Size: 2, Hash: wrong}
	err := s.VerifyConsistency(context.Background(), prev, next)
	if _, ok := err.(*source.ForkError); !ok {
		t.Fatalf("a root at size 2 that size 5 does not extend must be a ForkError, got: %v", err)
	}
}
