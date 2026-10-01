package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/signalaudit"
)

func frame(msgs ...[]byte) []byte {
	var out []byte
	for _, m := range msgs {
		out = binary.AppendUvarint(out, uint64(len(m)))
		out = append(out, m...)
	}
	return out
}

// Splitting Signal's vectors into two delimited files and replaying them in two
// runs through -state must end on the vectors' final root: the state file is a
// faithful resume point.
func TestStreamResumeFromState(t *testing.T) {
	path := os.Getenv("SIGNAL_AUDITOR_VECTORS")
	if path == "" {
		t.Skip("SIGNAL_AUDITOR_VECTORS not set; see internal/signalaudit package docs")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signalaudit.DecodeVectors(b)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	half := len(v.ShouldSucceed) / 2
	var a, c [][]byte
	for i, st := range v.ShouldSucceed {
		if i < half {
			a = append(a, st.Update)
		} else {
			c = append(c, st.Update)
		}
	}
	files := []string{filepath.Join(dir, "a.bin"), filepath.Join(dir, "b.bin")}
	os.WriteFile(files[0], frame(a...), 0o644)
	os.WriteFile(files[1], frame(c...), 0o644)
	statePath := filepath.Join(dir, "state.json")

	for _, f := range files {
		var s signalaudit.State
		if err := load(statePath, &s); err != nil {
			t.Fatal(err)
		}
		if err := replayStream(f, &s); err != nil {
			t.Fatal(err)
		}
		if err := save(statePath, &s); err != nil {
			t.Fatal(err)
		}
	}
	var s signalaudit.State
	if err := load(statePath, &s); err != nil {
		t.Fatal(err)
	}
	root, _ := s.LogRoot()
	if want := v.ShouldSucceed[len(v.ShouldSucceed)-1].LogRoot; s.Size() != uint64(len(v.ShouldSucceed)) || root != want {
		t.Fatalf("after resume: size %d root %x, want %d %x", s.Size(), root, len(v.ShouldSucceed), want)
	}
}

func TestStreamFraming(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"truncated message":  {0x05, 0x01, 0x02},
		"oversized length":   binary.AppendUvarint(nil, maxUpdate+1),
		"truncated length":   {0x80},
		"undecodable update": frame([]byte{0xff}),
	}
	for name, b := range cases {
		p := filepath.Join(dir, "x.bin")
		os.WriteFile(p, b, 0o644)
		var s signalaudit.State
		if err := replayStream(p, &s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := filepath.Join(dir, "empty.bin")
	os.WriteFile(p, nil, 0o644)
	var s signalaudit.State
	if err := replayStream(p, &s); err != nil || s.Size() != 0 {
		t.Fatalf("empty stream: %v", err)
	}
}
