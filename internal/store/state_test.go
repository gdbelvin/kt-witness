package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSourceStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.SourceState("a"); err != nil || got != nil {
		t.Fatalf("unset state: %q %v", got, err)
	}
	if err := s.PutSourceState("a", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSourceState("a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, _ := s.SourceState("a"); !bytes.Equal(got, []byte("two")) {
		t.Fatalf("after reopen: %q", got)
	}
	if got, _ := s.SourceState("b"); got != nil {
		t.Fatalf("other origin: %q", got)
	}
}
