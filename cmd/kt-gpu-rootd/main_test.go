package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{
		"epoch_tree_6730.bin",
		"epoch_tree_6731.bin.partial",
		"epoch_tree_6600.bin.mismatch",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A stub standing in for the CUDA binary, so the HTTP behaviour is
	// testable on a machine with no GPU — which is every machine this repo is
	// developed on.
	stub := filepath.Join(t.TempDir(), "stub.sh")
	os.WriteFile(stub, []byte("#!/bin/sh\necho '{\"root\":\"deadbeef\",\"leaves\":1}'\n"), 0o755)
	return &server{root: dir, bin: stub, log: slog.New(slog.NewTextHandler(os.Stderr, nil))}, dir
}

// TestRefusesPartialAndMismatch pins the rule that matters most here. The
// retained-tree directory holds a half-written `.partial` beside real trees;
// rebuilding one yields a root that matches nothing, and at the far end that is
// indistinguishable from the operator having equivocated. A filename must never
// be able to manufacture that finding.
func TestRefusesPartialAndMismatch(t *testing.T) {
	s, _ := newTestServer(t)
	for _, name := range []string{"epoch_tree_6731.bin.partial", "epoch_tree_6600.bin.mismatch"} {
		if _, err := s.resolve(name); err == nil {
			t.Errorf("%s: accepted, must be refused", name)
		}
	}
	if _, err := s.resolve("epoch_tree_6730.bin"); err != nil {
		t.Errorf("a complete tree was refused: %v", err)
	}
}

func TestPathIsConfinedToTheServedDirectory(t *testing.T) {
	s, dir := newTestServer(t)
	outside := filepath.Join(t.TempDir(), "elsewhere.bin")
	os.WriteFile(outside, []byte("x"), 0o644)

	for _, p := range []string{
		"../../etc/passwd",
		"/etc/passwd",
		outside,
		"subdir/../../../etc/hosts",
	} {
		if got, err := s.resolve(p); err == nil {
			t.Errorf("%s: escaped to %s", p, got)
		}
	}

	// A symlink inside the directory pointing out of it must not work either:
	// the check resolves links before comparing, precisely so that adding a
	// link to the export cannot widen it.
	link := filepath.Join(dir, "sneaky.bin")
	if err := os.Symlink(outside, link); err == nil {
		if got, err := s.resolve("sneaky.bin"); err == nil {
			t.Errorf("symlink escaped to %s", got)
		}
	}
}

func TestUnknownSchemeIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"scheme":"akd-v1","path":"epoch_tree_6730.bin"}`
	rr := httptest.NewRecorder()
	s.handleRoot(rr, httptest.NewRequest(http.MethodPost, "/root", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown scheme: got %d, want 400", rr.Code)
	}
}

func TestRootPassesTheRebuildOutputThrough(t *testing.T) {
	s, _ := newTestServer(t)
	body := `{"path":"epoch_tree_6730.bin"}`
	rr := httptest.NewRecorder()
	s.handleRoot(rr, httptest.NewRequest(http.MethodPost, "/root", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not the rebuild JSON: %v", err)
	}
	if out["root"] != "deadbeef" {
		t.Errorf("root not passed through: %v", out["root"])
	}
}

// TestBusyReturns503: the card holds one 20 GB tree at a time, so a second
// caller is told to come back rather than being allowed to abort the first.
func TestBusyReturns503(t *testing.T) {
	s, _ := newTestServer(t)
	s.busy = true
	rr := httptest.NewRecorder()
	s.handleRoot(rr, httptest.NewRequest(http.MethodPost, "/root", strings.NewReader(`{"path":"epoch_tree_6730.bin"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("busy: got %d, want 503", rr.Code)
	}
}
