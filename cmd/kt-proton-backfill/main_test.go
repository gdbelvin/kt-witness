package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClassify pins the rule the whole program exists to obey: a GPU may
// confirm a construction, but it may never be the reason one is called into
// question.
func TestClassify(t *testing.T) {
	const signed = "aa11"
	for _, c := range []struct {
		name     string
		gpu, cpu string
		want     outcome
	}{
		{"gpu agrees with the signed root", signed, signed, verifiedByGPU},
		{"gpu wrong, cpu agrees — a bug here, not a finding", "bad0", signed, gpuWrong},
		{"both disagree — this is the real thing", "bad0", "bad0", constructionFailed},
		{"both disagree, and with each other — still a real finding", "bad0", "bad1", constructionFailed},
		// The one that matters most: a GPU result must never be able to reach a
		// construction-failure conclusion on its own. When the GPU matches, the
		// CPU is not even consulted, so a broken CPU path cannot manufacture an
		// accusation either.
		{"gpu agrees even though cpu differs", signed, "bad1", verifiedByGPU},
	} {
		if got := classify(c.gpu, c.cpu, signed); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.jsonl")
	os.WriteFile(p, []byte(
		`{"epoch":6238,"tree_hash":"cc","chain_hash":"z","start_epoch":6236}`+"\n"+
			`{"epoch":6236,"tree_hash":"aa","chain_hash":"x","start_epoch":6236}`+"\n"+
			"\n"+
			`{"epoch":6237,"tree_hash":"bb","chain_hash":"y","start_epoch":6236}`+"\n"), 0o644)

	m, epochs, err := loadManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("got %d epochs, want 3", len(m))
	}
	// Order matters: the replay is forward and starts at the oldest, so the
	// manifest must come back sorted regardless of the file's order.
	want := []int64{6236, 6237, 6238}
	for i, e := range want {
		if epochs[i] != e {
			t.Errorf("epochs[%d] = %d, want %d", i, epochs[i], e)
		}
	}
	if m[6237].TreeHash != "bb" {
		t.Errorf("tree hash for 6237: %q", m[6237].TreeHash)
	}
}
