package cosig

import "testing"

// TestParsePeerMetrics covers the Prometheus-format peer view.
func TestParsePeerMetrics(t *testing.T) {
	body := `# HELP sunlight_witness_log_entries_total Entries.
# TYPE sunlight_witness_log_entries_total gauge
sunlight_witness_log_entries_total{origin="log2025-1.rekor.sigstore.dev"} 9.3757645e+07
sunlight_witness_log_entries_total{origin="keyserver.geomys.org"} 79
sunlight_witness_log_entries_total{origin="broken.example"} notanumber
`
	got := parsePeerMetrics("navigli", body)
	if len(got) != 2 {
		t.Fatalf("parsed %d views, want 2 (the malformed line must be skipped)", len(got))
	}
	// Prometheus renders large integers in exponent form; parsing these as
	// integers would silently drop every large log, which is all the ones worth
	// comparing.
	var rekor *PeerView
	for i := range got {
		if got[i].Origin == "log2025-1.rekor.sigstore.dev" {
			rekor = &got[i]
		}
	}
	if rekor == nil {
		t.Fatal("exponent-form size was not parsed")
	}
	if rekor.Size != 93757645 {
		t.Fatalf("size %d, want 93757645", rekor.Size)
	}
	// Size-only views must never look comparable.
	for _, v := range got {
		if v.HasRoot() {
			t.Fatalf("%s reported a root it does not publish", v.Origin)
		}
	}
}

// TestPollChoosesParserByContent checks the format is detected from the body,
// so a peer changing how it publishes does not need a config edit.
func TestPollChoosesParserByContent(t *testing.T) {
	html := "- example.org/log\n  (size 12, root AAAA=)\n"
	if v := parsePeerPage("p", html); len(v) != 1 || !v[0].HasRoot() {
		t.Fatalf("HTML page did not parse to one view with a root: %+v", v)
	}
	if v := parsePeerMetrics("p", html); len(v) != 0 {
		t.Fatalf("metrics parser matched an HTML page: %+v", v)
	}
}
