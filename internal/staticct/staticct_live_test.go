package staticct

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const logListURL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type tiledLog struct {
	Description   string         `json:"description"`
	Key           string         `json:"key"`
	MonitoringURL string         `json:"monitoring_url"`
	SubmissionURL string         `json:"submission_url"`
	State         map[string]any `json:"state"`
}

func fetchTiledLogs(t *testing.T) []tiledLog {
	t.Helper()
	resp, err := http.Get(logListURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Operators []struct {
			Name  string     `json:"name"`
			Tiled []tiledLog `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	var out []tiledLog
	for _, op := range list.Operators {
		out = append(out, op.Tiled...)
	}
	return out
}

// TestLiveStaticCT is the acceptance test, and it is deliberately run against
// the whole population rather than one log: every static CT log in Google's
// list is fetched and its checkpoint signature verified with a key taken only
// from the list.
//
// A signature scheme implemented wrongly does not verify dozens of independent
// logs run by different operators.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveStaticCT(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	logs := fetchTiledLogs(t)
	if len(logs) == 0 {
		t.Fatal("log list returned no tiled logs")
	}
	t.Logf("%d static CT logs in the list", len(logs))

	var verified, unreachable, keyMismatch int
	for _, l := range logs {
		if l.MonitoringURL == "" || l.SubmissionURL == "" || l.Key == "" {
			continue
		}
		spki, err := base64.StdEncoding.DecodeString(l.Key)
		if err != nil {
			t.Errorf("%s: key is not base64: %v", l.Description, err)
			continue
		}
		origin := OriginFromSubmissionURL(l.SubmissionURL)
		v, err := NewVerifier(origin, spki)
		if err != nil {
			t.Errorf("%s: %v", l.Description, err)
			continue
		}

		resp, err := http.Get(strings.TrimSuffix(l.MonitoringURL, "/") + "/checkpoint")
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			unreachable++
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if _, err := note.Open(body, note.VerifierList(v)); err != nil {
			keyMismatch++
			t.Errorf("%s (%s): checkpoint does not verify: %v", l.Description, origin, err)
			continue
		}
		verified++

		// Negative control, once: a checkpoint claiming a different tree size
		// must not verify, or the signature is not binding the tree at all.
		if verified == 1 {
			tampered := bytes.Replace(body, []byte("\n"+sizeLine(t, body)+"\n"),
				[]byte("\n"+sizeLine(t, body)+"0\n"), 1)
			if _, err := note.Open(tampered, note.VerifierList(v)); err == nil {
				t.Fatalf("%s: a checkpoint with an altered tree size still verified", l.Description)
			}
		}
	}
	t.Logf("verified %d, unreachable %d, failed %d", verified, unreachable, keyMismatch)
	if verified == 0 {
		t.Fatal("no checkpoint verified")
	}
	// Unreachable logs are absence, not evidence — some are staging or retired.
	// A failure to verify is different and is already reported above.
	if keyMismatch > 0 {
		t.Errorf("%d logs served a checkpoint that did not verify", keyMismatch)
	}
}

// TestVerifierRejectsWrongOrigin: a correctly signed checkpoint must not verify
// under another log's name, or one log's head could be witnessed as another's.
func TestVerifierRejectsWrongOrigin(t *testing.T) {
	v := &Verifier{name: "example.org/log"}
	if _, _, ok := parseCheckpoint([]byte("other.org/log\n5\n"+
		base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n"), v.name); ok {
		t.Fatal("a checkpoint naming a different origin was accepted")
	}
}

func TestParseCheckpointRejectsMalformed(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct{ name, body string }{
		{"too few lines", "example.org/log\n5\n"},
		{"size not a number", "example.org/log\nx\n" + good + "\n"},
		{"root not base64", "example.org/log\n5\n!!!\n"},
		{"root wrong length", "example.org/log\n5\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n"},
	} {
		if _, _, ok := parseCheckpoint([]byte(tc.body), "example.org/log"); ok {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if _, _, ok := parseCheckpoint([]byte("example.org/log\n5\n"+good+"\n"), "example.org/log"); !ok {
		t.Error("a well-formed checkpoint was rejected")
	}
}

// sizeLine returns the tree-size line of a checkpoint body.
func sizeLine(t *testing.T, body []byte) string {
	t.Helper()
	parts := strings.SplitN(string(body), "\n", 3)
	if len(parts) < 2 {
		t.Fatal("checkpoint has no size line")
	}
	return parts[1]
}
