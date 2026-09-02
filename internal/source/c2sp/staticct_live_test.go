package c2sp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/staticct"
)

// TestLiveStaticCTAsSource proves a static CT log is witnessable through the
// same adapter as any other tlog-tiles log: fetch a signed checkpoint, then
// prove append-only with a consistency proof computed locally from tiles.
//
// This is the step that turns "we can check their signature" into "we can
// witness them", and it is the one that could have failed independently — the
// signature work says nothing about whether the tile layout matches.
//
// Requires network; run with KT_WITNESS_LIVE=1.
func TestLiveStaticCTAsSource(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}

	resp, err := http.Get("https://www.gstatic.com/ct/log_list/v3/all_logs_list.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var list struct {
		Operators []struct {
			Name  string `json:"name"`
			Tiled []struct {
				Description   string `json:"description"`
				Key           string `json:"key"`
				MonitoringURL string `json:"monitoring_url"`
				SubmissionURL string `json:"submission_url"`
			} `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}

	// Take one log per operator, so a passing result is not one vendor's quirk.
	tested := 0
	for _, op := range list.Operators {
		for _, l := range op.Tiled {
			if l.MonitoringURL == "" || l.SubmissionURL == "" || l.Key == "" {
				continue
			}
			origin := staticct.OriginFromSubmissionURL(l.SubmissionURL)
			spki, err := base64.StdEncoding.DecodeString(l.Key)
			if err != nil {
				continue
			}
			v, err := staticct.NewVerifier(origin, spki)
			if err != nil {
				t.Errorf("%s: %v", l.Description, err)
				break
			}
			src, err := New(Config{
				Origin:   origin,
				BaseURL:  strings.TrimSuffix(l.MonitoringURL, "/") + "/",
				Verifier: v,
			})
			if err != nil {
				t.Errorf("%s: %v", l.Description, err)
				break
			}

			ctx := context.Background()
			head, err := src.Fetch(ctx, nil)
			if err != nil {
				t.Errorf("%s: Fetch: %v", l.Description, err)
				break
			}
			if src.Tier() != source.TierA {
				t.Errorf("%s: tier is %v, want A", l.Description, src.Tier())
			}

			// Negative control: a root this tree never had must not verify.
			bogus := *head
			bogus.Size = head.Size / 2
			if bogus.Size >= 2 {
				if err := src.VerifyConsistency(ctx, &bogus, head); err == nil {
					t.Errorf("%s: consistency verified against a fabricated root", l.Description)
				}
			}

			// Positive: a real second observation. CT logs grow continuously, so
			// a later fetch usually gives a genuinely larger tree, and the proof
			// between them is computed locally from tiles bound to the signed
			// root rather than taken from a served proof.
			grew := ""
			if next, err := src.Fetch(ctx, head); err != nil {
				t.Errorf("%s: second Fetch: %v", l.Description, err)
			} else if next.Size > head.Size {
				if err := src.VerifyConsistency(ctx, head, next); err != nil {
					t.Errorf("%s: append-only %d -> %d: %v", l.Description, head.Size, next.Size, err)
				} else {
					grew = fmt.Sprintf(" -> %d append-only proven", next.Size)
				}
			}
			t.Logf("%-28s %-52s size %d%s", op.Name, origin, head.Size, grew)
			tested++
			break
		}
	}
	if tested < 3 {
		t.Fatalf("only %d operators exercised", tested)
	}
	t.Logf("%d operators' static CT logs fetched and verified through the c2sp adapter", tested)
}
