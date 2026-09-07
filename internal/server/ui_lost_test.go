package server

import (
	"strings"
	"testing"
	"time"
)

// TestLostSectionAppearsOnlyWhenSomethingIsLost.
//
// The section is a claim about permanence, so it must not appear speculatively:
// a witness that has watched a stable window has lost nothing and should say
// nothing. Equally, once something HAS aged out, the page must lead with it —
// that is the finding a transparency system is otherwise structurally unable to
// report, because losing evidence produces no contradiction to detect.
func TestLostSectionAppearsOnlyWhenSomethingIsLost(t *testing.T) {
	stable := statusView{
		Logs: []logView{{Origin: "a/kt", Kind: "kt", History: &historyView{From: 1, To: 100}}},
	}
	if got := renderStatus(t, stable); strings.Contains(got, "Beyond checking") {
		t.Error("a witness that has lost nothing advertised a loss")
	}

	lost := statusView{
		LostEpochs: 236,
		LostOrigins: []lostView{{
			Origin: "proton.me/kt/v1", Expired: 236, Unreachable: 1,
			WindowFrom: 6236, WindowTo: 6736, EverFrom: 6000, Since: "1 Jun 2026",
		}},
		NoHistory: []string{"signal.org/kt"},
		Logs:      []logView{},
	}
	out := renderStatus(t, lost)
	for _, want := range []string{
		"Beyond checking",
		"236",             // the count itself
		"proton.me/kt/v1", // which operator
		"6,236",           // the window it now publishes
		"6,000",           // how far back it is known to have reached
		"signal.org/kt",   // publishes no construction evidence at all
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lost section is missing %q", want)
		}
	}
	// The claim must not be dated to when this witness started watching: the
	// figure comes from the operator's own metadata and would be true whether
	// or not anyone had been looking. Saying "since <date we arrived>" would
	// read as 522 epochs having expired on our watch.
	if strings.Contains(out, "Watched since") {
		t.Error("expiry was attributed to this witness's observation window")
	}

	// It must not be phrased as misbehaviour. This is the distinction the whole
	// section exists to draw, and getting it wrong would turn a retention policy
	// into an accusation.
	if strings.Contains(out, "fork(s) recorded") {
		t.Error("lost data was rendered inside a misbehaviour banner")
	}
}

func renderStatus(t *testing.T, v statusView) string {
	t.Helper()
	v.Now = time.Now()
	var sb strings.Builder
	if err := uiTemplate.Execute(&sb, v); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}
