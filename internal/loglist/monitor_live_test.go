package loglist

import (
	"context"
	"os"
	"testing"
)

// TestLiveMonitorStagingList fetches the staging list witness-network.org
// publishes and probes every log on it through PublicClient, reporting which
// ones can be polled. The two push-only logs this witness cosigned when this
// was written both publish at their origin's URL, so at least they should be
// promoted.
func TestLiveMonitorStagingList(t *testing.T) {
	if os.Getenv("KT_WITNESS_LIVE") == "" {
		t.Skip("set KT_WITNESS_LIVE=1 to run against production")
	}
	fx := newFixture(t)
	fx.f.Client = nil
	fx.f.URLs = []string{"https://staging.witness-network.org/log-list-10qps-4klogs.1"}
	if err := fx.f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := &Monitor{Registry: fx.reg}
	n := m.ProbeOnce(context.Background())
	for _, l := range fx.reg.Logs() {
		if fx.reg.IsStatic(l.Origin) {
			continue
		}
		t.Logf("%-6v %s", m.Polled(l.Origin), l.Origin)
	}
	t.Logf("promoted %d of %d listed logs", n, len(fx.reg.Logs())-1)
	for _, o := range []string{"api.riskrouter.eu/tlog/evidence-v2", "transparency.syngraphe.org/countersign/v1"} {
		if _, listed := fx.reg.Lookup(o); listed && !m.Polled(o) {
			t.Errorf("%s is listed and publishes at its origin URL, but was not promoted", o)
		}
	}
}
