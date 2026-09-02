package metrics

import (
	"strings"
	"testing"
)

// Declared-but-unused metrics must still appear, with a zero value. A counter
// that only materialises after the first failure cannot be alerted on, because
// before then the series is absent rather than false.
func TestDeclaredMetricsAppearBeforeUse(t *testing.T) {
	r := New()
	r.Describe("kt_witness_withheld_total", Counter, "withheld")
	r.Set("kt_witness_withheld_total", map[string]string{"origin": "a"}, 0)

	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# HELP kt_witness_withheld_total withheld",
		"# TYPE kt_witness_withheld_total counter",
		`kt_witness_withheld_total{origin="a"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Origins are operator-controlled and URL-ish. An unescaped quote would produce
// an exposition a scraper rejects — silently losing all metrics, not just one.
func TestLabelValuesAreEscaped(t *testing.T) {
	r := New()
	r.Describe("m", Gauge, "")
	r.Set("m", map[string]string{"origin": `evil"\value` + "\nnewline"}, 1)

	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// The property that matters: one sample stays on one line, whatever the
	// label contains. A raw newline would split it and a scraper would reject
	// the whole exposition, losing every metric rather than one.
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	samples := 0
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			samples++
		}
	}
	if samples != 1 {
		t.Errorf("expected exactly one sample line, got %d:\n%q", samples, out)
	}
	if !strings.Contains(out, `\"`) || !strings.Contains(out, `\\`) || !strings.Contains(out, `\n`) {
		t.Errorf("label value not escaped: %q", out)
	}
}

func TestCountersAccumulateAndGaugesReplace(t *testing.T) {
	r := New()
	r.Describe("c", Counter, "")
	r.Describe("g", Gauge, "")
	l := map[string]string{"origin": "x"}

	r.Inc("c", l)
	r.Add("c", l, 4)
	r.Set("g", l, 10)
	r.Set("g", l, 3)

	var b strings.Builder
	_ = r.Write(&b)
	out := b.String()
	if !strings.Contains(out, `c{origin="x"} 5`) {
		t.Errorf("counter did not accumulate:\n%s", out)
	}
	if !strings.Contains(out, `g{origin="x"} 3`) {
		t.Errorf("gauge did not replace:\n%s", out)
	}
}

// Labels must render in a stable order or every scrape looks like a new series.
func TestLabelOrderIsStable(t *testing.T) {
	r := New()
	r.Describe("m", Gauge, "")
	r.Set("m", map[string]string{"z": "1", "a": "2", "m": "3"}, 1)
	var b strings.Builder
	_ = r.Write(&b)
	if !strings.Contains(b.String(), `m{a="2",m="3",z="1"} 1`) {
		t.Errorf("labels not sorted: %s", b.String())
	}
}
