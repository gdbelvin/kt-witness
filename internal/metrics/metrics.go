// Package metrics is a small Prometheus-format registry.
//
// Hand-rolled rather than pulling in client_golang, for the same reason the
// status page has no CDN: this binary signs things, and every dependency is
// another party to trust with that. The exposition format is a few lines of
// text, and what a witness needs is counters and gauges rather than the
// exemplars and native histograms a full client provides.
//
// The one real loss is latency histograms. Sum-and-count is kept instead, which
// gives averages but not quantiles — enough to see "audits got slower", not
// enough to see "the p99 got slower". If quantiles ever matter, that is the
// moment to take the dependency, not before.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Kind distinguishes the two exposition types used here.
type Kind string

const (
	Counter Kind = "counter"
	Gauge   Kind = "gauge"
)

type key struct {
	name   string
	labels string // pre-rendered, so the hot path does no allocation-heavy work
}

type Registry struct {
	mu     sync.Mutex
	help   map[string]string
	kind   map[string]Kind
	values map[key]float64
	order  []string // metric names, in declaration order
}

func New() *Registry {
	return &Registry{
		help:   map[string]string{},
		kind:   map[string]Kind{},
		values: map[key]float64{},
	}
}

// Describe declares a metric's type and help text. Declaring up front means an
// unused metric still appears in the output with a zero value, which is what
// lets an alert distinguish "no failures" from "the metric disappeared".
func (r *Registry) Describe(name string, k Kind, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, seen := r.kind[name]; !seen {
		r.order = append(r.order, name)
	}
	r.kind[name] = k
	r.help[name] = help
}

func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for n := range labels {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escape(labels[n]))
		b.WriteString(`"`)
	}
	b.WriteByte('}')
	return b.String()
}

// escape handles the three characters the exposition format reserves in a label
// value. Origins are URL-ish and operator-controlled, so this is not optional.
func escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// Add increments a counter.
func (r *Registry) Add(name string, labels map[string]string, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key{name, labelString(labels)}] += delta
}

// Inc adds one.
func (r *Registry) Inc(name string, labels map[string]string) { r.Add(name, labels, 1) }

// Set assigns a gauge.
func (r *Registry) Set(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key{name, labelString(labels)}] = v
}

// Write renders the registry in Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	// Snapshot under the lock, render outside it: rendering can block on a slow
	// client, and holding the lock through that would stall the witness loop.
	type sample struct {
		labels string
		value  float64
	}
	byName := map[string][]sample{}
	for k, v := range r.values {
		byName[k.name] = append(byName[k.name], sample{k.labels, v})
	}
	order := append([]string(nil), r.order...)
	help := make(map[string]string, len(r.help))
	kind := make(map[string]Kind, len(r.kind))
	for n, h := range r.help {
		help[n] = h
	}
	for n, k := range r.kind {
		kind[n] = k
	}
	r.mu.Unlock()

	// Anything Set but never Described still gets rendered, after the declared
	// metrics and without a TYPE line.
	//
	// It used to be dropped silently. A whole feedback controller published its
	// state for two deploys and appeared nowhere, because Set stores into the
	// map and Write only walks the declared order — no error, no warning, just
	// absence. Undeclared output is untidy; invisible output is a debugging
	// dead end.
	declared := make(map[string]bool, len(order))
	for _, n := range order {
		declared[n] = true
	}
	var undeclared []string
	for n := range byName {
		if !declared[n] {
			undeclared = append(undeclared, n)
		}
	}
	sort.Strings(undeclared)
	order = append(order, undeclared...)

	var b strings.Builder
	for _, name := range order {
		samples := byName[name]
		if h := help[name]; h != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, h)
		}
		if k, ok := kind[name]; ok {
			fmt.Fprintf(&b, "# TYPE %s %s\n", name, k)
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i].labels < samples[j].labels })
		for _, s := range samples {
			b.WriteString(name)
			b.WriteString(s.labels)
			b.WriteByte(' ')
			b.WriteString(strconv.FormatFloat(s.value, 'g', -1, 64))
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Default is the process-wide registry. A witness runs one of everything, so
// threading a registry through every call site would be ceremony without
// benefit.
var Default = New()

func Add(name string, labels map[string]string, delta float64) { Default.Add(name, labels, delta) }
func Inc(name string, labels map[string]string)                { Default.Inc(name, labels) }
func Set(name string, labels map[string]string, v float64)     { Default.Set(name, labels, v) }
func Describe(name string, k Kind, help string)                { Default.Describe(name, k, help) }
