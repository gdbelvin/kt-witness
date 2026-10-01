package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testWitnessVKey = "witness.gdbsecurity.com+a1398f73+BAbIijGonVIk3ikDac+KKlSm1ELHOzcddhjjB6zB4BNf"

func getAbout(t *testing.T, s *Server, host, accept string, hdr map[string]string) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/about", nil)
	req.Host = host
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("/about: status %d", rec.Code)
	}
	// html/template writes '+' as &#43;; a browser renders and copies it as
	// '+', so compare what a reader sees.
	return html.UnescapeString(rec.Body.String())
}

// The four facts witness-network.org requires must all be on the page, in
// both the plain-text and HTML renderings, and the key must be the one we
// actually sign with.
func TestAboutStatesRequiredFacts(t *testing.T) {
	s := &Server{
		VKey:          testWitnessVKey,
		AddCheckpoint: http.NotFoundHandler(),
		About: AboutInfo{
			PublicURL: "https://witness.gdbsecurity.com/",
			Operator:  "GDB Security",
			Contact:   "gdb@gdbsecurity.com",
			Lists: []string{
				"https://example.org/lists/staging/log-list-10qps-4klogs.1",
				"https://example.org/lists/staging/log-list-100qps-40klogs.1",
			},
			ListRefresh: "24h",
		},
	}
	for _, accept := range []string{"", "text/html"} {
		body := getAbout(t, s, "internal:8080", accept, nil)
		for _, want := range []string{
			s.VKey,
			"key type 0x04, cosignature/v1",
			"https://witness.gdbsecurity.com/add-checkpoint",
			s.About.Lists[0],
			s.About.Lists[1],
			"24h",
			"GDB Security",
			"gdb@gdbsecurity.com",
			"not independent",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("accept=%q: /about omits %q", accept, want)
			}
		}
		if strings.Contains(body, "internal:8080") {
			t.Errorf("accept=%q: configured PublicURL ignored in favour of Host", accept)
		}
		if strings.Contains(body, "not enabled") {
			t.Errorf("accept=%q: push reported disabled when a handler is set", accept)
		}
	}
}

// With no PublicURL configured, the URL is the one the request reached us at.
// Behind the tunnel the connection is plain HTTP, so X-Forwarded-Proto wins.
func TestAboutDerivesURLFromRequest(t *testing.T) {
	s := &Server{VKey: testWitnessVKey}

	body := getAbout(t, s, "witness.example", "", map[string]string{"X-Forwarded-Proto": "https"})
	if !strings.Contains(body, "https://witness.example/add-checkpoint") {
		t.Errorf("forwarded https not honoured:\n%s", body)
	}
	body = getAbout(t, s, "witness.example:8080", "", nil)
	if !strings.Contains(body, "http://witness.example:8080/add-checkpoint") {
		t.Errorf("Host not used:\n%s", body)
	}
}

// Following no list is a legitimate state and must be said plainly, not left
// as an empty section a reviewer might read as a rendering bug.
func TestAboutSaysWhenNoListsFollowed(t *testing.T) {
	s := &Server{VKey: testWitnessVKey}
	for _, accept := range []string{"", "text/html"} {
		body := getAbout(t, s, "w.example", accept, nil)
		if !strings.Contains(body, noListsNote) {
			t.Errorf("accept=%q: missing %q", accept, noListsNote)
		}
		if !strings.Contains(body, "not enabled") {
			t.Errorf("accept=%q: push disabled but not said", accept)
		}
	}
}

// A key of the wrong type must be called out rather than labelled as what
// witness-network expects.
// An unconfigured witness prints no placeholders: no "not stated", no empty
// operator section, and no refresh interval for lists it does not follow.
func TestAboutOmitsUnsetFields(t *testing.T) {
	s := &Server{VKey: testWitnessVKey}
	for _, accept := range []string{"", "text/html"} {
		body := getAbout(t, s, "witness.example", accept, nil)
		for _, bad := range []string{"not stated", "re-read every", "list refresh interval", "operator:", ">Operator<"} {
			if strings.Contains(body, bad) {
				t.Errorf("accept=%q: page contains %q", accept, bad)
			}
		}
	}
}

func TestAboutFlagsWrongKeyType(t *testing.T) {
	s := &Server{VKey: "witness+00000000+AAAA"}
	body := getAbout(t, s, "w.example", "", nil)
	if strings.Contains(body, "key type 0x04") || !strings.Contains(body, "NOT cosignature/v1") {
		t.Errorf("wrong key type not flagged:\n%s", body)
	}
}
