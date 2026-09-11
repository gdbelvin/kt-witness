package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The manifest moved from //go:embed to a file read at runtime, which trades a
// compile-time guarantee that it exists for a deployment that has to mount it.
// This pins both halves of that trade: it is served when the file is there, and
// a missing one degrades to 404 rather than panicking or serving an empty body.
//
// The .well-known pointer is checked alongside because it asserts control over
// a funding URL. A clone with no manifest of its own must not claim it.
func TestFundingEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"missing file", "/nonexistent/funding.json", http.StatusNotFound},
		{"unconfigured", "", http.StatusNotFound},
		{"configured", "../../deploy/funding.example.json", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{FundingPath: tc.path}
			h := s.Handler()
			for _, u := range []string{"/funding.json", "/.well-known/funding-manifest-urls"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", u, nil))
				if w.Code != tc.want {
					t.Errorf("GET %s = %d, want %d", u, w.Code, tc.want)
				}
			}
		})
	}
}
