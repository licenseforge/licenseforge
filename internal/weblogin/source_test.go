package weblogin

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"licenseforge.io/licenseforge/internal/ratelimit"
)

// Audit entries record the client address the rate limiter resolved, so
// behind a trusted proxy they name the client, not the proxy.
func TestSourceUsesResolvedClientAddress(t *testing.T) {
	l := ratelimit.New(ratelimit.Config{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	for remote, want := range map[string]string{"10.0.0.1:1": "203.0.113.9", "198.51.100.7:1": "198.51.100.7"} {
		var got string
		r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		l.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = source(r).IP })).ServeHTTP(httptest.NewRecorder(), r)
		if got != want {
			t.Errorf("peer %s: source %q, want %q", remote, got, want)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil) // without the limiter: the connection
	r.RemoteAddr = "198.51.100.7:1"
	if got := source(r).IP; got != "198.51.100.7" {
		t.Errorf("unwrapped: %q", got)
	}
}
