package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

const index = "<!doctype html><title>app</title>"

var bundle = fstest.MapFS{
	"index.html":         {Data: []byte(index)},
	"favicon.svg":        {Data: []byte("<svg/>")},
	"assets/app-1a2b.js": {Data: []byte("console.log(1)")},
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHandler(t *testing.T) {
	h := newHandler(bundle)
	for _, tc := range []struct {
		method, path string
		code         int
		body, cache  string // body "" = anything but index.html
		ctype        string
	}{
		{"GET", "/", 200, index, "no-cache", "text/html"},
		{"HEAD", "/", 200, "", "no-cache", "text/html"},
		{"GET", "/index.html", 200, index, "no-cache", "text/html"},
		{"GET", "/t/acme/", 200, index, "no-cache", "text/html"}, // SPA fallback
		{"GET", "/login", 200, index, "no-cache", "text/html"},
		{"GET", "/favicon.svg", 200, "<svg/>", "no-cache", "image/svg+xml"},
		{"GET", "/assets/app-1a2b.js", 200, "console.log(1)", "public, max-age=31536000, immutable", "text/javascript"},
		{"GET", "/assets/gone-9z9z.js", 404, "", "", "text/plain"},
		{"GET", "/assets", 404, "", "", "text/plain"},
		{"POST", "/", 405, "", "", "text/plain"},
		// The server's own paths are never the app, matched or not.
		{"GET", "/api", 404, "", "", "application/problem+json"},
		{"GET", "/api/v1/nope", 404, "", "", "application/problem+json"},
		{"POST", "/api/v1/nope", 404, "", "", "application/problem+json"},
		{"GET", "/x/../api/y", 404, "", "", "application/problem+json"},
		{"GET", "/auth", 404, "", "", "text/plain"},
		{"GET", "/auth/session", 404, "", "", "text/plain"},
		{"GET", "/auth/login", 404, "", "", "text/plain"},
		{"GET", "/healthz", 404, "", "", "text/plain"},
		{"GET", "/readyz", 404, "", "", "text/plain"},
		{"GET", "/apiary", 200, index, "no-cache", "text/html"}, // only the exact prefixes
	} {
		rec := get(h, tc.method, tc.path)
		name := tc.method + " " + tc.path
		if rec.Code != tc.code {
			t.Errorf("%s = %d, want %d", name, rec.Code, tc.code)
		}
		if tc.body != "" && tc.method != "HEAD" && rec.Body.String() != tc.body {
			t.Errorf("%s body = %q, want %q", name, rec.Body, tc.body)
		}
		if tc.body == "" && strings.Contains(rec.Body.String(), index) {
			t.Errorf("%s served index.html", name)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.cache {
			t.Errorf("%s Cache-Control = %q, want %q", name, got, tc.cache)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.ctype) {
			t.Errorf("%s Content-Type = %q, want %s", name, got, tc.ctype)
		}
		for k, v := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "same-origin",
		} {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s = %q, want %q", name, k, got, v)
			}
		}
		csp := rec.Header().Get("Content-Security-Policy")
		for _, d := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, d+";") && !strings.HasSuffix(csp, d) {
				t.Errorf("%s CSP %q lacks %q", name, csp, d)
			}
		}
		if strings.Contains(csp, "unsafe-") {
			t.Errorf("%s CSP %q allows unsafe sources", name, csp)
		}
	}
}

// The embedded bundle (the real one with -tags webui) must work under the
// CSP: every script is an external file, and there are no inline styles.
func TestEmbeddedBundleFitsCSP(t *testing.T) {
	rec := get(Handler(), "GET", "/")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "<html") {
		t.Fatalf("GET / = %d %q", rec.Code, body)
	}
	for _, tag := range regexp.MustCompile(`(?is)<script\b[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(tag, "src=") {
			t.Errorf("inline script %q", tag)
		}
	}
	if regexp.MustCompile(`(?i)<style\b|\sstyle=`).MatchString(body) {
		t.Errorf("inline style in index.html")
	}
}
