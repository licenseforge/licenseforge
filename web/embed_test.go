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

func TestMount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/logout", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("PUT /things/{id}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("DELETE /things/{id}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("POST /api/v1/things", func(http.ResponseWriter, *http.Request) {})
	Mount(mux)
	for _, tc := range []struct {
		method, path string
		code         int
		allow        string
	}{
		{"GET", "/auth/logout", 405, "POST"},
		{"GET", "/things/1", 405, "PUT, DELETE"},
		{"HEAD", "/auth/logout", 405, "POST"},
		{"GET", "/t/acme/", 200, ""},
		{"HEAD", "/", 200, ""},
		{"POST", "/t/acme/", 405, "GET, HEAD"},
		{"GET", "/api/v1/things", 405, "POST"},
		{"POST", "/healthz", 405, "GET, HEAD"},
		{"PUT", "/auth/logout", 405, "POST"},
		{"POST", "/api/v2/nope", 404, ""},
		{"POST", "/auth/nope", 404, ""},
	} {
		rec := get(mux, tc.method, tc.path)
		if rec.Code != tc.code || rec.Header().Get("Allow") != tc.allow {
			t.Errorf("%s %s = %d, Allow %q; want %d, %q", tc.method, tc.path, rec.Code, rec.Header().Get("Allow"), tc.code, tc.allow)
		}
	}
	// Under /api/ the 405 is a problem, like the API's own (ADR-0032).
	rec := get(mux, "GET", "/api/v1/things")
	want := `{"type":"about:blank","title":"Method Not Allowed","status":405,"code":"method_not_allowed"}` + "\n"
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" || rec.Body.String() != want {
		t.Errorf("GET /api/v1/things = %q %q", ct, rec.Body)
	}
	if rec := get(mux, "GET", "/auth/logout"); strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem") {
		t.Error("problem JSON outside /api")
	}
}

// A method-less subtree (the API's /api/v1/) coexists with the dashboard:
// "GET /" would make ServeMux panic on registration.
func TestMountBesideSubtree(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	Mount(mux)
	for _, m := range []string{"GET", "POST", "DELETE"} {
		if rec := get(mux, m, "/api/v1/x"); rec.Code != 299 {
			t.Errorf("%s /api/v1/x = %d, want the subtree", m, rec.Code)
		}
	}
	if rec := get(mux, "GET", "/t/acme/"); rec.Code != 200 || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("GET /t/acme/ = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestHeadAndETag(t *testing.T) {
	h := newHandler(bundle)
	if rec := get(h, "HEAD", "/"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD / = %d with %d body bytes", rec.Code, rec.Body.Len())
	}
	for _, p := range []string{"/", "/t/acme/", "/favicon.svg", "/assets/app-1a2b.js"} {
		etag := get(h, "GET", p).Header().Get("ETag")
		if etag == "" {
			t.Fatalf("GET %s: no ETag", p)
		}
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("If-None-Match", etag)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Errorf("GET %s If-None-Match = %d %q, want 304", p, rec.Code, rec.Body)
		}
	}
	if get(h, "GET", "/").Header().Get("ETag") == get(h, "GET", "/favicon.svg").Header().Get("ETag") {
		t.Error("different files share an ETag")
	}
}

func TestAPINotFoundBody(t *testing.T) {
	want := `{"type":"about:blank","title":"Not Found","status":404,"code":"not_found"}` + "\n"
	if rec := get(newHandler(bundle), "GET", "/api/v1/nope"); rec.Body.String() != want {
		t.Errorf("GET /api/v1/nope body = %q", rec.Body)
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
