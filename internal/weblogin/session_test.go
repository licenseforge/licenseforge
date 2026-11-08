package weblogin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSessionAndLogout(t *testing.T) {
	f := setup(t)
	do := func(method, path string, header map[string]string) (*http.Response, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, f.app.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp, body
	}
	if resp, _ := do("GET", "/auth/session", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: %d", resp.StatusCode)
	}
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Fatalf("login: %d", code)
	}
	resp, body := do("GET", "/auth/session", nil)
	token, _ := body["csrf_token"].(string)
	if resp.StatusCode != http.StatusOK || token == "" || body["platform_admin"] != false || resp.Header.Get("Cache-Control") != "no-store" ||
		resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("session: %d %v", resp.StatusCode, body)
	}
	// Unsafe requests need the token and must be same-origin.
	for name, h := range map[string]map[string]string{
		"no token":     nil,
		"wrong token":  {CSRFHeader: CSRFToken("another session")},
		"cross-site":   {CSRFHeader: token, "Sec-Fetch-Site": "cross-site"},
		"other origin": {CSRFHeader: token, "Origin": "https://evil.example"},
		"sibling site": {CSRFHeader: token, "Sec-Fetch-Site": "same-site", "Origin": "https://other.example"},
	} {
		if resp, _ := do("POST", "/auth/logout", h); resp.StatusCode != http.StatusForbidden {
			t.Errorf("logout with %s: %d", name, resp.StatusCode)
		}
	}
	if _, _, err := f.ids.Session(t.Context(), f.session(t)); err != nil {
		t.Fatalf("refused logouts ended the session: %v", err)
	}
	// Behind a proxy that rewrites Host, the configured public origin is
	// still same-origin (browsers that send only Origin).
	// It passes the origin and cookie checks and stops at the (wrong) token.
	req, _ := http.NewRequest("POST", f.app.URL+"/auth/logout", nil)
	req.Host = "licenseforge.internal:8080" // the jar then sends no cookie: set it
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: f.session(t)})
	req.Header.Set("Origin", f.app.URL)
	req.Header.Set(CSRFHeader, "wrong")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	why, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(why), CSRFHeader) {
		t.Errorf("own origin behind a proxy refused by the origin check: %d %s", resp.StatusCode, why)
	}
	cookie := f.session(t)
	// No Fetch metadata and no Origin: a non-browser client with the token.
	if resp, _ := do("POST", "/auth/logout", map[string]string{CSRFHeader: token}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if _, _, err := f.ids.Session(t.Context(), cookie); err == nil {
		t.Error("session alive after logout")
	}
	if f.session(t) != "" {
		t.Error("session cookie kept after logout")
	}
	// A dead session cookie gets 401 and is cleared.
	f.client.Jar.SetCookies(mustURL(t, f.app.URL), []*http.Cookie{{Name: SessionCookie, Value: cookie, Path: "/", Secure: true}})
	if resp, _ := do("GET", "/auth/session", nil); resp.StatusCode != http.StatusUnauthorized || f.session(t) != "" {
		t.Errorf("dead session: %d, cookie %q", resp.StatusCode, f.session(t))
	}
}
