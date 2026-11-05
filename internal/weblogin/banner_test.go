package weblogin

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/identity"
)

const banner = "U.S. Government system. Authorized use only; use is monitored.\r\n<b>Not HTML</b>\t& no markup."

func withBanner(c *Config, _ *identity.Service) { c.Banner = banner }

func getConfig(t *testing.T, f *fixture) (*http.Response, map[string]string) {
	t.Helper()
	resp, err := f.client.Get(f.app.URL + "/auth/config") // no session: unauthenticated
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestAuthConfig(t *testing.T) {
	f := setupWith(t, withBanner)
	resp, body := getConfig(t, f)
	want := strings.ReplaceAll(banner, "\r\n", "\n")
	if resp.StatusCode != http.StatusOK || body["banner"] != want || len(body["banner_id"]) != 22 {
		t.Errorf("config = %d %q", resp.StatusCode, body)
	}
	for k, v := range map[string]string{
		"Content-Type": "application/json", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache",
		"ETag": `"` + body["banner_id"] + `"`,
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// Revalidation: the same banner answers 304, another ETag the full body.
	for etag, want := range map[string]int{resp.Header.Get("ETag"): http.StatusNotModified, `"old"`: http.StatusOK} {
		req, _ := http.NewRequest("GET", f.app.URL+"/auth/config", nil)
		req.Header.Set("If-None-Match", etag)
		r, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != want {
			t.Errorf("If-None-Match %s = %d, want %d", etag, r.StatusCode, want)
		}
	}

	if _, body := getConfig(t, setup(t)); body["banner"] != "" || body["banner_id"] != "" {
		t.Errorf("no banner configured: %q", body)
	}
}

// With a banner, a login starts only with its acknowledgement, and the
// completed login is logged with the user as AC-8 evidence.
func TestBannerGate(t *testing.T) {
	f := setupWith(t, withBanner)
	_, cfg := getConfig(t, f)
	for ack, loc := range map[string]string{"": "/login", "wrong": "/login?banner_changed=1", cfg["banner_id"] + "x": "/login?banner_changed=1"} {
		resp, err := f.client.Get(f.app.URL + "/auth/login?banner=" + ack)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != loc || len(resp.Cookies()) != 0 {
			t.Errorf("login with banner=%q: %d %q, cookies %v", ack, resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
		}
	}
	f.ack = cfg["banner_id"]
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	u, _, err := f.ids.Session(t.Context(), f.session(t))
	if err != nil {
		t.Fatal(err)
	}
	if logs := f.logs.String(); !strings.Contains(logs, `msg="login banner acknowledged" user=`+u.ID+` banner_id=`+cfg["banner_id"]) {
		t.Errorf("no acknowledgement logged:\n%s", logs)
	}

	// The callback wants the acknowledged banner in the flow cookie to be the
	// current one: a flow that agreed to none, or to another banner (a
	// rolling update), gets no session and agrees again. The refusal comes
	// before the token is verified, so it is logged, never chained (ADR-0033).
	before := f.head(t)
	for _, acked := range []string{"", "other-banner-id", cfg["banner_id"] + "x"} {
		f.client.Jar.SetCookies(mustURL(t, f.app.URL), []*http.Cookie{{Name: SessionCookie, Value: "", MaxAge: -1}})
		q := f.start(t)
		forgeFlowAck(t, f, acked)
		if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther ||
			f.last.Header.Get("Location") != "/login?banner_changed=1" || f.session(t) != "" {
			t.Errorf("flow acknowledging %q: %d %q, session %q", acked, code, f.last.Header.Get("Location"), f.session(t))
		}
	}
	if es := f.entries(t, before); len(es) != 0 {
		t.Errorf("banner refusals reached the audit chain: %d entries", len(es))
	}
	if !strings.Contains(f.logs.String(), `reason="banner not acknowledged"`) {
		t.Error("banner refusal not logged")
	}
	// A flow cookie missing parts is refused too.
	q = f.start(t)
	forgeFlowAck(t, f, "\x00drop")
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusBadRequest || f.session(t) != "" {
		t.Errorf("three-part flow cookie: %d", code)
	}

	// Without a banner nothing is asked or logged.
	f = setup(t)
	q = f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther || strings.Contains(f.logs.String(), "banner") {
		t.Errorf("login without a banner: %d\n%s", code, f.logs)
	}
}

func TestCheckBanner(t *testing.T) {
	for b, ok := range map[string]bool{
		"": true,
		"Zugriff nur für Befugte.\n\tÜberwacht": true,
		strings.Repeat("a", MaxBannerLen):       true,
		strings.Repeat("a", MaxBannerLen+1):     false,
		"bad \xff utf-8":                        false,
		"nul \x00":                              false,
		"escape \x1b[31m":                       false,
		"lone \r return":                        false,
		"next line \u0085":                      false,
		"bidi \u202eoverride":                   false,
		"zero\u200bwidth":                       false,
		"line\u2028separator":                   false,
		"para\u2029separator":                   false,
		"bom \ufeff":                            false,
	} {
		if err := checkBanner(b); (err == nil) != ok {
			t.Errorf("checkBanner(%.20q) = %v, want ok=%v", b, err, ok)
		}
	}
}

// The session cookie lives as long as the configured session.
func TestCookieFollowsMaxAge(t *testing.T) {
	for _, maxAge := range []time.Duration{0, 2 * time.Hour} {
		f := setupWith(t, func(_ *Config, s *identity.Service) { s.MaxAge = maxAge })
		q := f.start(t)
		if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
			t.Fatalf("callback: %d", code)
		}
		want := int(f.ids.SessionMaxAge().Seconds())
		var got int
		for _, c := range f.last.Cookies() {
			if c.Name == SessionCookie {
				got = c.MaxAge
			}
		}
		if got != want || (maxAge != 0 && want != int(maxAge.Seconds())) {
			t.Errorf("MaxAge %v: cookie Max-Age %d, want %d", maxAge, got, want)
		}
	}
}

func TestNewRefusesBadBanner(t *testing.T) {
	c := Config{Issuer: "https://idp.example", ClientID: "lf", RedirectURL: "https://app.example/auth/callback", Banner: "a\x00"}
	if _, err := New(t.Context(), c, identity.Service{}, nil); err == nil || !strings.Contains(err.Error(), "control or format character") {
		t.Errorf("New with a bad banner = %v", err)
	}
}

// forgeFlowAck rewrites the acknowledged banner in the jar's flow cookie
// ("\x00drop" removes the part).
func forgeFlowAck(t *testing.T, f *fixture, acked string) {
	t.Helper()
	u := mustURL(t, f.app.URL)
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name != flowCookie {
			continue
		}
		parts := strings.Split(c.Value, ".")
		if len(parts) != 6 {
			t.Fatalf("flow cookie has %d parts", len(parts))
		}
		if acked == "\x00drop" {
			parts = parts[:3]
		} else {
			parts[3] = acked
		}
		f.client.Jar.SetCookies(u, []*http.Cookie{{Name: flowCookie, Value: strings.Join(parts, "."), Path: "/", Secure: true, HttpOnly: true}})
		return
	}
	t.Fatal("no flow cookie")
}

// The checker the management API shares (Handler.Sessions) applies the
// configured idle timeout, and sessions get the configured max age.
func TestAPISessionsUseConfiguredTimeouts(t *testing.T) {
	f := setupWith(t, func(_ *Config, s *identity.Service) { s.IdleTimeout, s.MaxAge = 10*time.Minute, time.Hour })
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	cookie := f.session(t)
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	var lifetime float64
	if err := owner.QueryRow(`SELECT extract(epoch FROM expires_at - created_at) FROM sessions WHERE token_hash = sha256($1::bytea)`, cookie).Scan(&lifetime); err != nil {
		t.Fatal(err)
	}
	if lifetime != time.Hour.Seconds() {
		t.Errorf("session lifetime %vs, want the configured hour", lifetime)
	}
	check := func(idle string) int {
		t.Helper()
		if _, err := owner.Exec(`UPDATE sessions SET last_seen_at = now() - $2::interval WHERE token_hash = sha256($1::bytea)`, cookie, idle); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/api-tokens", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
		_, _, code, _ := f.h.Sessions().Check(httptest.NewRecorder(), req)
		return code
	}
	if code := check("9 minutes"); code != 0 {
		t.Errorf("idle 9 of 10 minutes: %d", code)
	}
	if code := check("11 minutes"); code != http.StatusUnauthorized {
		t.Errorf("idle 11 of 10 minutes: %d, want 401 (the default hour would allow it)", code)
	}
}
