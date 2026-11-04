package weblogin

import (
	"encoding/json"
	"net/http"
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
		"Content-Type": "application/json", "X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=60",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
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
	for _, ack := range []string{"", "wrong", cfg["banner_id"] + "x"} {
		resp, err := f.client.Get(f.app.URL + "/auth/login?banner=" + ack)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" || len(resp.Cookies()) != 0 {
			t.Errorf("login with banner=%q: %d %q, cookies %v", ack, resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
		}
	}
	f.ack = cfg["banner_id"]
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	u, err := f.ids.Session(t.Context(), f.session(t))
	if err != nil {
		t.Fatal(err)
	}
	if logs := f.logs.String(); !strings.Contains(logs, `msg="login banner acknowledged" user=`+u.ID+` banner_id=`+cfg["banner_id"]) {
		t.Errorf("no acknowledgement logged:\n%s", logs)
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
	if _, err := New(t.Context(), c, identity.Service{}, nil); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Errorf("New with a bad banner = %v", err)
	}
}
