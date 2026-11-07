package weblogin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Return paths are same-origin paths only (ADR-0038): anything a browser
// could resolve to another origin, or that hides one behind encoding, is
// refused.
func TestSafeReturn(t *testing.T) {
	for _, p := range []string{"", "/", "/t/acme/", "/t/acme/licenses", "/t/a.b_c~d-e/x"} {
		if _, ok := safeReturn(p); !ok {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{
		"//evil.example", "//evil.example/", "/\\evil.example", "\\\\evil.example", "/t/\\x",
		"https://evil.example", "javascript:alert(1)", "evil.example", "t/acme",
		"/%2F%2Fevil.example", "/%2f/evil.example", "/%5Cevil.example", "/t/%2e%2e/x", "/t/acme%00",
		"/t/acme?x=1", "/t/acme#x", "/t//acme", "/t/\tacme", "/t/\nacme", "/t/ acme", "/t/é",
		"/" + strings.Repeat("a", 512),
	} {
		if got, ok := safeReturn(p); ok {
			t.Errorf("%q accepted as %q", p, got)
		}
	}
	if got, _ := safeReturn(""); got != "/" {
		t.Errorf("empty return = %q", got)
	}
}

// stepUpPolicy counts Okta's phr as phishing-resistant and asks for it on
// a step-up to that level.
func stepUpPolicy(c *Config, _ *identity.Service) {
	p := identity.DefaultAssurancePolicy()
	p.PhishingResistantACR = []string{"phr"}
	p.StepUpPhishingResistantACR = []string{"phr", "phrh"}
	c.Assurance = &p
}

// startWith runs /auth/login with params and returns the response.
func (f *fixture) startWith(t *testing.T, params url.Values) *http.Response {
	t.Helper()
	params.Set("banner", f.ack)
	resp, err := f.client.Get(f.app.URL + "/auth/login?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func authorizeQuery(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d %q %v", resp.StatusCode, resp.Header.Get("Location"), err)
	}
	return loc.Query()
}

func TestStepUp(t *testing.T) {
	f := setupWith(t, stepUpPolicy)
	ctx := context.Background()
	sub := ids.New("sub")

	// A first login never asks for acr_values or max_age (ADR-0038).
	q := f.start(t)
	if q.Has("acr_values") || q.Has("max_age") {
		t.Errorf("plain login asks for %v", q)
	}
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "amr": []string{"pwd"}}); code != http.StatusSeeOther || f.last.Header.Get("Location") != "/" {
		t.Fatalf("login: %d %q", code, f.last.Header.Get("Location"))
	}
	weak := f.session(t)

	// A step-up asks for the configured acr_values and a fresh
	// authentication; an IdP that doesn't deliver gets the explanation, not
	// a redirect back into the refusal (no loop).
	params := url.Values{"assurance": {"phishing_resistant"}, "return": {"/t/acme/"}}
	q = authorizeQuery(t, f.startWith(t, params))
	if q.Get("acr_values") != "phr phrh" || q.Get("max_age") != "0" {
		t.Errorf("step-up asks for %v", q)
	}
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "amr": []string{"pwd", "otp"}}); code != http.StatusSeeOther ||
		f.last.Header.Get("Location") != "/login?assurance=phishing_resistant&return=%2Ft%2Facme%2F&step_up_failed=phishing_resistant" {
		t.Errorf("undelivered step-up: %d %q", code, f.last.Header.Get("Location"))
	}
	// Claims are what count, never the request: the session is the mfa one
	// the IdP proved, and it is a new one.
	_, info, err := f.ids.Session(ctx, f.session(t))
	if err != nil || info.Assurance != authz.AssuranceMFA {
		t.Errorf("session after an undelivered step-up: %+v %v", info, err)
	}
	if _, _, err := f.ids.Session(ctx, weak); err == nil {
		t.Error("the session before the step-up survived")
	}

	// Delivered: a fresh phishing-resistant session, back at the return path.
	before := f.session(t)
	q = authorizeQuery(t, f.startWith(t, params))
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "amr": []string{"pwd"}, "acr": "phr"}); code != http.StatusSeeOther ||
		f.last.Header.Get("Location") != "/t/acme/" {
		t.Fatalf("step-up: %d %q", code, f.last.Header.Get("Location"))
	}
	_, info, err = f.ids.Session(ctx, f.session(t))
	if err != nil || info.Assurance != authz.AssurancePhishingResistant {
		t.Errorf("stepped-up session: %+v %v", info, err)
	}
	if _, _, err := f.ids.Session(ctx, before); err == nil {
		t.Error("the session before the step-up survived")
	}

	// A step-up to mfa, with no acr_values configured for it: max_age only.
	q = authorizeQuery(t, f.startWith(t, url.Values{"assurance": {"mfa"}}))
	if q.Has("acr_values") || q.Get("max_age") != "0" {
		t.Errorf("mfa step-up asks for %v", q)
	}
	// Exceeding the level asked for is fine; no return path means /.
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "amr": []string{"hwk"}}); code != http.StatusSeeOther || f.last.Header.Get("Location") != "/" {
		t.Errorf("mfa step-up: %d %q", code, f.last.Header.Get("Location"))
	}
}

func TestStepUpRefusals(t *testing.T) {
	f := setupWith(t, stepUpPolicy)
	for _, params := range []url.Values{
		{"assurance": {"none"}}, {"assurance": {"MFA"}}, {"assurance": {"high"}},
		{"return": {"//evil.example"}}, {"assurance": {"mfa"}, "return": {"https://evil.example/"}},
	} {
		if resp := f.startWith(t, params); resp.StatusCode != http.StatusBadRequest || len(resp.Cookies()) != 0 {
			t.Errorf("%v: %d, cookies %v", params, resp.StatusCode, resp.Cookies())
		}
	}
	// A flow cookie whose return path or level was changed is refused at
	// the callback, before the code is used.
	for _, field := range []struct {
		i int
		v string
	}{{5, encodeReturn("//evil.example")}, {5, "!!"}, {5, encodeReturn("/") + ".x"}, {4, "none"}, {4, "root"}} {
		q := authorizeQuery(t, f.startWith(t, url.Values{"assurance": {"mfa"}, "return": {"/t/acme/"}}))
		setFlowPart(t, f, field.i, field.v)
		if code := f.finish(t, q, q.Get("state"), map[string]any{"amr": []string{"otp"}}); code != http.StatusBadRequest || f.session(t) != "" {
			t.Errorf("flow cookie part %d = %q: %d", field.i, field.v, code)
		}
	}
}

// With a banner, /auth/login without the acknowledgement sends the user to
// agree first and keeps the step-up's parameters for the login page.
func TestStepUpThroughBanner(t *testing.T) {
	f := setupWith(t, withBanner)
	resp, err := f.client.Get(f.app.URL + "/auth/login?assurance=mfa&return=%2Ft%2Facme%2F")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?assurance=mfa&return=%2Ft%2Facme%2F" {
		t.Errorf("%d %q", resp.StatusCode, resp.Header.Get("Location"))
	}	// Only the validated first value goes on, never a second, unchecked one.
	resp, err = f.client.Get(f.app.URL + "/auth/login?assurance=mfa&assurance=x&return=%2Fok&return=%2F%2Fevil.example")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login?assurance=mfa&return=%2Fok" {
		t.Errorf("repeated parameters: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestStepUpACRFromEnv(t *testing.T) {
	p, err := identity.AssurancePolicyFromEnv(func(k string) string {
		return map[string]string{identity.EnvStepUpPhishingResistantACR: " phr, phrh "}[k]
	})
	if err != nil || strings.Join(p.StepUpPhishingResistantACR, " ") != "phr phrh" || p.StepUpMFAACR != nil {
		t.Errorf("%+v %v", p, err)
	}
	if _, err := identity.AssurancePolicyFromEnv(func(k string) string {
		return map[string]string{identity.EnvStepUpMFAACR: "a b"}[k]
	}); err == nil {
		t.Error("a space inside a value accepted")
	}
}

func setFlowPart(t *testing.T, f *fixture, i int, v string) {
	t.Helper()
	u := mustURL(t, f.app.URL)
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == flowCookie {
			parts := strings.Split(c.Value, ".")
			if len(parts) != 6 {
				t.Fatalf("flow cookie has %d parts", len(parts))
			}
			parts[i] = v
			f.client.Jar.SetCookies(u, []*http.Cookie{{Name: flowCookie, Value: strings.Join(parts, "."), Path: "/", Secure: true, HttpOnly: true}})
			return
		}
	}
	t.Fatal("no flow cookie")
}
