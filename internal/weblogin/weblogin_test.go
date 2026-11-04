package weblogin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

// idp is a minimal OIDC provider: discovery, JWKS, and a token endpoint that
// checks PKCE and returns an ID token built from the registered code.
type idp struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	code map[string]grant
	hang int // JWKS requests left to hang (until the client gives up)
}

type grant struct {
	challenge string
	claims    map[string]any
}

func newIdP(t *testing.T) *idp {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, code: map[string]grant{}}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		hang := p.hang > 0
		p.hang--
		p.mu.Unlock()
		if hang { // until the client gives up; past the callback's 15 s, so only a client timeout rescues the next login
			select {
			case <-r.Context().Done():
			case <-time.After(20 * time.Second):
			}
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		g, ok := p.code[r.FormValue("code")]
		delete(p.code, r.FormValue("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": p.sign(t, g.claims)})
	})
	return p
}

func (p *idp) sign(t *testing.T, claims map[string]any) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type fixture struct {
	idp    *idp
	app    *httptest.Server
	ids    identity.Service
	db     *store.DB
	client *http.Client
	logs   *syncBuffer
	ack    string         // ?banner= sent to /auth/login
	last   *http.Response // the last callback's response (body closed)
}

// syncBuffer collects the handler's logs; server goroutines write to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func setup(t *testing.T, opts ...func(*idp)) *fixture { return setupWith(t, nil, opts...) }

// setupWith lets cfg change the handler's configuration and identity service.
func setupWith(t *testing.T, cfg func(*Config, *identity.Service), opts ...func(*idp)) *fixture {
	ctx := context.Background()
	db, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &fixture{idp: newIdP(t), ids: identity.Service{DB: db}, db: db, logs: &syncBuffer{}}
	for _, o := range opts {
		o(f.idp)
	}
	mux := http.NewServeMux()
	// TLS so the browser-side client keeps the Secure __Host- cookies.
	f.app = httptest.NewUnstartedServer(mux)
	f.app.StartTLS()
	t.Cleanup(f.app.Close)
	c := Config{Issuer: f.idp.srv.URL, ClientID: "lf", ClientSecret: "s", RedirectURL: f.app.URL + "/auth/callback"}
	if cfg != nil {
		cfg(&c, &f.ids)
	}
	h, err := New(ctx, c, f.ids, slog.New(slog.NewTextHandler(f.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h.Register(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "home") })
	jar, _ := cookiejar.New(nil)
	f.client = f.app.Client()
	f.client.Jar = jar
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}

// start runs /auth/login and returns the authorize request's parameters.
func (f *fixture) start(t *testing.T) url.Values {
	resp, err := f.client.Get(f.app.URL + "/auth/login?banner=" + url.QueryEscape(f.ack))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), f.idp.srv.URL+"/authorize") {
		t.Fatalf("login: %d %q %v", resp.StatusCode, loc, err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorize request lacks PKCE/state/nonce: %v", q)
	}
	return q
}

// finish registers a code at the IdP with claims (merged over valid ones)
// and calls back with state; it returns the callback response status.
func (f *fixture) finish(t *testing.T, q url.Values, state string, override map[string]any) int {
	claims := map[string]any{
		"iss": f.idp.srv.URL, "aud": "lf", "sub": ids.New("sub"), "nonce": q.Get("nonce"),
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"email": "ana@example.com", "email_verified": true, "name": "Ana",
	}
	for k, v := range override {
		claims[k] = v
	}
	code := rand.Text()
	f.idp.mu.Lock()
	f.idp.code[code] = grant{challenge: q.Get("code_challenge"), claims: claims}
	f.idp.mu.Unlock()
	resp, err := f.client.Get(f.app.URL + "/auth/callback?" + url.Values{"code": {code}, "state": {state}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	f.last = resp
	return resp.StatusCode
}

func (f *fixture) session(t *testing.T) string {
	u, _ := url.Parse(f.app.URL)
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

func TestLogin(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	q := f.start(t)
	sub := ids.New("sub")
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub}); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	first := f.session(t)
	u, err := f.ids.Session(ctx, first)
	if err != nil || u.Subject != sub || u.Issuer != f.idp.srv.URL || !u.EmailVerified || u.Name == nil || *u.Name != "Ana" {
		t.Fatalf("session user = %+v, %v", u, err)
	}
	// The flow cookie is single use: replaying the callback fails.
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub}); code != http.StatusBadRequest {
		t.Errorf("replayed callback: %d", code)
	}
	// Logging in again replaces the session (no fixation).
	q = f.start(t)
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "email_verified": "false"}); code != http.StatusSeeOther {
		t.Fatalf("second login: %d", code)
	}
	if _, err := f.ids.Session(ctx, first); err == nil {
		t.Error("old session survived a new login")
	}
	if u, err = f.ids.Session(ctx, f.session(t)); err != nil || u.EmailVerified {
		t.Errorf(`email_verified "false": %+v, %v`, u, err)
	}
	q = f.start(t)
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "email_verified": "true"}); code != http.StatusSeeOther {
		t.Fatalf("third login: %d", code)
	}
	if u, err = f.ids.Session(ctx, f.session(t)); err != nil || !u.EmailVerified {
		t.Errorf(`email_verified "true": %+v, %v`, u, err)
	}
}

func TestLoginRefusals(t *testing.T) {
	f := setup(t)
	bad := map[string]struct {
		state    func(url.Values) string
		override map[string]any
		want     int
	}{
		"state mismatch": {func(url.Values) string { return "x" }, nil, http.StatusBadRequest},
		"nonce mismatch": {nil, map[string]any{"nonce": "other"}, http.StatusUnauthorized},
		"other audience": {nil, map[string]any{"aud": "someone-else"}, http.StatusUnauthorized},
		"other issuer":   {nil, map[string]any{"iss": "https://evil.example"}, http.StatusUnauthorized},
		"expired token":  {nil, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, http.StatusUnauthorized},
		"no subject":     {nil, map[string]any{"sub": ""}, http.StatusUnauthorized},
		"foreign azp":    {nil, map[string]any{"aud": []string{"lf", "other"}, "azp": "other"}, http.StatusUnauthorized},
	}
	for name, c := range bad {
		q := f.start(t)
		state := q.Get("state")
		if c.state != nil {
			state = c.state(q)
		}
		if code := f.finish(t, q, state, c.override); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
		if f.session(t) != "" {
			t.Errorf("%s: session cookie set", name)
		}
	}
	// PKCE: a code redeemed with another flow's verifier is refused.
	q1, q2 := f.start(t), f.start(t) // the second flow cookie replaces the first
	q2.Set("code_challenge", q1.Get("code_challenge"))
	if code := f.finish(t, q2, q2.Get("state"), nil); code != http.StatusUnauthorized {
		t.Errorf("wrong PKCE verifier: %d", code)
	}
	// A stray callback (cross-site link, no state) leaves the login in
	// progress alone; a provider error for this login ends it.
	q := f.start(t)
	get := func(query string) int {
		t.Helper()
		resp, err := f.client.Get(f.app.URL + "/auth/callback?" + query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("error=access_denied"); code != http.StatusBadRequest {
		t.Errorf("stray callback: %d", code)
	}
	if code := get(url.Values{"error": {"access_denied"}, "state": {q.Get("state")}}.Encode()); code != http.StatusUnauthorized {
		t.Errorf("provider error: %d", code)
	}
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusBadRequest {
		t.Errorf("login after a provider error: %d", code)
	}
	q = f.start(t)
	_ = get("error=access_denied")
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Errorf("login after a stray callback: %d", code)
	}
}

// A provider whose key endpoint hangs fails one login, not all of them.
func TestKeyFetchTimesOut(t *testing.T) {
	old := httpTimeout
	httpTimeout = 500 * time.Millisecond
	t.Cleanup(func() { httpTimeout = old })
	f := setup(t, func(p *idp) { p.hang = 1 })
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusUnauthorized {
		t.Errorf("login while keys hang: %d", code)
	}
	q = f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusSeeOther {
		t.Errorf("login after the hang: %d", code)
	}
}

func TestNewRefusesInsecureURLs(t *testing.T) {
	for _, c := range []Config{
		{Issuer: "http://idp.example", ClientID: "lf", RedirectURL: "https://lf.example/auth/callback"},
		{Issuer: "https://idp.example", ClientID: "lf", RedirectURL: "http://lf.example/auth/callback"},
		{Issuer: "https://idp.example", ClientID: "lf", RedirectURL: "/auth/callback"},
		{Issuer: "https://:443", ClientID: "lf", RedirectURL: "https://lf.example/auth/callback"},
	} {
		if _, err := New(context.Background(), c, identity.Service{}, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "must be https") {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for u, want := range map[string]string{
		"https://LF.Example:443/auth/callback":  "https://lf.example",
		"https://lf.example:8443/auth/callback": "https://lf.example:8443",
		"http://localhost:80/auth/callback":     "http://localhost",
		"https://[::1]:443/x":                   "https://[::1]",
		"https://[::1]:8443/x":                  "https://[::1]:8443",
	} {
		if got, err := origin(u); got != want || err != nil {
			t.Errorf("origin(%s) = %q, %v; want %q", u, got, err, want)
		}
	}
	for _, u := range []string{"https://u:p@lf.example/x", "https://[fe80::1%25en0]/x"} {
		if _, err := origin(u); err == nil {
			t.Errorf("origin(%s) accepted", u)
		}
	}
	for _, u := range []string{"http://localhost:8080/x", "http://127.0.0.1/x", "http://[::1]:8080/x", "https://lf.example/x"} {
		if !secureURL(u) {
			t.Errorf("%s refused", u)
		}
	}
}

func TestLoginDisabledUser(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	sub := ids.New("sub")
	u, err := f.ids.Login(ctx, identity.Claims{Issuer: f.idp.srv.URL, Subject: sub})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.DisableUser(ctx, u.ID, func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub}); code != http.StatusForbidden {
		t.Errorf("disabled user: %d", code)
	}
	if f.session(t) != "" {
		t.Error("session cookie set for a disabled user")
	}
}
