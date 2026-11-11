//go:build e2e

// Package e2e holds the end-to-end journeys (ADR-0041). They run against the
// environment e2e/env/up.sh deploys, with `make e2e`; not part of `make test`.
package e2e

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// env is where the environment is, from e2e/env/.state/env (written by
// up.sh), overridden by the process environment.
type env struct {
	BaseURL, CAFile, Tenant, InviteTokenFile string
	// KubeContext and Namespace: kubectl's context for the cluster and the
	// e2e namespace (default minikube, licenseforge-e2e: an older env file).
	KubeContext, Namespace string
}

func loadEnv(t *testing.T) env {
	t.Helper()
	vals := map[string]string{}
	path := os.Getenv("E2E_ENV_FILE")
	if path == "" {
		path = filepath.Join("env", ".state", "env")
	}
	if f, err := os.Open(path); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if k, v, ok := strings.Cut(s.Text(), "="); ok {
				vals[k] = v
			}
		}
		_ = f.Close()
	}
	get := func(k string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return vals[k]
	}
	e := env{BaseURL: get("E2E_BASE_URL"), CAFile: get("E2E_CA_FILE"), Tenant: get("E2E_TENANT"), InviteTokenFile: get("E2E_INVITE_TOKEN_FILE"),
		KubeContext: cmp.Or(get("E2E_KUBE_CONTEXT"), "minikube"), Namespace: cmp.Or(get("E2E_NAMESPACE"), "licenseforge-e2e")}
	if e.BaseURL == "" {
		t.Fatalf("no e2e environment: run e2e/env/up.sh first (or set E2E_BASE_URL); read %s", path)
	}
	return e
}

// httpClient trusts the environment's CA (and nothing else, when set).
func (e env) httpClient(t *testing.T, jar http.CookieJar, followRedirects bool) *http.Client {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // a proxy would have to resolve nip.io itself
	// Dial the address a nip.io name carries, without DNS: resolvers with
	// DNS-rebinding protection drop such answers. TLS still checks the name.
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil {
			if m := nipIP.FindStringSubmatch(host); m != nil {
				addr = net.JoinHostPort(m[1], port)
			}
		}
		return dial(ctx, network, addr)
	}
	if e.CAFile != "" {
		pem, err := os.ReadFile(e.CAFile)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("no certificate in %s", e.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c := &http.Client{Transport: tr, Jar: jar, Timeout: 30 * time.Second}
	if !followRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// browser is a signed-in dashboard session: cookies plus the CSRF token.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
	// idem, when set, is the next POST's Idempotency-Key ("-": none),
	// instead of a fresh one for the routes that take one.
	idem string
}

var (
	formAction = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)
	nipIP      = regexp.MustCompile(`\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.nip\.io$`)
)

// login signs in through the identity provider's login form, as a person
// would: /auth/login, the provider's form, the callback, a session.
func login(t *testing.T, e env, username, password string) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := e.httpClient(t, jar, true)
	resp, err := c.Get(e.BaseURL + "/auth/login")
	page := mustRead(t, resp, err)
	m := formAction.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no login form at the identity provider:\n%.400s", page)
	}
	action := strings.ReplaceAll(string(m[1]), "&amp;", "&")
	resp, err = c.PostForm(action, url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Request.URL.Host != mustURL(t, e.BaseURL).Host {
		t.Fatalf("login as %s ended at %s, not back at LicenseForge (wrong password?)", username, resp.Request.URL)
	}
	b := &browser{t: t, base: e.BaseURL, c: c}
	var s struct {
		CSRF string `json:"csrf_token"`
	}
	b.do("GET", "/auth/session", nil, 200, &s)
	if s.CSRF == "" {
		t.Fatal("signed in, but no session")
	}
	b.csrf = s.CSRF
	return b
}

// do sends an API request (JSON body, merge patch for PATCH) and decodes the
// answer into out unless it's nil; any status but want fails the test.
func (b *browser) do(method, path string, body any, want int, out any) {
	b.t.Helper()
	if err := b.try(method, path, body, want, out); err != nil {
		b.t.Fatal(err)
	}
}

// refused sends a request that must be refused with status and problem code.
func (b *browser) refused(method, path string, body any, status int, code string) {
	b.t.Helper()
	var p struct{ Code string }
	if err := b.try(method, path, body, status, &p); err != nil {
		b.t.Error(err)
	} else if p.Code != code {
		b.t.Errorf("%s %s: refused with %q, want %q", method, path, p.Code, code)
	}
}

func (b *browser) try(method, path string, body any, want int, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		ct := "application/json"
		if method == "PATCH" {
			ct = "application/merge-patch+json"
		}
		req.Header.Set("Content-Type", ct)
	}
	if method != "GET" {
		req.Header.Set("X-CSRF-Token", b.csrf)
		req.Header.Set("Origin", b.base)
	}
	if method == "POST" {
		key := b.idem
		if key == "" && (strings.HasSuffix(path, "/licenses") || strings.HasSuffix(path, "/activation-requests")) {
			key = rand.Text()
		}
		if key != "" && key != "-" {
			req.Header.Set("Idempotency-Key", key)
		}
		b.idem = ""
	}
	resp, err := b.c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: %d, want %d: %.500s", method, path, resp.StatusCode, want, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func mustRead(t *testing.T, resp *http.Response, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
