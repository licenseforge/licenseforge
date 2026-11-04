package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestReadyzTimeout(t *testing.T) {
	mux := newMux(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, quiet) // a database that never answers
	start := time.Now()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || time.Since(start) > 3*time.Second {
		t.Errorf("readyz = %d after %v", rec.Code, time.Since(start))
	}
}

func TestHealthEndpoints(t *testing.T) {
	var readyErr error
	mux := newMux(func(context.Context) error { return readyErr }, quiet)
	for _, tc := range []struct {
		method, path string
		down         bool
		want         int
	}{
		{http.MethodGet, "/healthz", false, http.StatusOK},
		{http.MethodGet, "/readyz", false, http.StatusOK},
		{http.MethodGet, "/readyz", true, http.StatusServiceUnavailable},
		{http.MethodGet, "/healthz", true, http.StatusOK}, // liveness ignores the database
		{http.MethodPost, "/healthz", false, http.StatusMethodNotAllowed},
		{http.MethodGet, "/t/acme/", false, http.StatusOK}, // the dashboard
		{http.MethodGet, "/api/v1/nope", false, http.StatusNotFound},
		{http.MethodPost, "/t/acme/", false, http.StatusMethodNotAllowed},
	} {
		readyErr = nil
		if tc.down {
			readyErr = errors.New("connection refused: secret-host")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want || strings.Contains(rec.Body.String(), "secret-host") {
			t.Errorf("%s %s (down=%v) = %d %q, want %d", tc.method, tc.path, tc.down, rec.Code, rec.Body, tc.want)
		}
	}
}

// A route for another method keeps its 405 despite the dashboard's GET /.
func TestDashboardKeepsMethodNotAllowed(t *testing.T) {
	mux := newMux(func(context.Context) error { return nil }, quiet)
	mux.HandleFunc("POST /auth/logout", func(http.ResponseWriter, *http.Request) {})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /auth/logout = %d, Allow %q; want 405, POST", rec.Code, rec.Header().Get("Allow"))
	}
}

// The real mux takes the API as a method-less /api/v1/ subtree (as serve
// mounts it) next to the dashboard without a ServeMux registration panic,
// and each path still reaches its owner.
func TestMuxBesideAPISubtree(t *testing.T) {
	mux := newMux(func(context.Context) error { return nil }, quiet)
	mux.Handle("/api/v1/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) }))
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/tenants/acme/api-tokens", 299},
		{http.MethodPost, "/api/v1/tenants/acme/api-tokens", 299},
		{http.MethodDelete, "/api/v1/x", 299},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/t/acme/", http.StatusOK},
		{http.MethodGet, "/api/v2/x", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

const testKeys = "k1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func setEnv(t *testing.T, tenant, platform, keys string) {
	t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", "")
	t.Setenv("LICENSEFORGE_DRAIN", "0s")
	t.Setenv("LICENSEFORGE_DATABASE_URL", tenant)
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", platform)
	t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", env.IdentityURL)
	t.Setenv("LICENSEFORGE_MASTER_KEYS", keys)
	for _, k := range []string{"ISSUER", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URL"} {
		t.Setenv("LICENSEFORGE_OIDC_"+k, "")
	}
}

// startServe runs serve and returns its address and a function that stops it
// and returns serve's error.
func startServe(t *testing.T) (string, func() error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, ln, quiet) }()
	return ln.Addr().String(), func() error {
		cancel()
		select {
		case err := <-errc:
			return err
		case <-time.After(20 * time.Second):
			return errors.New("serve didn't stop")
		}
	}
}

func TestServe(t *testing.T) {
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	t.Setenv("LICENSEFORGE_DRAIN", "3s")
	addr, stop := startServe(t)
	client := &http.Client{Timeout: 2 * time.Second}
	get := func(path ...string) int {
		p := "/readyz"
		if len(path) > 0 {
			p = path[0]
		}
		resp, err := client.Get("http://" + addr + p)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	var code int
	for range 50 { // the listener is bound; serve may still be opening the database
		if code = get(); code != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Errorf("readyz = %d", code)
	}
	if code := get("/api/v1/tenants/acme/api-tokens"); code != http.StatusUnauthorized { // the API is mounted
		t.Errorf("api without credentials = %d", code)
	}
	errc := make(chan error, 1)
	go func() { errc <- stop() }()
	for range 25 { // until readiness flips; the drain window is still open
		if code = get(); code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable || get("/healthz") != http.StatusOK {
		t.Errorf("while draining: readyz = %d, healthz must stay 200", code)
	}
	if err := <-errc; err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestServeRefuses(t *testing.T) {
	for name, c := range map[string]struct{ tenant, platform, keys, owner, want string }{
		"no tenant URL":        {"", env.PlatformURL, testKeys, "", "LICENSEFORGE_DATABASE_URL is not set"},
		"no platform URL":      {env.TenantURL, "", testKeys, "", "LICENSEFORGE_PLATFORM_DATABASE_URL is not set"},
		"no keys":              {env.TenantURL, env.PlatformURL, "", "", "LICENSEFORGE_MASTER_KEYS is not set"},
		"bad keys":             {env.TenantURL, env.PlatformURL, "k1=short", "", "LICENSEFORGE_MASTER_KEYS: secrets:"},
		"owner as tenant":      {env.OwnerURL, env.PlatformURL, testKeys, "", "unsafe database role"},
		"owner as platform":    {env.TenantURL, env.OwnerURL, testKeys, "", "unsafe database role"},
		"pools swapped":        {env.PlatformURL, env.TenantURL, testKeys, "", "unsafe database role"},
		"owner login in env":   {env.TenantURL, env.PlatformURL, testKeys, env.OwnerURL, "must not hold the owner login"},
		"negative drain":       {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_DRAIN"},
		"no identity URL":      {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_IDENTITY_DATABASE_URL is not set"},
		"platform as identity": {env.TenantURL, env.PlatformURL, testKeys, "", "identity pool"},
		"OIDC without client":  {env.TenantURL, env.PlatformURL, testKeys, "", "client ID"},
	} {
		setEnv(t, c.tenant, c.platform, c.keys)
		t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", c.owner)
		switch name {
		case "negative drain":
			t.Setenv("LICENSEFORGE_DRAIN", "-1s")
		case "no identity URL":
			t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", "")
		case "platform as identity":
			t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", env.PlatformURL)
		case "OIDC without client":
			t.Setenv("LICENSEFORGE_OIDC_ISSUER", "https://idp.example")
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // a serve that doesn't refuse returns nil here
		err = serve(ctx, ln, quiet)
		cancel()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: serve = %v, want %q", name, err, c.want)
		}
	}
}

func TestMigrate(t *testing.T) {
	t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", "")
	if err := migrate(context.Background(), quiet); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Errorf("migrate without URL = %v", err)
	}
	t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", env.OwnerURL)
	if err := migrate(context.Background(), quiet); err != nil { // already migrated: a no-op
		t.Errorf("migrate = %v", err)
	}
}
