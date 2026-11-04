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
		{http.MethodGet, "/nope", false, http.StatusNotFound},
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

const testKeys = "k1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func setEnv(t *testing.T, tenant, platform, keys string) {
	t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", "")
	t.Setenv("LICENSEFORGE_DRAIN", "0s")
	t.Setenv("LICENSEFORGE_DATABASE_URL", tenant)
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", platform)
	t.Setenv("LICENSEFORGE_MASTER_KEYS", keys)
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
	t.Setenv("LICENSEFORGE_DRAIN", "1s")
	addr, stop := startServe(t)
	client := &http.Client{Timeout: 2 * time.Second}
	get := func() int {
		resp, err := client.Get("http://" + addr + "/readyz")
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
	errc := make(chan error, 1)
	go func() { errc <- stop() }()
	time.Sleep(300 * time.Millisecond) // inside the drain window: still serving, not ready
	if code := get(); code != http.StatusServiceUnavailable {
		t.Errorf("readyz while draining = %d", code)
	}
	if err := <-errc; err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestServeRefuses(t *testing.T) {
	for name, c := range map[string]struct{ tenant, platform, keys, owner, want string }{
		"no tenant URL":      {"", env.PlatformURL, testKeys, "", "LICENSEFORGE_DATABASE_URL is not set"},
		"no platform URL":    {env.TenantURL, "", testKeys, "", "LICENSEFORGE_PLATFORM_DATABASE_URL is not set"},
		"no keys":            {env.TenantURL, env.PlatformURL, "", "", "LICENSEFORGE_MASTER_KEYS is not set"},
		"bad keys":           {env.TenantURL, env.PlatformURL, "k1=short", "", "LICENSEFORGE_MASTER_KEYS: secrets:"},
		"owner as tenant":    {env.OwnerURL, env.PlatformURL, testKeys, "", "unsafe database role"},
		"owner as platform":  {env.TenantURL, env.OwnerURL, testKeys, "", "unsafe database role"},
		"pools swapped":      {env.PlatformURL, env.TenantURL, testKeys, "", "unsafe database role"},
		"owner login in env": {env.TenantURL, env.PlatformURL, testKeys, env.OwnerURL, "must not hold the owner login"},
	} {
		setEnv(t, c.tenant, c.platform, c.keys)
		t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", c.owner)
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
