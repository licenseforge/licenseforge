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
	addr, stop := startServe(t)
	var code int
	for range 50 { // wait for the listener goroutine
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			code = resp.StatusCode
			_ = resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != http.StatusOK {
		t.Errorf("readyz = %d", code)
	}
	if err := stop(); err != nil {
		t.Errorf("serve: %v", err)
	}
}

func TestServeRefuses(t *testing.T) {
	for name, c := range map[string]struct{ tenant, platform, keys, want string }{
		"no tenant URL":   {"", env.PlatformURL, testKeys, "LICENSEFORGE_DATABASE_URL is not set"},
		"no platform URL": {env.TenantURL, "", testKeys, "LICENSEFORGE_PLATFORM_DATABASE_URL is not set"},
		"no keys":         {env.TenantURL, env.PlatformURL, "", "LICENSEFORGE_MASTER_KEYS is not set"},
		"bad keys":        {env.TenantURL, env.PlatformURL, "k1=short", "secrets"},
		"owner as tenant": {env.OwnerURL, env.PlatformURL, testKeys, "unsafe database role"},
		"pools swapped":   {env.PlatformURL, env.TenantURL, testKeys, "unsafe database role"},
	} {
		setEnv(t, c.tenant, c.platform, c.keys)
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
