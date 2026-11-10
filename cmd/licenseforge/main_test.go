package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ids"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/storetest"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
	t.Setenv("LICENSEFORGE_RETENTION_DATABASE_URL", "")
	t.Setenv("LICENSEFORGE_DRAIN", "0s")
	t.Setenv("LICENSEFORGE_DATABASE_URL", tenant)
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", platform)
	t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", env.IdentityURL)
	t.Setenv("LICENSEFORGE_MASTER_KEYS", keys)
	for _, k := range []string{"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "SESSION_IDLE_TIMEOUT", "SESSION_MAX_AGE", "LOGIN_BANNER",
		"AUDIT_OTLP_ENDPOINT", "AUDIT_OTLP_CA_FILE", "AUDIT_OTLP_CERT_FILE", "AUDIT_OTLP_KEY_FILE", "AUDIT_OTLP_HEADERS",
		"AUDIT_SYSLOG_ADDR", "AUDIT_SYSLOG_CA_FILE", "AUDIT_SYSLOG_CERT_FILE", "AUDIT_SYSLOG_KEY_FILE", "AUDIT_SYSLOG_SERVER_NAME", "AUDIT_SYSLOG_SD_ID",
		"TRUSTED_PROXIES", "RATE_LIMIT_ACTIVATION", "RATE_LIMIT_MANAGEMENT", "RATE_LIMIT_LOGIN",
		"AUDIT_VERIFY_INTERVAL", "AUDIT_VERIFY_FULL_INTERVAL",
		"WEBHOOK_WORKERS", "WEBHOOK_ALLOW_CIDRS", "WEBHOOK_DENY_CIDRS", "WEBHOOK_PORTS"} {
		t.Setenv("LICENSEFORGE_"+k, "")
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// startServe runs serve and returns its address, its metrics address and a
// function that stops it and returns serve's error.
func startServe(t *testing.T) (string, string, func() error) {
	t.Helper()
	ln, mln := listen(t), listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, ln, mln, quiet) }()
	// Ready once it answers: serve opens the database before it serves, and
	// stopping it during that is a startup error, not a clean stop.
	probe := &http.Client{Timeout: 2 * time.Second}
	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		if resp, err := probe.Get("http://" + ln.Addr().String() + "/healthz"); err == nil {
			_ = resp.Body.Close()
			break
		}
		select {
		case err := <-errc:
			cancel()
			t.Fatalf("serve stopped while starting: %v", err)
		default:
		}
		if time.Since(start) > 30*time.Second {
			cancel()
			select { // don't leave it running into the next test
			case err := <-errc:
				t.Logf("serve: %v", err)
			case <-time.After(20 * time.Second):
			}
			t.Fatal("serve didn't start")
		}
	}
	return ln.Addr().String(), mln.Addr().String(), func() error {
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
	addr, maddr, stop := startServe(t)
	client := &http.Client{Timeout: 2 * time.Second}
	fetch := func(host, p string) (int, string) {
		resp, err := client.Get("http://" + host + p)
		if err != nil {
			return 0, ""
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	get := func(path ...string) int {
		p := "/readyz"
		if len(path) > 0 {
			p = path[0]
		}
		code, _ := fetch(addr, p)
		return code
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
	// /metrics is on its own listener only (no auth: never public).
	if code, body := fetch(addr, "/metrics"); strings.Contains(body, "licenseforge_http_requests_total") || strings.Contains(body, "go_goroutines") {
		t.Errorf("public listener serves metrics (%d)", code)
	}
	code, body := fetch(maddr, "/metrics")
	for _, want := range []string{
		`licenseforge_http_requests_total{code="2xx",route="GET /readyz"}`,
		`licenseforge_db_pool_open_connections{pool="tenant"}`, `licenseforge_db_pool_open_connections{pool="identity"}`,
		`licenseforge_logins_total{outcome="success"} 0`, "go_goroutines", "process_cpu_seconds_total",
	} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("metrics listener: %d, missing %s", code, want)
		}
	}
	if strings.Contains(body, `route="/metrics"`) || strings.Contains(body, `route="GET /metrics"`) {
		t.Error("scrapes counted as public requests")
	}
	if code := get("/metrics"); code == 0 {
		t.Error("public listener down")
	}
	if code, _ := fetch(maddr, "/readyz"); code != http.StatusNotFound {
		t.Errorf("metrics listener serves /readyz: %d", code)
	}
	if code := get("/api/v1/tenants/acme/api-tokens"); code != http.StatusUnauthorized { // the API is mounted
		t.Errorf("api without credentials = %d", code)
	}
	// API requests carry the API's own route pattern, not the /api/v1/ mount, nor the tenant.
	_ = get("/api/v1/nope")
	_, body = fetch(maddr, "/metrics")
	for _, want := range []string{`licenseforge_http_requests_total{code="4xx",route="GET /api/v1/tenants/{tenant}/api-tokens"}`,
		`licenseforge_http_requests_total{code="4xx",route="/api/v1/"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics: missing %s", want)
		}
	}
	if strings.Contains(body, "acme") {
		t.Error("tenant slug in metrics")
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
		"no tenant URL":          {"", env.PlatformURL, testKeys, "", "LICENSEFORGE_DATABASE_URL is not set"},
		"no platform URL":        {env.TenantURL, "", testKeys, "", "LICENSEFORGE_PLATFORM_DATABASE_URL is not set"},
		"no keys":                {env.TenantURL, env.PlatformURL, "", "", "LICENSEFORGE_MASTER_KEYS is not set"},
		"bad keys":               {env.TenantURL, env.PlatformURL, "k1=short", "", "LICENSEFORGE_MASTER_KEYS: secrets:"},
		"owner as tenant":        {env.OwnerURL, env.PlatformURL, testKeys, "", "unsafe database role"},
		"owner as platform":      {env.TenantURL, env.OwnerURL, testKeys, "", "unsafe database role"},
		"pools swapped":          {env.PlatformURL, env.TenantURL, testKeys, "", "unsafe database role"},
		"owner login in env":     {env.TenantURL, env.PlatformURL, testKeys, env.OwnerURL, "must not hold the owner login"},
		"retention login in env": {env.TenantURL, env.PlatformURL, testKeys, "", "must not hold the retention login"},
		"negative drain":         {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_DRAIN"},
		"no identity URL":        {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_IDENTITY_DATABASE_URL is not set"},
		"platform as identity":   {env.TenantURL, env.PlatformURL, testKeys, "", "identity pool"},
		"OIDC without client":    {env.TenantURL, env.PlatformURL, testKeys, "", "client ID"},
		"syslog without port":    {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_AUDIT_SYSLOG_*"},
		"syslog cert, no key":    {env.TenantURL, env.PlatformURL, testKeys, "", "both the certificate and the key"},
		"OTLP over plain http":   {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_AUDIT_OTLP_*"},
		"bad idle timeout":       {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_SESSION_IDLE_TIMEOUT: want a duration"},
		"idle timeout too low":   {env.TenantURL, env.PlatformURL, testKeys, "", "idle timeout 1m0s"},
		"max age over a day":     {env.TenantURL, env.PlatformURL, testKeys, "", "max age 25h0m0s"},
		"max age below idle":     {env.TenantURL, env.PlatformURL, testKeys, "", "below the idle timeout"},
		"bad banner":             {env.TenantURL, env.PlatformURL, testKeys, "", "login banner"},
		"bad trusted proxy":      {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_TRUSTED_PROXIES"},
		"negative rate limit":    {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_RATE_LIMIT_LOGIN"},
		"bad rate limit":         {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_RATE_LIMIT_MANAGEMENT"},
		"bad verify interval":    {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_AUDIT_VERIFY_INTERVAL"},
		"no full verify":         {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL"},
		"bad webhook workers":    {env.TenantURL, env.PlatformURL, testKeys, "", "LICENSEFORGE_WEBHOOK_WORKERS"},
		"bad webhook CIDR":       {env.TenantURL, env.PlatformURL, testKeys, "", "webhooks: CIDR"},
		"bad webhook port":       {env.TenantURL, env.PlatformURL, testKeys, "", "webhooks: port"},
	} {
		setEnv(t, c.tenant, c.platform, c.keys)
		t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", c.owner)
		switch name {
		case "retention login in env":
			t.Setenv("LICENSEFORGE_RETENTION_DATABASE_URL", env.RetentionURL)
		case "negative drain":
			t.Setenv("LICENSEFORGE_DRAIN", "-1s")
		case "no identity URL":
			t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", "")
		case "platform as identity":
			t.Setenv("LICENSEFORGE_IDENTITY_DATABASE_URL", env.PlatformURL)
		case "bad webhook workers":
			t.Setenv("LICENSEFORGE_WEBHOOK_WORKERS", "100")
		case "bad webhook CIDR":
			t.Setenv("LICENSEFORGE_WEBHOOK_ALLOW_CIDRS", "10.0.0.0/33")
		case "bad webhook port":
			t.Setenv("LICENSEFORGE_WEBHOOK_PORTS", "443,0")
		case "OTLP over plain http":
			t.Setenv("LICENSEFORGE_AUDIT_OTLP_ENDPOINT", "http://otel.example:4318/v1/logs")
		case "syslog without port":
			t.Setenv("LICENSEFORGE_AUDIT_SYSLOG_ADDR", "siem.example")
		case "syslog cert, no key":
			t.Setenv("LICENSEFORGE_AUDIT_SYSLOG_ADDR", "siem.example:6514")
			t.Setenv("LICENSEFORGE_AUDIT_SYSLOG_CERT_FILE", "/nonexistent.crt")
		case "OIDC without client":
			t.Setenv("LICENSEFORGE_OIDC_ISSUER", "https://idp.example")
		case "bad idle timeout":
			t.Setenv("LICENSEFORGE_SESSION_IDLE_TIMEOUT", "1 hour")
		case "idle timeout too low":
			t.Setenv("LICENSEFORGE_SESSION_IDLE_TIMEOUT", "1m")
		case "max age over a day":
			t.Setenv("LICENSEFORGE_SESSION_MAX_AGE", "25h")
		case "max age below idle":
			t.Setenv("LICENSEFORGE_SESSION_IDLE_TIMEOUT", "3h")
			t.Setenv("LICENSEFORGE_SESSION_MAX_AGE", "2h")
		case "bad trusted proxy":
			t.Setenv("LICENSEFORGE_TRUSTED_PROXIES", "10.0.0.0/8, proxy.local")
		case "negative rate limit":
			t.Setenv("LICENSEFORGE_RATE_LIMIT_LOGIN", "-1")
		case "bad rate limit":
			t.Setenv("LICENSEFORGE_RATE_LIMIT_MANAGEMENT", "600/min")
		case "bad verify interval":
			t.Setenv("LICENSEFORGE_AUDIT_VERIFY_INTERVAL", "-1m")
		case "no full verify":
			t.Setenv("LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL", "0")
		case "bad banner":
			t.Setenv("LICENSEFORGE_OIDC_ISSUER", "https://idp.example")
			t.Setenv("LICENSEFORGE_LOGIN_BANNER", strings.Repeat("x", 4097))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // a serve that doesn't refuse returns nil here
		err := serve(ctx, listen(t), listen(t), quiet)
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

// A metrics listener that fails stops the server with an error naming it.
func TestServeFailsWithMetricsListener(t *testing.T) {
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	mln := listen(t)
	_ = mln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := serve(ctx, listen(t), mln, quiet); err == nil || !strings.Contains(err.Error(), "metrics listener") {
		t.Errorf("serve = %v, want a metrics listener error", err)
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	t.Setenv("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS", "")
	t.Setenv("LICENSEFORGE_RETENTION_DATABASE_URL", "")
	if err := prune(ctx, quiet); err == nil || !strings.Contains(err.Error(), "LICENSEFORGE_RETENTION_DATABASE_URL is not set") {
		t.Errorf("prune without the login = %v", err)
	}
	t.Setenv("LICENSEFORGE_RETENTION_DATABASE_URL", env.PlatformURL)
	if err := prune(ctx, quiet); err == nil || !strings.Contains(err.Error(), "unsafe database role") {
		t.Errorf("prune with the platform login = %v", err)
	}
	t.Setenv("LICENSEFORGE_RETENTION_DATABASE_URL", env.RetentionURL)
	for _, bad := range []string{"30", "1y", "-400", "36501"} {
		t.Setenv("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS", bad)
		if err := prune(ctx, quiet); err == nil || !strings.Contains(err.Error(), "LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS") {
			t.Errorf("platform days %q: %v", bad, err)
		}
	}
	t.Setenv("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS", "400")
	if err := prune(ctx, quiet); err != nil {
		t.Errorf("prune = %v", err)
	}
}

// With a syslog collector configured, serve registers the sink before
// serving and starts the exporter (here against a closed port, so its
// rounds fail and are counted).
func TestServeStartsAuditExport(t *testing.T) {
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	closed := listen(t)
	addr := closed.Addr().String()
	_ = closed.Close()
	t.Setenv("LICENSEFORGE_AUDIT_SYSLOG_ADDR", addr)
	t.Setenv("LICENSEFORGE_AUDIT_OTLP_ENDPOINT", "http://"+addr+"/v1/logs")
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error { // something to export
		_, err := audit.Record(context.Background(), tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := map[string]float64{"syslog": testutil.ToFloat64(metrics.AuditExportFailures.WithLabelValues("syslog")),
		"otlp": testutil.ToFloat64(metrics.AuditExportFailures.WithLabelValues("otlp"))}
	_, _, stop := startServe(t)
	defer func() { _ = stop() }()
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var registered int
		_ = owner.QueryRow(`SELECT count(*) FROM audit_export_sinks WHERE id IN ('syslog', 'otlp')`).Scan(&registered)
		running := testutil.ToFloat64(metrics.AuditExportFailures.WithLabelValues("syslog")) > before["syslog"] &&
			testutil.ToFloat64(metrics.AuditExportFailures.WithLabelValues("otlp")) > before["otlp"]
		if registered == 2 && running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of 2 sinks registered, both exporters running: %v", registered, running)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The public listener limits per client address before anything else
// (ADR-0032 step 0); health checks and the dashboard aren't limited.
func TestServeRateLimits(t *testing.T) {
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	t.Setenv("LICENSEFORGE_RATE_LIMIT_MANAGEMENT", "2")
	addr, maddr, stop := startServe(t)
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	get := func(host, p string) (*http.Response, string) {
		resp, err := client.Get("http://" + host + p)
		if err != nil {
			return nil, ""
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	for range 50 { // until serve has opened the database
		if resp, _ := get(addr, "/readyz"); resp != nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The limiter's window is the wall-clock minute: start well inside one, so
	// the three requests (milliseconds) can't straddle a reset.
	if now := time.Now(); now.Sub(now.Truncate(time.Minute)) > 58*time.Second {
		time.Sleep(now.Truncate(time.Minute).Add(time.Minute + 50*time.Millisecond).Sub(now))
	}
	var codes []int
	for range 3 {
		resp, _ := get(addr, "/api/v1/tenants/acme/api-tokens")
		if resp == nil {
			t.Fatal("no response")
		}
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests && (resp.Header.Get("Retry-After") == "" || resp.Header.Get("RateLimit-Policy") != `"address-management";q=2;w=60`) {
			t.Errorf("429 headers: %v", resp.Header)
		}
	}
	if codes[0] != http.StatusUnauthorized || codes[1] != http.StatusUnauthorized || codes[2] != http.StatusTooManyRequests {
		t.Errorf("codes %v, want 401 401 429", codes)
	}
	for range 5 {
		if resp, _ := get(addr, "/healthz"); resp == nil || resp.StatusCode != http.StatusOK {
			t.Fatal("health check limited")
		}
	}
	if _, body := get(maddr, "/metrics"); !strings.Contains(body, `licenseforge_rate_limited_requests_total{surface="management"}`) ||
		!strings.Contains(body, `licenseforge_rate_limited_requests_total{surface="login"} 0`) {
		t.Error("metrics: no rate-limit counter by surface")
	}
}

// serve starts the periodic audit verification: its first run writes a
// checkpoint to the platform chain.
func TestServeVerifiesAudit(t *testing.T) {
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	admin, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	count := func() (n int) {
		if err := admin.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'audit.checkpoint'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	// This process's verifier: only serve sets the gauge here, after a run.
	metrics.AuditVerifyLastSuccess.Set(0)
	start := time.Now()
	_, _, stop := startServe(t)
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	for range 100 {
		if testutil.ToFloat64(metrics.AuditVerifyLastSuccess) >= float64(start.Unix()) && count() > before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("no audit verification run (and checkpoint) after start")
}

// `licenseforge tenant create` makes a tenant and its first owner's
// invitation on the platform login (ADR-0042); the printed token is the one
// the owner accepts with.
func TestTenantCreate(t *testing.T) {
	ctx := context.Background()
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", env.PlatformURL)
	slug := "cli-" + strings.ToLower(ids.New("x")[2:10])
	var out bytes.Buffer
	if err := tenantCreate(ctx, []string{"--slug", slug, "--name", "Via CLI", "--owner-email", "cli.owner@example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^tenant (\S+) \((tnt_\S+)\) created\ninvite for cli\.owner@example\.com, valid until \S+, shown once:\n  /invite#token=(\S+)$`).FindStringSubmatch(out.String())
	if m == nil || m[1] != slug {
		t.Fatalf("output:\n%s", out.String())
	}
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	var uid string
	if err := d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail("cli.owner@example.com").SetEmailVerified(true).Save(ctx)
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	mem, err := d.AcceptInvitation(ctx, m[3], uid, func(*ent.Tx, *ent.Membership) error { return nil })
	if err != nil || mem.TenantID != m[2] || mem.Role != membership.RoleOwner {
		t.Fatalf("accept: %+v, %v", mem, err)
	}
	// --test makes a test-mode tenant (ADR-0047), and says so.
	var tout bytes.Buffer
	if err := tenantCreate(ctx, []string{"--slug", slug + "-t", "--name", "Sandbox", "--owner-email", "t@example.com", "--test"}, &tout); err != nil ||
		!strings.Contains(tout.String(), " created in test mode\n") {
		t.Fatalf("--test: %v\n%s", err, tout.String())
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for s, want := range map[string]bool{slug: false, slug + "-t": true} {
			tn, err := tx.Tenant.Query().Where(tenant.Slug(s)).Only(ctx)
			if err != nil {
				return err
			}
			if tn.Test != want {
				t.Errorf("%s: test = %v", s, tn.Test)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Refused: a taken slug, a missing flag, a stray argument, no platform login.
	if err := tenantCreate(ctx, []string{"--slug", slug, "--name", "Again", "--owner-email", "a@b.example"}, io.Discard); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("taken slug: %v", err)
	}
	for _, args := range [][]string{{"--slug", "x-1", "--name", "X"}, {"--slug", "x-2", "--name", "X", "--owner-email", "a@b.example", "extra"}} {
		if err := tenantCreate(ctx, args, io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
	// Not the platform login: the owner login could write, so only the role
	// check refuses it.
	for name, dsn := range map[string]string{"tenant": env.TenantURL, "owner": env.OwnerURL} {
		t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", dsn)
		if err := tenantCreate(ctx, []string{"--slug", "x-3-" + name, "--name", "X", "--owner-email", "a@b.example"}, io.Discard); err == nil {
			t.Errorf("ran on the %s login", name)
		}
	}
}

// `licenseforge tenant invite-owner` re-issues a lost owner invitation.
func TestTenantInviteOwner(t *testing.T) {
	ctx := context.Background()
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", env.PlatformURL)
	slug := "cli-re-" + strings.ToLower(ids.New("x")[2:10])
	if err := tenantCreate(ctx, []string{"--slug", slug, "--name", "Lost", "--owner-email", "lost@example.com"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := tenantInviteOwner(ctx, []string{"--tenant", slug, "--owner-email", "found@example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^tenant ` + slug + ` \(tnt_\S+\): 1 earlier owner invitation\(s\) revoked\ninvite for found@example\.com, valid until \S+, shown once:\n  /invite#token=\S+$`).MatchString(out.String()) {
		t.Fatalf("output:\n%s", out.String())
	}
	for _, args := range [][]string{{"--tenant", slug}, {"--tenant", slug, "--owner-email", "a@b.example", "extra"}, {"--tenant", "no-such-tenant", "--owner-email", "a@b.example"}} {
		if err := tenantInviteOwner(ctx, args, io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
	t.Setenv("LICENSEFORGE_PLATFORM_DATABASE_URL", env.TenantURL)
	if err := tenantInviteOwner(ctx, []string{"--tenant", slug, "--owner-email", "a@b.example"}, io.Discard); err == nil {
		t.Error("ran on the tenant login")
	}
}

// Webhook settings: 0 workers starts nothing; out-of-range counts are refused.
func TestWebhookDispatcherSettings(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	for v, ok := range map[string]bool{"": true, "0": true, "8": true, "64": true, "-1": false, "65": false, "x": false} {
		t.Setenv("LICENSEFORGE_WEBHOOK_WORKERS", v)
		start, err := webhookDispatcher(nil, nil, log)
		if (err == nil) != ok {
			t.Errorf("workers %q: %v", v, err)
		}
		if v == "0" && start != nil {
			t.Error("0 workers starts a dispatcher")
		}
		if ok && v != "0" && start == nil {
			t.Errorf("workers %q: nothing to start", v)
		}
	}
}

// Secrets from mounted files (key_FILE): read, trailing line break dropped;
// both set, an empty file or a missing one is an error (DISA V-242415).
func TestSecretEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("LF_T", "")
	t.Setenv("LF_T_FILE", "")
	if v, err := secretEnv("LF_T"); v != "" || err != nil {
		t.Errorf("unset: %q %v", v, err)
	}
	t.Setenv("LF_T", "from-env")
	if v, err := secretEnv("LF_T"); v != "from-env" || err != nil {
		t.Errorf("env: %q %v", v, err)
	}
	t.Setenv("LF_T_FILE", write("both", "x"))
	if _, err := secretEnv("LF_T"); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("both: %v", err)
	}
	t.Setenv("LF_T", "")
	for content, want := range map[string]string{"postgres://u@h/db\n": "postgres://u@h/db", "k1=abc\r\n": "k1=abc", "  spaced \n": "  spaced "} {
		t.Setenv("LF_T_FILE", write("f", content))
		if v, err := secretEnv("LF_T"); v != want || err != nil {
			t.Errorf("%q: %q %v", content, v, err)
		}
	}
	for name, path := range map[string]string{"empty": write("empty", "\n"), "missing": filepath.Join(dir, "nope"), "BOM": write("bom", "\ufeffpostgres://u@h/db")} {
		t.Setenv("LF_T_FILE", path)
		if _, err := secretEnv("LF_T"); err == nil {
			t.Errorf("%s file: no error", name)
		}
	}
	if _, err := mustEnv("LF_T"); err == nil {
		t.Error("mustEnv with a missing file")
	}
}

// serve starts with every secret from files, and refuses the owner and
// retention logins given as files too.
func TestServeWithSecretFiles(t *testing.T) {
	dir := t.TempDir()
	file := func(key, v string) {
		p := filepath.Join(dir, key)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, "")
		t.Setenv(key+"_FILE", p)
	}
	setEnv(t, env.TenantURL, env.PlatformURL, testKeys)
	file("LICENSEFORGE_DATABASE_URL", env.TenantURL)
	file("LICENSEFORGE_PLATFORM_DATABASE_URL", env.PlatformURL)
	file("LICENSEFORGE_IDENTITY_DATABASE_URL", env.IdentityURL)
	file("LICENSEFORGE_MASTER_KEYS", testKeys)
	_, _, stop := startServe(t) // fails the test if serve can't start
	if err := stop(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	for key, want := range map[string]string{"LICENSEFORGE_OWNER_DATABASE_URL": "owner login", "LICENSEFORGE_RETENTION_DATABASE_URL": "retention login"} {
		file(key, "postgres://x@localhost/db")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // a broken refusal would serve
		if err := serve(ctx, listen(t), listen(t), quiet); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s_FILE: %v", key, err)
		}
		cancel()
		t.Setenv(key+"_FILE", "")
	}
}
