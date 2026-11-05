// Command licenseforge runs the LicenseForge server, or applies database
// migrations with `licenseforge migrate`.
//
// Configuration comes from the environment (ADR-0005), so Kubernetes Secrets
// can supply it:
//
//	LICENSEFORGE_DATABASE_URL           tenant pool login (licenseforge_api)
//	LICENSEFORGE_PLATFORM_DATABASE_URL  platform pool login (licenseforge_admin)
//	LICENSEFORGE_IDENTITY_DATABASE_URL  login-path pool (licenseforge_login, ADR-0029)
//	LICENSEFORGE_OWNER_DATABASE_URL     schema owner, for `migrate` only
//	LICENSEFORGE_RETENTION_DATABASE_URL audit retention login, for `audit prune` only (ADR-0036)
//	LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS  `audit prune`: the platform chain's retention, at least 365; unset = keep everything
//	LICENSEFORGE_MASTER_KEYS            keyring (ADR-0025)
//	LICENSEFORGE_ADDR                   listen address, default :8080
//	LICENSEFORGE_METRICS_ADDR           Prometheus /metrics, default :9090; never on LICENSEFORGE_ADDR
//	LICENSEFORGE_DRAIN                  wait after SIGTERM before closing, default 5s
//	LICENSEFORGE_OIDC_ISSUER            dashboard login (ADR-0003); unset = no login
//	LICENSEFORGE_OIDC_CLIENT_ID         OIDC client registration, required with the issuer
//	LICENSEFORGE_OIDC_CLIENT_SECRET     empty for a public client (PKCE only)
//	LICENSEFORGE_OIDC_REDIRECT_URL      https://<host>/auth/callback
//	LICENSEFORGE_SESSION_IDLE_TIMEOUT   dashboard session idle timeout, default 1h (5m to 24h, AC-12)
//	LICENSEFORGE_SESSION_MAX_AGE        dashboard session lifetime, default 12h (1h to 24h, at least the idle timeout)
//	LICENSEFORGE_LOGIN_BANNER           system use notification shown before login (AC-8), plain text up to 4 KB
//	LICENSEFORGE_API_HOST               API-only host (api.example.com): tokens only there, sessions only elsewhere; unset = both
//	LICENSEFORGE_BOOTSTRAP_ADMIN        issuer|subject (or a verified email) made platform admin at login while there is none
//
// The serving process refuses to start if the owner or the retention login is
// in its environment: serving pods must never hold them (ADR-0009, ADR-0036).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"licenseforge.io/licenseforge/internal/activations"
	"licenseforge.io/licenseforge/internal/api"
	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/invitations"
	"licenseforge.io/licenseforge/internal/issue"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/members"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/retention"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/weblogin"
	"licenseforge.io/licenseforge/web"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	addr := flag.String("addr", envOr("LICENSEFORGE_ADDR", ":8080"), "listen address")
	metricsAddr := flag.String("metrics-addr", envOr("LICENSEFORGE_METRICS_ADDR", ":9090"), "metrics listen address (no auth: keep it off the public network)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: licenseforge [flags]       run the server\n       licenseforge migrate       apply database migrations\n       licenseforge audit prune   apply audit retention (ADR-0036)\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); stop() }() // after the first signal, a second one exits at once

	cmd := strings.Join(flag.Args(), " ")
	var err error
	switch cmd {
	case "":
		var ln, mln net.Listener
		if ln, err = net.Listen("tcp", *addr); err == nil {
			if mln, err = net.Listen("tcp", *metricsAddr); err == nil {
				err = serve(ctx, ln, mln, log)
			} else {
				_ = ln.Close()
			}
		}
	case "migrate":
		err = migrate(ctx, log)
	case "audit prune":
		err = prune(ctx, log)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}

// prune applies audit retention (ADR-0036) with the retention login:
// tenants' audit_retention_days, and LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS
// (unset: keep everything) for the platform chain. Run it as the CronJob.
func prune(ctx context.Context, log *slog.Logger) error {
	dsn, err := mustEnv("LICENSEFORGE_RETENTION_DATABASE_URL")
	if err != nil {
		return err
	}
	platformDays := 0
	if v := os.Getenv("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS"); v != "" {
		if platformDays, err = strconv.Atoi(v); err != nil || platformDays < retention.MinDays {
			return fmt.Errorf("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS: want whole days, at least %d; got %q", retention.MinDays, v)
		}
	}
	r, err := store.OpenRetention(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	cuts, err := retention.Prune(ctx, r, platformDays)
	var deleted int64
	for _, c := range cuts {
		deleted += c.Deleted
		log.Info("audit retention cut", "chain", c.TenantID, "through_seq", c.Through, "deleted", c.Deleted)
	}
	log.Info("audit retention done", "cuts", len(cuts), "deleted", deleted, "platform_days", platformDays)
	return err
}

func migrate(ctx context.Context, log *slog.Logger) error {
	dsn, err := mustEnv("LICENSEFORGE_OWNER_DATABASE_URL")
	if err != nil {
		return err
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Info("migrations applied", "version", version)
	return nil
}

// serve runs the server on ln, and /metrics alone on mln, until ctx is done.
// It closes both.
func serve(ctx context.Context, ln, mln net.Listener, log *slog.Logger) error {
	defer func() { _ = ln.Close(); _ = mln.Close() }()
	if os.Getenv("LICENSEFORGE_OWNER_DATABASE_URL") != "" {
		return errors.New("LICENSEFORGE_OWNER_DATABASE_URL is set: the server must not hold the owner login; use it for `licenseforge migrate` only")
	}
	if os.Getenv("LICENSEFORGE_RETENTION_DATABASE_URL") != "" { // ADR-0036: no DELETE on audit entries in serving pods
		return errors.New("LICENSEFORGE_RETENTION_DATABASE_URL is set: the server must not hold the retention login; use it for `licenseforge audit prune` only")
	}
	drain, err := time.ParseDuration(envOr("LICENSEFORGE_DRAIN", "5s"))
	if err != nil || drain < 0 {
		return fmt.Errorf("LICENSEFORGE_DRAIN: want a duration like 5s, got %q", os.Getenv("LICENSEFORGE_DRAIN"))
	}
	tenantDSN, err := mustEnv("LICENSEFORGE_DATABASE_URL")
	if err != nil {
		return err
	}
	platformDSN, err := mustEnv("LICENSEFORGE_PLATFORM_DATABASE_URL")
	if err != nil {
		return err
	}
	identityDSN, err := mustEnv("LICENSEFORGE_IDENTITY_DATABASE_URL")
	if err != nil {
		return err
	}
	keys, err := mustEnv("LICENSEFORGE_MASTER_KEYS")
	if err != nil {
		return err
	}
	keyring, err := secrets.ParseKeyring(keys)
	if err != nil { // fail at start, not on first use
		return fmt.Errorf("LICENSEFORGE_MASTER_KEYS: %w", err)
	}
	// A database outage at start is a crash loop (Kubernetes retries), not "not ready".
	openCtx, cancelOpen := context.WithTimeout(ctx, 30*time.Second)
	db, err := store.Open(openCtx, store.Logins{Tenant: tenantDSN, Platform: platformDSN, Identity: identityDSN})
	cancelOpen()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	metrics.SetPools(db.Stats)

	var draining atomic.Bool
	ready := func(ctx context.Context) error {
		if draining.Load() {
			return errors.New("shutting down")
		}
		return db.Ping(ctx)
	}
	mux := newMux(ready, log)
	// Sessions everywhere (dashboard and API) use the configured timeouts.
	ids, err := sessionTimeouts(identity.Service{DB: db})
	if err != nil {
		return err
	}
	var sessions *weblogin.Sessions
	if issuer := os.Getenv("LICENSEFORGE_OIDC_ISSUER"); issuer != "" {
		discoverCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		login, err := weblogin.New(discoverCtx, weblogin.Config{
			Issuer:       issuer,
			ClientID:     os.Getenv("LICENSEFORGE_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("LICENSEFORGE_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("LICENSEFORGE_OIDC_REDIRECT_URL"),
			Banner:       os.Getenv("LICENSEFORGE_LOGIN_BANNER"),
			// Read only here, at start: a later change needs a restart.
			BootstrapAdmin: os.Getenv("LICENSEFORGE_BOOTSTRAP_ADMIN"),
		}, ids, log)
		cancel()
		if err != nil {
			return err
		}
		login.Register(mux)
		sessions = login.Sessions()
	} else {
		log.Warn("LICENSEFORGE_OIDC_ISSUER is not set: dashboard login is off")
	}
	// API tokens need only the tenant pool (hashes, no keyring); license keys
	// and stored idempotent responses (which can hold one) are encrypted, and
	// the activation API decrypts license keys and signs leases.
	mux.Handle(api.Prefix+"/", api.New(api.Config{Tokens: apitokens.Service{DB: db}, Members: members.Service{DB: db}, Invitations: invitations.Service{DB: db}, Identity: ids,
		Licenses: licenses.Service{DB: db, Keys: keyring}, Idempotency: idempotency.Store{DB: db, Keys: keyring},
		Activations: activations.Service{DB: db, Keys: keyring, Issuer: issue.Issuer{DB: db, Keys: signing.Local{DB: db, Keys: keyring}}},
		Sessions:    sessions, APIHost: os.Getenv("LICENSEFORGE_API_HOST"), Log: log}))
	if !web.Embedded {
		log.Warn("built without the dashboard (make web build TAGS=webui): serving a placeholder page")
	}
	srv := &http.Server{
		Handler:           metrics.Instrument(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	msrv := &http.Server{
		Handler:           metricsMux(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc, merrc := make(chan error, 1), make(chan error, 1)
	go func() {
		log.Info("listening", "addr", ln.Addr().String(), "metrics", mln.Addr().String(), "version", version)
		errc <- srv.Serve(ln)
	}()
	go func() { merrc <- msrv.Serve(mln) }()
	defer func() { _ = msrv.Close() }()

	select {
	case err := <-errc:
		return err
	case err := <-merrc:
		return fmt.Errorf("metrics listener: %w", err)
	case <-ctx.Done():
	}

	// Fail readiness first and keep serving while load balancers stop
	// routing here, so a rolling update drops no requests.
	draining.Store(true)
	log.Info("draining", "for", drain.String())
	time.Sleep(drain)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) { // Serve failed during the drain
		return err
	}
	return nil
}

// metricsMux serves /metrics only. It runs on its own listener: the public
// mux never mounts it.
func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	return mux
}

// newMux serves the health endpoints and the dashboard. ready reports whether the database is
// reachable; /readyz fails while it isn't, so Kubernetes stops routing here.
func newMux(ready func(context.Context) error, log *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	text := func(w http.ResponseWriter, code int, s string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(s))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { text(w, http.StatusOK, "ok\n") }) // liveness: no dependencies
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil { // details go to logs, not to unauthenticated callers
			log.Warn("not ready", "err", err)
			text(w, http.StatusServiceUnavailable, "database unavailable\n")
			return
		}
		text(w, http.StatusOK, "ok\n")
	})
	web.Mount(mux) // more specific routes (health, /auth/, /api/) win
	return mux
}

// sessionTimeouts sets s's timeouts from the environment, within bounds.
func sessionTimeouts(s identity.Service) (identity.Service, error) {
	var err error
	for _, v := range []struct {
		key, def string
		to       *time.Duration
	}{
		{"LICENSEFORGE_SESSION_IDLE_TIMEOUT", identity.DefaultIdleTimeout.String(), &s.IdleTimeout},
		{"LICENSEFORGE_SESSION_MAX_AGE", identity.DefaultMaxAge.String(), &s.MaxAge},
	} {
		if *v.to, err = time.ParseDuration(envOr(v.key, v.def)); err != nil {
			return s, fmt.Errorf("%s: want a duration like 30m, got %q", v.key, os.Getenv(v.key))
		}
	}
	if err := identity.CheckSessionTimeouts(s.IdleTimeout, s.MaxAge); err != nil {
		return s, fmt.Errorf("LICENSEFORGE_SESSION_IDLE_TIMEOUT / LICENSEFORGE_SESSION_MAX_AGE: %w", err)
	}
	return s, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is not set", key)
}
