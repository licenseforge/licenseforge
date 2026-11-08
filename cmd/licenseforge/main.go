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
//	LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS  `audit prune`: the platform chain's retention, 365 to 36,500 days; unset = keep everything
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
//	LICENSEFORGE_AUDIT_SYSLOG_ADDR      SIEM collector host:port (RFC 5424 over TLS, ADR-0036); unset = no export
//	LICENSEFORGE_AUDIT_SYSLOG_CA_FILE   PEM roots for the collector's certificate; unset = system roots
//	LICENSEFORGE_AUDIT_SYSLOG_CERT_FILE client certificate (mTLS), PEM, with _KEY_FILE; unset = none
//	LICENSEFORGE_AUDIT_SYSLOG_KEY_FILE
//	LICENSEFORGE_AUDIT_SYSLOG_SERVER_NAME  name the collector's certificate must carry; default the address's host
//	LICENSEFORGE_AUDIT_OTLP_ENDPOINT    OTLP/HTTP logs URL (JSON), https://host:4318/v1/logs (ADR-0036); unset = none
//	LICENSEFORGE_AUDIT_OTLP_CA_FILE, _CERT_FILE, _KEY_FILE  as for syslog
//	LICENSEFORGE_AUDIT_OTLP_HEADERS     request headers, k=v,k2=v2 (values %-encoded), e.g. an API key
//	LICENSEFORGE_AUDIT_SYSLOG_SD_ID     structured data ID name@PEN, default licenseforge@32473
//	LICENSEFORGE_AUDIT_VERIFY_INTERVAL  incremental audit chain verification, default 15m; 0 = off (ADR-0036)
//	LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL  full verification from the anchor, default 168h
//	LICENSEFORGE_BOOTSTRAP_ADMIN        issuer|subject (or a verified email) made platform admin at login while there is none
//	LICENSEFORGE_TRUSTED_PROXIES        CIDRs or addresses of proxies whose X-Forwarded-For is believed; unset = none
//	LICENSEFORGE_RATE_LIMIT_ACTIVATION  requests per client address per minute, per replica, on the activation API; default 1200, 0 = off
//	LICENSEFORGE_RATE_LIMIT_MANAGEMENT  the same for the rest of /api/v1 and /auth/ (except login); default 600, 0 = off
//	LICENSEFORGE_RATE_LIMIT_LOGIN       the same for /auth/login and /auth/callback; default 60, 0 = off
//	LICENSEFORGE_OIDC_MFA_AMR                amr values that count as MFA (comma list; default mfa,otp,swk; ADR-0038)
//	LICENSEFORGE_OIDC_PHISHING_RESISTANT_AMR amr values that count as phishing-resistant MFA (default hwk,sc,pop)
//	LICENSEFORGE_OIDC_MFA_ACR                acr/acrs values that count as MFA (default none)
//	LICENSEFORGE_OIDC_PHISHING_RESISTANT_ACR acr/acrs values that count as phishing-resistant (default none; e.g. phr,phrh on Okta)
//	LICENSEFORGE_PLATFORM_MFA_POLICY         none (default), mfa or phishing_resistant: what platform admins' sessions need on /api/v1/platform (ADR-0038, ADR-0042)
//	LICENSEFORGE_OIDC_STEP_UP_MFA_ACR        acr_values a step-up login to mfa asks for (comma list; default none: max_age=0 only)
//	LICENSEFORGE_OIDC_STEP_UP_PHISHING_RESISTANT_ACR the same for phishing_resistant (e.g. phr on Okta)
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
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/auditexport"
	"licenseforge.io/licenseforge/internal/auditverify"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/catalog"
	"licenseforge.io/licenseforge/internal/customers"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/invitations"
	"licenseforge.io/licenseforge/internal/issue"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/members"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/platform"
	"licenseforge.io/licenseforge/internal/ratelimit"
	"licenseforge.io/licenseforge/internal/retention"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/tenants"
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
		if platformDays, err = strconv.Atoi(v); err != nil || platformDays < retention.MinDays || platformDays > retention.MaxDays {
			return fmt.Errorf("LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS: want whole days, %d to %d; got %q", retention.MinDays, retention.MaxDays, v)
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
	limiter, err := rateLimiter(log)
	if err != nil {
		return err
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
	sinks := map[string]auditexport.Sink{}
	if addr := os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_ADDR"); addr != "" {
		sink, err := auditexport.NewSyslog(auditexport.SyslogConfig{Addr: addr,
			CAFile: os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_CA_FILE"), CertFile: os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_CERT_FILE"),
			KeyFile: os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_KEY_FILE"), ServerName: os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_SERVER_NAME"),
			SDID: os.Getenv("LICENSEFORGE_AUDIT_SYSLOG_SD_ID")})
		if err != nil {
			return fmt.Errorf("LICENSEFORGE_AUDIT_SYSLOG_*: %w", err)
		}
		sinks["syslog"] = sink
	}
	if endpoint := os.Getenv("LICENSEFORGE_AUDIT_OTLP_ENDPOINT"); endpoint != "" {
		sink, err := auditexport.NewOTLP(auditexport.OTLPConfig{Endpoint: endpoint,
			CAFile: os.Getenv("LICENSEFORGE_AUDIT_OTLP_CA_FILE"), CertFile: os.Getenv("LICENSEFORGE_AUDIT_OTLP_CERT_FILE"),
			KeyFile: os.Getenv("LICENSEFORGE_AUDIT_OTLP_KEY_FILE"), Headers: os.Getenv("LICENSEFORGE_AUDIT_OTLP_HEADERS")})
		if err != nil {
			return fmt.Errorf("LICENSEFORGE_AUDIT_OTLP_*: %w", err)
		}
		sinks["otlp"] = sink
	}
	for name, sink := range sinks {
		// Registered before serving: from now on retention keeps what this sink hasn't exported.
		if err := auditexport.Register(ctx, db, name); err != nil {
			return err
		}
		x := auditexport.New(db, name, sink, log)
		go func() { // stops with ctx (shutdown); entries left are sent by the next pod
			if err := x.Run(ctx); err != nil {
				log.Error("audit export stopped", "sink", name, "err", err)
			}
		}()
	}

	// Periodic chain verification (ADR-0036); one replica per interval runs it.
	verify := auditverify.New(db, log)
	if verify.Interval, err = envDuration("LICENSEFORGE_AUDIT_VERIFY_INTERVAL", auditverify.DefaultInterval); err != nil {
		return err
	}
	if verify.FullInterval, err = envDuration("LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL", auditverify.DefaultFullInterval); err != nil {
		return err
	}
	if verify.Interval > 0 {
		if verify.FullInterval == 0 {
			return errors.New("LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL: must be above 0 while verification is on")
		}
		go func() { _ = verify.Run(ctx) }() // stops with ctx; errors are logged
	} else {
		log.Warn("LICENSEFORGE_AUDIT_VERIFY_INTERVAL is 0: periodic audit verification is off")
	}

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
	// Fail at start on a malformed policy, not at the first login.
	assurance, err := identity.AssurancePolicyFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	platformMFA := authz.Assurance(os.Getenv("LICENSEFORGE_PLATFORM_MFA_POLICY"))
	if platformMFA == "" {
		platformMFA = authz.AssuranceNone
	}
	if !platformMFA.Valid() {
		return fmt.Errorf("LICENSEFORGE_PLATFORM_MFA_POLICY: %q isn't none, mfa or phishing_resistant", platformMFA)
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
			Assurance:      &assurance,
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
	mux.Handle(api.Prefix+"/", api.New(api.Config{Tokens: apitokens.Service{DB: db}, Members: members.Service{DB: db}, Invitations: invitations.Service{DB: db}, Tenants: tenants.Service{DB: db}, Identity: ids,
		Platform: platform.Service{DB: db}, PlatformMFAPolicy: platformMFA,
		Licenses: licenses.Service{DB: db, Keys: keyring}, Idempotency: idempotency.Store{DB: db, Keys: keyring},
		Products: catalog.Products{DB: db}, Features: catalog.Features{DB: db}, Plans: catalog.Plans{DB: db}, Customers: customers.Service{DB: db}, Audit: audit.Log{DB: db}, SigningKeys: signing.Local{DB: db, Keys: keyring},
		Activations: activations.Service{DB: db, Keys: keyring, Issuer: issue.Issuer{DB: db, Keys: signing.Local{DB: db, Keys: keyring}}},
		Sessions:    sessions, APIHost: os.Getenv("LICENSEFORGE_API_HOST"), Log: log}))
	if !web.Embedded {
		log.Warn("built without the dashboard (make web build TAGS=webui): serving a placeholder page")
	}
	// The address limit runs before anything else (ADR-0032 step 0). No
	// endpoint streams: bodies are at most 1 MB, the slowest handler (login
	// callback) is bounded by 15 s of IdP calls, and the dashboard's assets
	// are small, so a request that takes 30 s to send or 60 s to answer is
	// a slow client holding a connection.
	srv := &http.Server{
		Handler:           limiter.Wrap(metrics.Instrument(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	msrv := &http.Server{
		Handler:           metricsMux(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
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

// rateLimiter builds the per-client-address limiter from the environment.
func rateLimiter(log *slog.Logger) (*ratelimit.Limiter, error) {
	trusted, err := ratelimit.ParseTrusted(os.Getenv("LICENSEFORGE_TRUSTED_PROXIES"))
	if err != nil {
		return nil, fmt.Errorf("LICENSEFORGE_TRUSTED_PROXIES: %w", err)
	}
	quotas := map[ratelimit.Surface]int{}
	for _, q := range []struct {
		env     string
		surface ratelimit.Surface
		def     int
	}{
		{"LICENSEFORGE_RATE_LIMIT_ACTIVATION", ratelimit.Activation, ratelimit.DefaultActivation},
		{"LICENSEFORGE_RATE_LIMIT_MANAGEMENT", ratelimit.Management, ratelimit.DefaultManagement},
		{"LICENSEFORGE_RATE_LIMIT_LOGIN", ratelimit.Login, ratelimit.DefaultLogin},
	} {
		n, err := strconv.Atoi(envOr(q.env, strconv.Itoa(q.def)))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%s: want requests per minute (0 = off), got %q", q.env, os.Getenv(q.env))
		}
		quotas[q.surface] = n
	}
	return ratelimit.New(ratelimit.Config{Trusted: trusted, Quotas: quotas, Log: log}), nil
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

// envDuration reads a non-negative duration from key, def when unset.
func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s: want a duration like 15m (0 = off), got %q", key, v)
	}
	return d, nil
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
