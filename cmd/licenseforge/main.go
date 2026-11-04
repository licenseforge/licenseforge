// Command licenseforge runs the LicenseForge server, or applies database
// migrations with `licenseforge migrate`.
//
// Configuration comes from the environment (ADR-0005), so Kubernetes Secrets
// can supply it:
//
//	LICENSEFORGE_DATABASE_URL           tenant pool login (licenseforge_api)
//	LICENSEFORGE_PLATFORM_DATABASE_URL  platform pool login (licenseforge_admin)
//	LICENSEFORGE_OWNER_DATABASE_URL     schema owner, for `migrate` only
//	LICENSEFORGE_MASTER_KEYS            keyring (ADR-0025)
//	LICENSEFORGE_ADDR                   listen address, default :8080
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
	"syscall"
	"time"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	addr := flag.String("addr", envOr("LICENSEFORGE_ADDR", ":8080"), "listen address")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: licenseforge [flags]   run the server\n       licenseforge migrate   apply database migrations\n")
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

	var err error
	switch flag.Arg(0) {
	case "":
		var ln net.Listener
		if ln, err = net.Listen("tcp", *addr); err == nil {
			err = serve(ctx, ln, log)
		}
	case "migrate":
		err = migrate(ctx, log)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
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

// serve runs the server on ln until ctx is done. It closes ln.
func serve(ctx context.Context, ln net.Listener, log *slog.Logger) error {
	defer func() { _ = ln.Close() }()
	tenantDSN, err := mustEnv("LICENSEFORGE_DATABASE_URL")
	if err != nil {
		return err
	}
	platformDSN, err := mustEnv("LICENSEFORGE_PLATFORM_DATABASE_URL")
	if err != nil {
		return err
	}
	keys, err := mustEnv("LICENSEFORGE_MASTER_KEYS")
	if err != nil {
		return err
	}
	if _, err := secrets.ParseKeyring(keys); err != nil { // fail at start, not on first use
		return err
	}
	db, err := store.Open(ctx, tenantDSN, platformDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	srv := &http.Server{
		Handler:           newMux(db.Ping, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", ln.Addr().String(), "version", version)
		errc <- srv.Serve(ln)
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newMux serves the health endpoints. ready reports whether the database is
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
	return mux
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
