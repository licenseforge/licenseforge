package store

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDatabaseTLS(t *testing.T) {
	for dsn, ok := range map[string]bool{
		"postgres://u:p@db.example:5432/x?sslmode=verify-full":        true,
		"postgres://u:p@db.example:5432/x?sslmode=verify-ca":          true,
		"postgres://u:p@db.example:5432/x?sslmode=require":            false, // encrypted, but to anyone
		"postgres://u:p@db.example:5432/x?sslmode=prefer":             false, // falls back to plaintext
		"postgres://u:p@db.example:5432/x?sslmode=allow":              false,
		"postgres://u:p@db.example:5432/x?sslmode=disable":            false,
		"postgres://u:p@db.example:5432/x":                            false, // pgx's default: prefer
		"postgres://u:p@db.example,db2.example/x?sslmode=verify-full": true,
		"postgres://u:p@localhost,db.example/x?sslmode=disable":       false, // the second host isn't local
		"postgres://u:p@127.0.0.1:5432/x?sslmode=disable":             true,
		"postgres://u:p@[::1]:5432/x?sslmode=disable":                 true,
		"postgres://u:p@localhost/x?sslmode=disable":                  true,
		"host=/var/run/postgresql user=u dbname=x sslmode=disable":    true,
	} {
		cfg, err := parseDSN(dsn)
		if ok != (err == nil) || (!ok && !errors.Is(err, ErrInsecureDatabase)) {
			t.Errorf("%s: %v", dsn, err)
			continue
		}
		if ok && cfg.TLSConfig != nil && cfg.TLSConfig.MinVersion < tls.VersionTLS12 {
			t.Errorf("%s: TLS minimum %x", dsn, cfg.TLSConfig.MinVersion)
		}
	}
	t.Setenv(AllowPlaintextEnv, "true")
	if _, err := parseDSN("postgres://u:p@db.example/x?sslmode=disable"); err != nil {
		t.Errorf("allowed plaintext: %v", err)
	}
	t.Setenv(AllowPlaintextEnv, "")
	// Every pool opens through the check, before connecting.
	if _, err := Open(context.Background(), Logins{Tenant: "postgres://u:p@db.example/x?sslmode=disable"}); !errors.Is(err, ErrInsecureDatabase) {
		t.Errorf("Open: %v", err)
	}
	if err := Migrate(context.Background(), "postgres://u:p@db.example/x?sslmode=prefer"); !errors.Is(err, ErrInsecureDatabase) {
		t.Errorf("Migrate: %v", err)
	}
}

// TLS 1.2+ for every client, and in FIPS 140-3 mode (make test-fips) only
// approved suites: Go's crypto/tls enforces both; this pins it (SC-8, SC-13).
func TestClientTLSPolicy(t *testing.T) {
	serve := func(cfg *tls.Config) error {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.TLS = cfg
		srv.StartTLS()
		defer srv.Close()
		resp, err := srv.Client().Get(srv.URL) // the default client TLS settings, the server's certificate trusted
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := serve(&tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("a TLS 1.1 server was accepted")
	}
	chacha := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}}
	if err := serve(chacha); fips140.Enabled() != (err != nil) {
		t.Errorf("ChaCha20-only server (not FIPS-approved), FIPS mode %v: %v", fips140.Enabled(), err)
	}
}
