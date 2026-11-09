package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// caFile writes a self-signed CA certificate for sslrootcert.
func caFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDatabaseTLS(t *testing.T) {
	ca := caFile(t)
	for dsn, ok := range map[string]bool{
		"postgres://u:p@db.example:5432/x?sslmode=verify-full":                  true,
		"postgres://u:p@db.example:5432/x?sslmode=verify-ca&sslrootcert=" + ca:  true,
		"postgres://u:p@db.example:5432/x?sslmode=verify-ca":                    false, // no root: pgx trusts any public certificate, any name
		"postgres://u:p@db.example:5432/x?sslmode=require&sslrootcert=" + ca:    true,  // libpq: require with a root is verify-ca
		"postgres://u:p@db.example:5432/x?sslrootcert=system":                   true,  // pgx: verify-full
		"postgres://u:p@db.example:5432/x?sslmode=prefer&sslnegotiation=direct": false,
		"host=/tmp,db.example user=u dbname=x sslmode=disable":                  false,
		"postgres://u:p@[::ffff:127.0.0.1]:5432/x?sslmode=disable":              true,
		"postgres://u:p@db.example:5432/x?sslmode=require":                      false, // encrypted, but to anyone
		"postgres://u:p@db.example:5432/x?sslmode=prefer":                       false, // falls back to plaintext
		"postgres://u:p@db.example:5432/x?sslmode=allow":                        false,
		"postgres://u:p@db.example:5432/x?sslmode=disable":                      false,
		"postgres://u:p@db.example:5432/x":                                      false, // pgx's default: prefer
		"postgres://u:p@db.example,db2.example/x?sslmode=verify-full":           true,
		"postgres://u:p@localhost,db.example/x?sslmode=disable":                 false, // the second host isn't local
		"postgres://u:p@127.0.0.1:5432/x?sslmode=disable":                       true,
		"postgres://u:p@[::1]:5432/x?sslmode=disable":                           true,
		"postgres://u:p@localhost/x?sslmode=disable":                            true,
		"host=/var/run/postgresql user=u dbname=x sslmode=disable":              true,
	} {
		cfg, err := parseDSN(dsn)
		if ok != (err == nil) || (!ok && !errors.Is(err, ErrInsecureDatabase)) {
			t.Errorf("%s: %v", dsn, err)
			continue
		}
		if ok {
			for _, f := range append([]*pgconn.FallbackConfig{{TLSConfig: cfg.TLSConfig}}, cfg.Fallbacks...) {
				if f.TLSConfig != nil && f.TLSConfig.MinVersion < tls.VersionTLS12 {
					t.Errorf("%s: TLS minimum %x", dsn, f.TLSConfig.MinVersion)
				}
			}
		}
	}
	// PGSSLMODE applies to a URL without sslmode.
	t.Setenv("PGSSLMODE", "disable")
	if _, err := parseDSN("postgres://u:p@db.example/x"); !errors.Is(err, ErrInsecureDatabase) {
		t.Errorf("PGSSLMODE=disable: %v", err)
	}
	t.Setenv("PGSSLMODE", "")
	// The opt-out: true or unset, nothing else.
	for _, bad := range []string{"1", "True", "yes"} {
		t.Setenv(AllowPlaintextEnv, bad)
		if _, err := parseDSN("postgres://u:p@localhost/x?sslmode=disable"); err == nil || errors.Is(err, ErrInsecureDatabase) {
			t.Errorf("%s=%s: %v", AllowPlaintextEnv, bad, err)
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
