package store

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInsecureDatabase: a database URL that doesn't verify the server's
// certificate, to a host that isn't local (SC-8, ADR-0024: TLS 1.2+
// everywhere). pgx's default, sslmode=prefer, falls back to plaintext and
// verifies nothing; sslmode=verify-full (or verify-ca) is required.
var ErrInsecureDatabase = errors.New("store: the database URL must use sslmode=verify-full (or verify-ca) unless the host is local; set LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT=true only for development clusters")

// AllowPlaintextEnv lets a development cluster (e2e) reach its database
// without TLS. Never in production.
const AllowPlaintextEnv = "LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT"

// parseDSN parses dsn and refuses it per ErrInsecureDatabase; every TLS
// connection it allows negotiates TLS 1.2 or later.
func parseDSN(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if err := checkTLS(&cfg.Config, os.Getenv(AllowPlaintextEnv) == "true"); err != nil {
		return nil, err
	}
	return cfg, nil
}

// checkTLS: every host pgx may try (the first and its fallbacks) verifies
// the server's certificate, or is local, or plaintext is allowed.
func checkTLS(c *pgconn.Config, allowPlaintext bool) error {
	hosts := append([]*pgconn.FallbackConfig{{Host: c.Host, Port: c.Port, TLSConfig: c.TLSConfig}}, c.Fallbacks...)
	for _, h := range hosts {
		if h.TLSConfig != nil && h.TLSConfig.MinVersion < tls.VersionTLS12 {
			h.TLSConfig.MinVersion = tls.VersionTLS12 // the configs are shared pointers: this sets pgx's
		}
		if allowPlaintext || local(h.Host) {
			continue
		}
		// verify-full verifies the chain and name; verify-ca skips the
		// name with a peer check of its own; require and prefer verify
		// nothing.
		if h.TLSConfig == nil || (h.TLSConfig.InsecureSkipVerify && h.TLSConfig.VerifyPeerCertificate == nil) {
			return fmt.Errorf("%w (host %s)", ErrInsecureDatabase, h.Host)
		}
	}
	return nil
}

// local: a Unix socket or a loopback address.
func local(host string) bool {
	if strings.HasPrefix(host, "/") || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
