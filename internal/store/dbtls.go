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
var ErrInsecureDatabase = errors.New("store: the database URL must use sslmode=verify-full (or verify-ca with sslrootcert) unless the host is local (localhost, a loopback address or a Unix socket); set LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT=true only for development clusters")

// AllowPlaintextEnv lets a development cluster (e2e) reach its database
// without TLS. Never in production.
const AllowPlaintextEnv = "LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT"

// PlaintextAllowed reads AllowPlaintextEnv: "true" or unset; anything else
// is an error (a typo must not silently keep or drop the check).
func PlaintextAllowed() (bool, error) {
	switch v := os.Getenv(AllowPlaintextEnv); v {
	case "":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("store: %s must be true or unset, not %q", AllowPlaintextEnv, v)
	}
}

// parseDSN parses dsn and refuses it per ErrInsecureDatabase; every TLS
// connection it allows negotiates TLS 1.2 or later.
func parseDSN(dsn string) (*pgx.ConnConfig, error) {
	allow, err := PlaintextAllowed()
	if err != nil {
		return nil, err
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if err := checkTLS(&cfg.Config, allow); err != nil {
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
		// verify-full verifies the chain and the name. verify-ca skips the
		// name and checks the chain itself, against sslrootcert: without
		// one, pgx falls back to the system roots, so any public
		// certificate for any name passes. require and prefer verify
		// nothing.
		if h.TLSConfig == nil || (h.TLSConfig.InsecureSkipVerify && (h.TLSConfig.VerifyPeerCertificate == nil || h.TLSConfig.RootCAs == nil)) {
			return fmt.Errorf("%w (host %s)", ErrInsecureDatabase, h.Host)
		}
	}
	return nil
}

// local: a Unix socket, a loopback address, or localhost (resolved through
// /etc/hosts, which Kubernetes and Docker always write).
func local(host string) bool {
	if strings.HasPrefix(host, "/") || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
