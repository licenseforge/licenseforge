package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"licenseforge.io/licenseforge/internal/store/ent"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Group roles (ADR-0009). The operator creates them once per cluster and makes
// one login a member of each; see deploy/database-setup.sql.
const (
	AppRole      = "licenseforge_app"
	PlatformRole = "licenseforge_platform"
)

// migrationLock is the pg_advisory_lock key serializing migrations, so
// replicas starting at the same time apply them once.
const migrationLock = 0x4C46_4D49_4752 // "LFMIGR"

// ErrUnsafeRole means a database login could bypass tenant isolation.
var ErrUnsafeRole = errors.New("store: unsafe database role (ADR-0009)")

// DB is LicenseForge's database access. Tenant work and platform work use
// separate connection pools with separate logins, so tenant code can't reach
// platform privileges even through a SQL bug.
type DB struct {
	tenant, platform     *ent.Client
	tenantDB, platformDB *sql.DB
}

// Open connects the tenant pool (a login in AppRole) and the platform pool (a
// login in PlatformRole) and refuses logins that could bypass isolation.
func Open(ctx context.Context, tenantDSN, platformDSN string) (*DB, error) {
	tdb, err := openChecked(ctx, tenantDSN, AppRole, PlatformRole)
	if err != nil {
		return nil, fmt.Errorf("tenant pool: %w", err)
	}
	pdb, err := openChecked(ctx, platformDSN, PlatformRole, AppRole)
	if err != nil {
		_ = tdb.Close()
		return nil, fmt.Errorf("platform pool: %w", err)
	}
	return &DB{
		tenant:     ent.NewClient(ent.Driver(entsql.OpenDB("postgres", tdb))),
		platform:   ent.NewClient(ent.Driver(entsql.OpenDB("postgres", pdb))),
		tenantDB:   tdb,
		platformDB: pdb,
	}, nil
}

// Close closes both pools.
func (d *DB) Close() error { return errors.Join(d.tenantDB.Close(), d.platformDB.Close()) }

func openChecked(ctx context.Context, dsn, want, forbidden string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := checkRole(ctx, db, want, forbidden); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// checkRole refuses logins that could bypass row-level security or escalate:
// switched roles (SET ROLE via connection options), superuser, BYPASSRLS or
// CREATEROLE, membership in a role with those attributes, membership in the
// other pool's group, owning any relation, or a preset tenant setting.
func checkRole(ctx context.Context, db *sql.DB, want, forbidden string) error {
	var (
		switched, privileged, inPrivileged, inWant, inForbidden, owns bool
		preset                                                        string
	)
	err := db.QueryRowContext(ctx, `
		SELECT session_user <> current_user,
		       r.rolsuper OR r.rolbypassrls OR r.rolcreaterole,
		       EXISTS (SELECT 1 FROM pg_roles x
		               WHERE x.oid <> r.oid AND (x.rolsuper OR x.rolbypassrls OR x.rolcreaterole)
		                 AND pg_has_role(r.oid, x.oid, 'MEMBER')),
		       pg_has_role(r.oid, $1, 'MEMBER'),
		       pg_has_role(r.oid, $2, 'MEMBER'),
		       EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid
		               AND c.relkind IN ('r','p','v','m','f')
		               AND c.relnamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema'))),
		       COALESCE(current_setting('app.tenant_id', true), '')
		FROM pg_roles r WHERE r.rolname = session_user`, want, forbidden).
		Scan(&switched, &privileged, &inPrivileged, &inWant, &inForbidden, &owns, &preset)
	if err != nil {
		return fmt.Errorf("store: check role: %w", err)
	}
	switch {
	case switched:
		return fmt.Errorf("%w: connection switched role (SET ROLE in options)", ErrUnsafeRole)
	case privileged:
		return fmt.Errorf("%w: login is superuser, BYPASSRLS or CREATEROLE", ErrUnsafeRole)
	case inPrivileged:
		return fmt.Errorf("%w: login is a member of a superuser, BYPASSRLS or CREATEROLE role", ErrUnsafeRole)
	case !inWant:
		return fmt.Errorf("%w: login is not a member of %s", ErrUnsafeRole, want)
	case inForbidden:
		return fmt.Errorf("%w: login must not be a member of %s", ErrUnsafeRole, forbidden)
	case owns:
		return fmt.Errorf("%w: login owns tables; use a separate owner login for migrations", ErrUnsafeRole)
	case preset != "":
		return fmt.Errorf("%w: app.tenant_id is preset for the session (connection options or ALTER ROLE ... SET)", ErrUnsafeRole)
	}
	return nil
}

// WithTenant runs fn in a transaction in which row-level security exposes
// only tenantID's rows. fn's error rolls the transaction back.
func (d *DB) WithTenant(ctx context.Context, tenantID string, fn func(*ent.Tx) error) error {
	if tenantID == "" {
		return errors.New("store: empty tenant ID")
	}
	return inTx(ctx, d.tenant, func(tx *ent.Tx) error {
		// Transaction-local: can't leak to the next user of the pooled connection.
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// WithPlatform runs fn on the platform pool (all tenants). Use only for
// platform operations such as creating tenants (ADR-0019), never for requests
// on behalf of a tenant.
func (d *DB) WithPlatform(ctx context.Context, fn func(*ent.Tx) error) error {
	return inTx(ctx, d.platform, fn)
}

func inTx(ctx context.Context, client *ent.Client, fn func(*ent.Tx) error) (err error) {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if v := recover(); v != nil {
			_ = tx.Rollback()
			panic(v)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type migration struct{ version, checksum, body string }

func embedded() ([]migration, error) {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var ms []migration
	for _, f := range files {
		body, err := migrations.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		ms = append(ms, migration{
			version:  strings.TrimSuffix(strings.TrimPrefix(f, "migrations/"), ".sql"),
			checksum: hex.EncodeToString(sum[:]),
			body:     string(body),
		})
	}
	return ms, nil
}

// Migrate applies pending migrations as the schema owner (ownerDSN), each in
// its own transaction, under a session advisory lock. It refuses a database
// whose applied migrations differ from this binary's (edited files, unknown
// newer versions) or would need an older migration applied out of order.
func Migrate(ctx context.Context, ownerDSN string) (err error) {
	ms, err := embedded()
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(ctx) // advisory lock and work on one session
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)
	}()
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}

	applied := map[string]string{}
	rows, err := conn.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return err
	}
	newest := ""
	for rows.Next() {
		var v, sum string
		if err := rows.Scan(&v, &sum); err != nil {
			_ = rows.Close()
			return err
		}
		applied[v] = sum
		newest = max(newest, v)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}

	known := map[string]bool{}
	var pending []migration
	for _, m := range ms {
		known[m.version] = true
		sum, ok := applied[m.version]
		switch {
		case ok && sum != m.checksum:
			return fmt.Errorf("store: applied migration %s was modified (checksum mismatch); add a new migration instead", m.version)
		case ok:
		case m.version < newest:
			return fmt.Errorf("store: migration %s is older than applied %s; rename it to a newer timestamp", m.version, newest)
		default:
			pending = append(pending, m)
		}
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("store: database has migration %s unknown to this binary; upgrade LicenseForge instead of downgrading", v)
		}
	}
	for _, m := range pending {
		if err := applyOne(ctx, conn, m); err != nil {
			return fmt.Errorf("store: migration %s: %w", m.version, err)
		}
	}
	return nil
}

func applyOne(ctx context.Context, conn *sql.Conn, m migration) (err error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// Fail fast instead of queueing behind traffic and blocking every reader.
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, m.body); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, m.version, m.checksum); err != nil {
		return err
	}
	return tx.Commit()
}
