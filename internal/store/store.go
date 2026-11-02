package store

import (
	"context"
	"database/sql"
	"embed"
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

// migrationLock is the pg_advisory_xact_lock key serializing migrations, so
// replicas starting at the same time apply them once.
const migrationLock = 0x4C46_4D49_4752 // "LFMIGR"

// ErrUnsafeRole means the database role could bypass row-level security.
var ErrUnsafeRole = errors.New("store: database role is a superuser or has BYPASSRLS; tenant isolation would not apply (ADR-0009)")

// Open connects to PostgreSQL and refuses roles that bypass row-level
// security. The caller owns db and should close it.
func Open(ctx context.Context, dsn string) (*ent.Client, *sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, err
	}
	var unsafe bool
	err = db.QueryRowContext(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&unsafe)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("store: check role: %w", err)
	}
	if unsafe {
		_ = db.Close()
		return nil, nil, ErrUnsafeRole
	}
	drv := entsql.OpenDB("postgres", db)
	return ent.NewClient(ent.Driver(drv)), db, nil
}

// Migrate applies the embedded migrations that haven't run yet, in order, in
// one transaction under an advisory lock. It fails if the database has
// migrations this binary doesn't know (it is older than the schema).
func Migrate(ctx context.Context, db *sql.DB) (err error) {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLock); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	applied := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			_ = rows.Close()
			return err
		}
		applied[v] = true
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}

	known := map[string]bool{}
	for _, f := range files {
		version := strings.TrimSuffix(strings.TrimPrefix(f, "migrations/"), ".sql")
		known[version] = true
		if applied[version] {
			continue
		}
		body, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("store: migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			return err
		}
	}
	for v := range applied {
		if !known[v] {
			return fmt.Errorf("store: database has migration %s unknown to this binary; upgrade LicenseForge instead of downgrading", v)
		}
	}
	return tx.Commit()
}

// WithTenant runs fn in a transaction in which row-level security exposes
// only tenantID's rows. fn's error rolls the transaction back.
func WithTenant(ctx context.Context, client *ent.Client, tenantID string, fn func(*ent.Tx) error) error {
	if tenantID == "" {
		return errors.New("store: empty tenant ID")
	}
	return inTx(ctx, client, `SELECT set_config('app.tenant_id', $1, true)`, tenantID, fn)
}

// WithPlatform runs fn with platform-admin scope (all tenants). Use only for
// platform operations such as creating tenants (ADR-0019), never for requests
// on behalf of a tenant.
func WithPlatform(ctx context.Context, client *ent.Client, fn func(*ent.Tx) error) error {
	return inTx(ctx, client, `SELECT set_config('app.scope', $1, true)`, "platform", fn)
}

func inTx(ctx context.Context, client *ent.Client, setting, value string, fn func(*ent.Tx) error) (err error) {
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
	// set_config(..., true) is transaction-local: it can't leak to the next
	// user of the pooled connection.
	if _, err = tx.ExecContext(ctx, setting, value); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
