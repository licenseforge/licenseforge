package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // also registers the "pgx" database/sql driver

	"licenseforge.io/licenseforge/internal/store/ent"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Group roles (ADR-0009, ADR-0029). The operator creates them once per cluster
// and makes one login a member of each; see deploy/database-setup.sql.
const (
	AppRole      = "licenseforge_app"
	PlatformRole = "licenseforge_platform"
	IdentityRole = "licenseforge_identity" // the login path: identity tables only
	// RetentionRole prunes audit chains (ADR-0036): the only role with DELETE
	// on audit entries, used by `licenseforge audit prune`, never by serving pods.
	RetentionRole = "licenseforge_retention"
)

// minPostgres is the oldest supported server (server_version_num, ADR-0028).
var minPostgres = 170000 // var so tests can raise it

// migrationLock is the pg_advisory_lock key serializing migrations, so
// replicas starting at the same time apply them once.
const migrationLock = 0x4C46_4D49_4752 // "LFMIGR"

// ErrUnsafeRole means a database login could bypass tenant isolation.
var ErrUnsafeRole = errors.New("store: unsafe database role (ADR-0009)")

// DB is LicenseForge's database access. Tenant work, platform work and the
// login path use separate connection pools with separate logins, so a SQL bug
// in one can't reach the others' privileges.
type DB struct {
	tenant, platform, identity       *ent.Client
	tenantDB, platformDB, identityDB *sql.DB
}

// Logins are the connection strings of the serving logins (not the owner).
type Logins struct {
	Tenant   string // member of AppRole: tenant requests
	Platform string // member of PlatformRole: platform-admin work
	Identity string // member of IdentityRole: login and invitations (ADR-0029)
}

// Open connects the three pools and refuses logins that could bypass
// isolation.
func Open(ctx context.Context, l Logins) (*DB, error) {
	var dbs []*sql.DB
	fail := func(pool string, err error) (*DB, error) {
		for _, db := range dbs {
			_ = db.Close()
		}
		return nil, fmt.Errorf("%s pool: %w", pool, err)
	}
	for _, p := range []struct{ name, dsn, role string }{
		{"tenant", l.Tenant, AppRole}, {"platform", l.Platform, PlatformRole}, {"identity", l.Identity, IdentityRole},
	} {
		db, err := openChecked(ctx, p.dsn, p.role)
		if err != nil {
			return fail(p.name, err)
		}
		dbs = append(dbs, db)
	}
	client := func(db *sql.DB) *ent.Client { return ent.NewClient(ent.Driver(entsql.OpenDB("postgres", db))) }
	return &DB{
		tenant: client(dbs[0]), platform: client(dbs[1]), identity: client(dbs[2]),
		tenantDB: dbs[0], platformDB: dbs[1], identityDB: dbs[2],
	}, nil
}

// Retention is the audit retention job's connection (ADR-0036), separate
// from DB: serving processes never hold it.
type Retention struct {
	client *ent.Client
	db     *sql.DB
}

// OpenRetention connects the retention login and refuses one that could
// bypass row-level security or is a member of any other role, like Open.
func OpenRetention(ctx context.Context, dsn string) (*Retention, error) {
	db, err := openChecked(ctx, dsn, RetentionRole)
	if err != nil {
		return nil, fmt.Errorf("retention login: %w", err)
	}
	return &Retention{client: ent.NewClient(ent.Driver(entsql.OpenDB("postgres", db))), db: db}, nil
}

// Tx runs fn in a READ COMMITTED transaction of the retention login.
func (r *Retention) Tx(ctx context.Context, fn func(*ent.Tx) error) error {
	return inTx(ctx, r.client, nil, fn)
}

// Close closes the connection pool.
func (r *Retention) Close() error { return r.db.Close() }

// Ping checks that every pool can reach the database.
func (d *DB) Ping(ctx context.Context) error {
	return errors.Join(d.tenantDB.PingContext(ctx), d.platformDB.PingContext(ctx), d.identityDB.PingContext(ctx))
}

// SetMaxOpenConns limits each pool to n open connections (0: unlimited).
func (d *DB) SetMaxOpenConns(n int) {
	for _, db := range []*sql.DB{d.tenantDB, d.platformDB, d.identityDB} {
		db.SetMaxOpenConns(n)
	}
}

// Stats are the connection pool stats by pool name (metrics).
func (d *DB) Stats() map[string]sql.DBStats {
	return map[string]sql.DBStats{"tenant": d.tenantDB.Stats(), "platform": d.platformDB.Stats(), "identity": d.identityDB.Stats()}
}

// Close closes every pool.
func (d *DB) Close() error {
	return errors.Join(d.tenantDB.Close(), d.platformDB.Close(), d.identityDB.Close())
}

// openPool opens a serving pool on which no session state survives between
// uses: statements run unnamed (QueryExecModeExec), so there are no cached
// prepared statements a request could replace, and DISCARD ALL before every
// reuse drops anything a request left behind (session settings, prepared
// statements, temp state, advisory locks, LISTENs).
func openPool(dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	return stdlib.OpenDB(*cfg, stdlib.OptionResetSession(func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, "DISCARD ALL"); err != nil {
			return driver.ErrBadConn // database/sql only discards the connection on ErrBadConn
		}
		return nil
	})), nil
}

func openChecked(ctx context.Context, dsn, want string) (*sql.DB, error) {
	db, err := openPool(dsn)
	if err != nil {
		return nil, err
	}
	if err := checkRole(ctx, db, want); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// checkRole refuses logins that could bypass row-level security or escalate.
// Membership is an allow-list: the login may be a member of want and nothing
// else, which also rules out the owner role, the other pool's group and
// predefined roles such as pg_execute_server_program or pg_read_all_data.
func checkRole(ctx context.Context, db *sql.DB, want string) error {
	var (
		switched, privileged, wantPrivileged, inWant, otherMember, owns, canTemp, canCreate bool
		preset                                                                              string
		version                                                                             int
	)
	err := db.QueryRowContext(ctx, `
		SELECT session_user <> current_user,
		       r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication,
		       (SELECT g.rolsuper OR g.rolbypassrls OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication
		          FROM pg_roles g WHERE g.rolname = $1),
		       pg_has_role(r.oid, $1, 'MEMBER'),
		       EXISTS (SELECT 1 FROM pg_roles x
		               WHERE x.oid <> r.oid AND x.rolname <> $1 AND pg_has_role(r.oid, x.oid, 'MEMBER')),
		       EXISTS (SELECT 1 FROM pg_class c WHERE pg_has_role(r.oid, c.relowner, 'MEMBER')
		               AND c.relnamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema') OR nspname LIKE 'pg_toast%'))
		         OR EXISTS (SELECT 1 FROM pg_database d WHERE d.datname = current_database() AND pg_has_role(r.oid, d.datdba, 'MEMBER'))
		         OR EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = 'public' AND pg_has_role(r.oid, n.nspowner, 'MEMBER')),
		       has_database_privilege(r.oid, current_database(), 'TEMPORARY'),
		       EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname NOT IN ('pg_catalog','information_schema')
		               AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
		               AND has_schema_privilege(r.oid, n.oid, 'CREATE'))
		         OR has_database_privilege(r.oid, current_database(), 'CREATE'),
		       COALESCE(current_setting('app.tenant_id', true), ''),
		       current_setting('server_version_num')::int
		FROM pg_roles r WHERE r.rolname = session_user`, want).
		Scan(&switched, &privileged, &wantPrivileged, &inWant, &otherMember, &owns, &canTemp, &canCreate, &preset, &version)
	if err != nil {
		return fmt.Errorf("store: check role: %w", err)
	}
	if err := checkVersion(version); err != nil {
		return err
	}
	switch {
	case switched:
		return fmt.Errorf("%w: connection switched role (SET ROLE in options)", ErrUnsafeRole)
	case privileged || wantPrivileged:
		return fmt.Errorf("%w: login or %s has SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION", ErrUnsafeRole, want)
	case !inWant:
		return fmt.Errorf("%w: login is not a member of %s", ErrUnsafeRole, want)
	case otherMember:
		return fmt.Errorf("%w: login must be a member of %s only (no owner, other group or predefined roles)", ErrUnsafeRole, want)
	case owns:
		return fmt.Errorf("%w: login owns the database, schema or tables; use a separate owner login for migrations", ErrUnsafeRole)
	case canCreate:
		return fmt.Errorf("%w: login can create schemas or objects in a schema (functions or operators could intercept queries); REVOKE CREATE", ErrUnsafeRole)
	case canTemp:
		return fmt.Errorf("%w: login can create temporary tables, which shadow real tables on pooled connections; REVOKE TEMPORARY ON DATABASE ... FROM PUBLIC", ErrUnsafeRole)
	case preset != "":
		return fmt.Errorf("%w: app.tenant_id is preset for the session (connection options or ALTER ROLE ... SET)", ErrUnsafeRole)
	}
	return nil
}

func checkVersion(v int) error {
	if v < minPostgres {
		return fmt.Errorf("store: PostgreSQL %d is not supported; %d or newer is required", v/10000, minPostgres/10000)
	}
	return nil
}

// WithTenant runs fn in a transaction in which row-level security exposes
// only tenantID's rows. fn's error rolls the transaction back.
func (d *DB) WithTenant(ctx context.Context, tenantID string, fn func(*ent.Tx) error) error {
	if tenantID == "" {
		return errors.New("store: empty tenant ID")
	}
	return d.tenantTx(ctx, tenantID, nil, fn)
}

// ReadTenant runs fn in a read-only transaction scoped like WithTenant;
// snapshot makes it REPEATABLE READ (audit.Verify reads with it).
func (d *DB) ReadTenant(ctx context.Context, tenantID string, snapshot bool, fn func(*ent.Tx) error) error {
	if tenantID == "" {
		return errors.New("store: empty tenant ID")
	}
	return d.tenantTx(ctx, tenantID, readOpts(snapshot), fn)
}

func (d *DB) tenantTx(ctx context.Context, tenantID string, opts *sql.TxOptions, fn func(*ent.Tx) error) error {
	return inTx(ctx, d.tenant, opts, func(tx *ent.Tx) error {
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
	return inTx(ctx, d.platform, nil, fn)
}

// ReadPlatform runs fn in a read-only transaction on the platform pool;
// snapshot makes it REPEATABLE READ. It is an audit.Verify Runner for any
// chain.
func (d *DB) ReadPlatform(ctx context.Context, snapshot bool, fn func(*ent.Tx) error) error {
	return inTx(ctx, d.platform, readOpts(snapshot), fn)
}

func readOpts(snapshot bool) *sql.TxOptions {
	o := &sql.TxOptions{ReadOnly: true}
	if snapshot {
		o.Isolation = sql.LevelRepeatableRead
	}
	return o
}

// WithIdentity runs fn on the identity pool, the login path (ADR-0029): it
// reads identity data of every tenant and touches no licensing table.
// tenantID is the tenant an invitation is being accepted into ("" for plain
// login work); the database lets a membership and its audit entry be written
// only there.
func (d *DB) WithIdentity(ctx context.Context, tenantID string, fn func(*ent.Tx) error) error {
	return inTx(ctx, d.identity, nil, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

func inTx(ctx context.Context, client *ent.Client, opts *sql.TxOptions, fn func(*ent.Tx) error) (err error) {
	tx, err := client.BeginTx(ctx, opts)
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
	var version int
	if err := conn.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return err
	}
	if err := checkVersion(version); err != nil {
		return err
	}
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

// noTxMarker as a migration's first line runs it outside a transaction, for
// statements that can't run in one (CREATE INDEX CONCURRENTLY). Such a file
// should contain a single statement so a failure leaves nothing half-applied.
const noTxMarker = "-- lf:no-transaction"

// invalidIndexes reports indexes left invalid by a failed CREATE INDEX
// CONCURRENTLY, which PostgreSQL maintains on every write but never uses.
func invalidIndexes(ctx context.Context, conn *sql.Conn) error {
	var names sql.NullString
	err := conn.QueryRowContext(ctx, `SELECT string_agg(c.relname, ', ') FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid WHERE NOT i.indisvalid`).Scan(&names)
	if err != nil {
		return err
	}
	if names.Valid {
		return fmt.Errorf("invalid index(es) %s from a failed concurrent build: DROP INDEX CONCURRENTLY them, then migrate again", names.String)
	}
	return nil
}

func applyOne(ctx context.Context, conn *sql.Conn, m migration) (err error) {
	if strings.HasPrefix(m.body, noTxMarker) {
		// No lock_timeout: CREATE INDEX CONCURRENTLY waits for old snapshots
		// without blocking other traffic, and a timeout would leave an invalid index.
		if _, err := conn.ExecContext(ctx, m.body); err != nil {
			return errors.Join(err, invalidIndexes(ctx, conn))
		}
		if err := invalidIndexes(ctx, conn); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, m.version, m.checksum)
		return err
	}
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
