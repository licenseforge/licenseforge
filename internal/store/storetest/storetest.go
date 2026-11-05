// Package storetest creates a throwaway PostgreSQL database with the
// production role layout (deploy/database-setup.sql), for tests of any package
// that uses the store. It doesn't import package store, so store's own tests
// can use it too.
//
// LICENSEFORGE_TEST_DATABASE_URL is a superuser URL (`make dev-db` prints one).
// Fresh role names per run, because superusers bypass row-level security and
// would make isolation tests meaningless. In CI a missing URL is a failure.
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx driver

	"licenseforge.io/licenseforge/internal/store/ids"
)

// Env is the database created for one test binary.
type Env struct {
	Name                                                                  string // database name
	AdminURL, OwnerURL, TenantURL, PlatformURL, IdentityURL, RetentionURL string
}

var (
	cleanupMu    sync.Mutex
	cleanupStmts []string
)

// AddCleanup queues admin statements run after the tests, in order.
func AddCleanup(stmts ...string) {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	cleanupStmts = append(cleanupStmts, stmts...)
}

// Suffix returns 10 random lowercase characters for unique names.
func Suffix() string { return strings.TrimPrefix(ids.New("x"), "x_")[:10] }

// UserURL returns admin with another login (password "test") and database.
func UserURL(admin, user, db string, params ...string) string {
	u, _ := url.Parse(admin)
	u.User = url.UserPassword(user, "test")
	u.Path = "/" + db
	q := u.Query()
	for i := 0; i+1 < len(params); i += 2 {
		q.Set(params[i], params[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// AdminExec runs statements as the admin.
func AdminExec(admin *sql.DB, stmts ...string) error {
	for _, s := range stmts {
		if _, err := admin.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// Main sets up the database, migrates it with migrate (store.Migrate), runs
// the tests with env filled in, and cleans up. Use it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }
func Main(m *testing.M, env *Env, migrate func(ctx context.Context, ownerURL string) error) int {
	env.AdminURL = os.Getenv("LICENSEFORGE_TEST_DATABASE_URL")
	if env.AdminURL == "" {
		if os.Getenv("CI") != "" {
			fmt.Fprintln(os.Stderr, "LICENSEFORGE_TEST_DATABASE_URL must be set in CI: tenant isolation tests are release blockers (ADR-0009)")
			return 1
		}
		fmt.Fprintln(os.Stderr, "skipping database tests: LICENSEFORGE_TEST_DATABASE_URL not set (run `make dev-db`)")
		return 0
	}
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = admin.Close() }()
	code := 1
	if err := setup(admin, env, migrate); err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
	}
	if env.Name != "" {
		AddCleanup(fmt.Sprintf(`DROP ROLE IF EXISTS lf_own_%s`, strings.TrimPrefix(env.Name, "lf_test_")))
	}
	for _, s := range cleanupStmts {
		if _, err := admin.Exec(s); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup: %s: %v\n", s, err)
		}
	}
	return code
}

func setup(admin *sql.DB, env *Env, migrate func(context.Context, string) error) error {
	// Group roles are cluster-wide and shared by concurrent test runs.
	// Test binaries of several packages run in parallel: a concurrent CREATE
	// ROLE fails with duplicate_object or unique_violation, which is fine.
	if err := AdminExec(admin, `DO $$ BEGIN
		BEGIN CREATE ROLE licenseforge_app NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
		BEGIN CREATE ROLE licenseforge_platform NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
		BEGIN CREATE ROLE licenseforge_identity NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
		BEGIN CREATE ROLE licenseforge_retention NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
	END $$`); err != nil {
		return err
	}
	s := Suffix()
	env.Name = "lf_test_" + s
	owner, api, adm, idn, ret := "lf_own_"+s, "lf_api_"+s, "lf_adm_"+s, "lf_idn_"+s, "lf_ret_"+s
	// The database goes first (roles holding privileges on a live database
	// can't be dropped); the owner role goes last. Cleanups added by tests run
	// in between (Main).
	AddCleanup(
		fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, env.Name),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, api),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, adm),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, idn),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, ret),
	)
	if err := AdminExec(admin,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test'`, owner),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app`, api),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_platform`, adm),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_identity`, idn),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_retention`, ret),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, env.Name, owner),
		fmt.Sprintf(`REVOKE CONNECT ON DATABASE %s FROM PUBLIC`, env.Name),
		fmt.Sprintf(`REVOKE TEMPORARY ON DATABASE %s FROM PUBLIC`, env.Name),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s, %s, %s, %s`, env.Name, owner, api, adm, idn, ret),
	); err != nil {
		return err
	}
	env.OwnerURL = UserURL(env.AdminURL, owner, env.Name)
	env.TenantURL = UserURL(env.AdminURL, api, env.Name)
	env.PlatformURL = UserURL(env.AdminURL, adm, env.Name)
	env.IdentityURL = UserURL(env.AdminURL, idn, env.Name)
	env.RetentionURL = UserURL(env.AdminURL, ret, env.Name)
	return migrate(context.Background(), env.OwnerURL)
}
