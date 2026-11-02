package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Tests need PostgreSQL: LICENSEFORGE_TEST_DATABASE_URL is a superuser URL
// (`make dev-db` prints one). Each run recreates the production role layout
// from deploy/database-setup.sql with fresh names, because superusers bypass
// row-level security and would make the isolation tests meaningless. In CI a
// missing URL is a failure.
var (
	adminURL string
	env      testEnv
)

type testEnv struct{ name, ownerURL, tenantURL, platformURL string }

func TestMain(m *testing.M) {
	adminURL = os.Getenv("LICENSEFORGE_TEST_DATABASE_URL")
	if adminURL == "" {
		if os.Getenv("CI") != "" {
			fmt.Fprintln(os.Stderr, "LICENSEFORGE_TEST_DATABASE_URL must be set in CI: tenant isolation tests are release blockers (ADR-0009)")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "skipping store tests: LICENSEFORGE_TEST_DATABASE_URL not set (run `make dev-db`)")
		os.Exit(0)
	}
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := 1
	if err := setup(admin); err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
	}
	teardown(admin)
	_ = admin.Close()
	os.Exit(code)
}

func suffix() string { return strings.TrimPrefix(ids.New("x"), "x_")[:10] }

// userURL returns adminURL with another login and database.
func userURL(user, db string, params ...string) string {
	u, _ := url.Parse(adminURL)
	u.User = url.UserPassword(user, "test")
	u.Path = "/" + db
	q := u.Query()
	for i := 0; i+1 < len(params); i += 2 {
		q.Set(params[i], params[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

var cleanupStmts []string

func adminExec(admin *sql.DB, stmts ...string) error {
	for _, s := range stmts {
		if _, err := admin.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

func setup(admin *sql.DB) error {
	// Group roles are cluster-wide and shared by concurrent test runs.
	if err := adminExec(admin, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_app') THEN CREATE ROLE licenseforge_app NOLOGIN; END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_platform') THEN CREATE ROLE licenseforge_platform NOLOGIN; END IF;
	END $$`); err != nil {
		return err
	}
	s := suffix()
	env.name = "lf_test_" + s
	owner, api, adm := "lf_own_"+s, "lf_api_"+s, "lf_adm_"+s
	cleanupStmts = []string{
		fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, env.name),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, owner),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, api),
		fmt.Sprintf(`DROP ROLE IF EXISTS %s`, adm),
	}
	if err := adminExec(admin,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test'`, owner),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app`, api),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_platform`, adm),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, env.name, owner),
		fmt.Sprintf(`REVOKE CONNECT ON DATABASE %s FROM PUBLIC`, env.name),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s, %s`, env.name, owner, api, adm),
	); err != nil {
		return err
	}
	env.ownerURL = userURL(owner, env.name)
	env.tenantURL = userURL(api, env.name)
	env.platformURL = userURL(adm, env.name)
	return Migrate(context.Background(), env.ownerURL)
}

func teardown(admin *sql.DB) {
	for _, s := range cleanupStmts {
		_, _ = admin.Exec(s)
	}
}

func openDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), env.tenantURL, env.platformURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenRefusesUnsafeRoles(t *testing.T) {
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	s := suffix()
	creator, byp, member := "lf_cr_"+s, "lf_byp_"+s, "lf_mem_"+s
	t.Cleanup(func() {
		for _, r := range []string{creator, member, byp} {
			_, _ = admin.Exec(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
		}
	})
	if err := adminExec(admin,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' CREATEROLE IN ROLE licenseforge_app`, creator),
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN BYPASSRLS`, byp),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app, %s`, member, byp),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s, %s`, env.name, creator, member),
	); err != nil {
		t.Fatal(err)
	}
	tenantUser := "lf_api_" + strings.TrimPrefix(env.name, "lf_test_")
	for name, dsn := range map[string]string{
		"superuser":              strings.Replace(adminURL, "/postgres?", "/"+env.name+"?", 1),
		"schema owner":           env.ownerURL,
		"platform login":         env.platformURL,
		"createrole":             userURL(creator, env.name),
		"member of bypassrls":    userURL(member, env.name),
		"preset tenant":          userURL(tenantUser, env.name, "app.tenant_id", "tnt_x"),
		"switched role":          userURL(tenantUser, env.name, "role", "licenseforge_app"),
		"superuser switched too": strings.Replace(adminURL, "/postgres?", "/"+env.name+"?role="+tenantUser+"&", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(context.Background(), dsn, env.platformURL); !errors.Is(err, ErrUnsafeRole) {
				t.Fatalf("got %v, want ErrUnsafeRole", err)
			}
		})
	}
	if _, err := Open(context.Background(), env.tenantURL, env.tenantURL); !errors.Is(err, ErrUnsafeRole) {
		t.Fatalf("tenant login as platform pool: got %v, want ErrUnsafeRole", err)
	}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	t.Run("concurrent and idempotent", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 5)
		for range 5 {
			wg.Add(1)
			go func() { defer wg.Done(); errs <- Migrate(ctx, env.ownerURL) }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	owner, err := sql.Open("pgx", env.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	for name, stmt := range map[string]string{
		"unknown newer migration": `INSERT INTO schema_migrations (version, checksum) VALUES ('29991231000000_future', 'x')`,
		"modified applied file":   `UPDATE schema_migrations SET checksum = 'tampered' WHERE version = (SELECT min(version) FROM schema_migrations)`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := owner.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			// Commit so Migrate sees it, then undo.
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = owner.Exec(`DELETE FROM schema_migrations WHERE version = '29991231000000_future'`)
				ms, _ := embedded()
				_, _ = owner.Exec(`UPDATE schema_migrations SET checksum = $1 WHERE version = $2`, ms[0].checksum, ms[0].version)
			}()
			if err := Migrate(ctx, env.ownerURL); err == nil {
				t.Fatal("Migrate must refuse")
			}
		})
	}
}

// Data migrations run as the owner and must see every tenant's rows.
func TestOwnerSeesAllRowsForDataMigrations(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	tn := createTenants(t, d, 1)[0]
	if err := d.WithTenant(ctx, tn.ID, func(tx *ent.Tx) error {
		return tx.Product.Create().SetTenantID(tn.ID).SetSlug("backfill").SetName("x").Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	owner, err := sql.Open("pgx", env.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	res, err := owner.Exec(`UPDATE products SET name = upper(name) WHERE tenant_id = $1`, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("owner updated %d rows, want 1", n)
	}
}

func createTenants(t *testing.T, d *DB, n int) []*ent.Tenant {
	t.Helper()
	var out []*ent.Tenant
	err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		for range n {
			tn, err := tx.Tenant.Create().SetSlug("t-" + suffix()).SetName("T").Save(context.Background())
			if err != nil {
				return err
			}
			out = append(out, tn)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTenantIsolation is the release blocker from ADR-0009: even with no
// application-level filter, a tenant can't see or change another tenant's rows.
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	ts := createTenants(t, d, 2)
	a, b := ts[0], ts[1]
	var bProduct *ent.Product
	for _, tn := range ts {
		if err := d.WithTenant(ctx, tn.ID, func(tx *ent.Tx) error {
			p, err := tx.Product.Create().SetTenantID(tn.ID).SetSlug("db").SetName("DB").Save(ctx)
			if tn == b {
				bProduct = p
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	err := d.WithTenant(ctx, a.ID, func(tx *ent.Tx) error {
		ps, err := tx.Product.Query().All(ctx)
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			t.Error("tenant A sees none of its own products")
		}
		for _, p := range ps {
			if p.TenantID != a.ID {
				t.Errorf("tenant A saw product of tenant %s", p.TenantID)
			}
		}
		if tns, err := tx.Tenant.Query().All(ctx); err != nil || len(tns) != 1 || tns[0].ID != a.ID {
			t.Errorf("tenant A sees tenants %v (err %v), want only itself", tns, err)
		}
		if _, err := tx.Product.Get(ctx, bProduct.ID); !ent.IsNotFound(err) {
			t.Errorf("Get B's product: %v, want not found", err)
		}
		if n, err := tx.Product.Update().Where(product.ID(bProduct.ID)).SetName("pwned").Save(ctx); err != nil || n != 0 {
			t.Errorf("update B's product: n=%d err=%v, want 0 rows", n, err)
		}
		if n, err := tx.Product.Delete().Where(product.ID(bProduct.ID)).Exec(ctx); err != nil || n != 0 {
			t.Errorf("delete B's product: n=%d err=%v, want 0 rows", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A can't insert into B (WITH CHECK), nor modify tenant rows at all, even its own.
	for name, op := range map[string]func(tx *ent.Tx) error{
		"insert into B": func(tx *ent.Tx) error {
			return tx.Product.Create().SetTenantID(b.ID).SetSlug("smuggled").SetName("x").Exec(ctx)
		},
		"update own tenant row": func(tx *ent.Tx) error {
			n, err := tx.Tenant.Update().Where(tenant.ID(a.ID)).SetName("self-upgraded").Save(ctx)
			if err == nil && n == 0 {
				return errors.New("no rows") // denied by policy: treat as refusal
			}
			return err
		},
		"escalate to platform role": func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `SET LOCAL ROLE licenseforge_platform`)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := d.WithTenant(ctx, a.ID, op)
			if err == nil {
				t.Errorf("tenant A could %s", name)
			}
		})
	}
	// Without a tenant scope the tenant pool sees and writes nothing.
	if n, err := d.tenant.Product.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("unscoped query saw %d products (err %v), want 0", n, err)
	}
	if err := d.tenant.Product.Create().SetTenantID(a.ID).SetSlug("unscoped").SetName("x").Exec(ctx); err == nil {
		t.Error("unscoped insert succeeded")
	}
}

// The tenant setting must not survive the transaction on a reused connection.
func TestTenantScopeDoesNotLeak(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	d.tenantDB.SetMaxOpenConns(1) // force reuse of the same connection
	tn := createTenants(t, d, 1)[0]
	if err := d.WithTenant(ctx, tn.ID, func(tx *ent.Tx) error {
		return tx.Product.Create().SetTenantID(tn.ID).SetSlug("leak").SetName("x").Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := d.tenant.Product.Query().Count(ctx); err != nil || n != 0 {
		t.Fatalf("after WithTenant, unscoped query on the same connection saw %d rows (err %v)", n, err)
	}
}

// TestEveryRelationHasCanonicalRLS fails when a new relation doesn't follow
// the pattern in the security migration: every table is either tenants, an
// allow-listed internal table, or has tenant_id with exactly the canonical
// policies; views, materialized views, partitioned and foreign tables are
// refused until reviewed (they can bypass or not inherit RLS).
func TestEveryRelationHasCanonicalRLS(t *testing.T) {
	owner, err := sql.Open("pgx", env.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	internal := map[string]bool{"schema_migrations": true} // no grants to app roles
	tenantPolicies := map[string]string{
		"tenant_isolation": "ALL licenseforge_app ((tenant_id)::text = app_tenant_id()) ((tenant_id)::text = app_tenant_id())",
		"platform_all":     "ALL licenseforge_platform true true",
	}
	tenantsPolicies := map[string]string{
		"tenant_read":  "SELECT licenseforge_app ((id)::text = app_tenant_id())",
		"platform_all": "ALL licenseforge_platform true true",
	}
	ou, _ := url.Parse(env.ownerURL)
	ownerRole := ou.User.Username()

	rows, err := owner.Query(`
		SELECT n.nspname, c.relname, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p','v','m','f')
		  AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'`)
	if err != nil {
		t.Fatal(err)
	}
	type rel struct {
		schema, name, kind         string
		enabled, forced, hasTenant bool
	}
	var rels []rel
	for rows.Next() {
		var r rel
		if err := rows.Scan(&r.schema, &r.name, &r.kind, &r.enabled, &r.forced, &r.hasTenant); err != nil {
			t.Fatal(err)
		}
		rels = append(rels, r)
	}
	_ = rows.Close()

	policies := func(table string) map[string]string {
		got := map[string]string{}
		prs, err := owner.Query(`SELECT policyname, permissive, cmd, array_to_string(roles, ','), COALESCE(qual, ''), COALESCE(with_check, '')
			FROM pg_policies WHERE schemaname = 'public' AND tablename = $1`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = prs.Close() }()
		for prs.Next() {
			var name, permissive, cmd, roles, qual, check string
			if err := prs.Scan(&name, &permissive, &cmd, &roles, &qual, &check); err != nil {
				t.Fatal(err)
			}
			if permissive != "PERMISSIVE" {
				name += " (restrictive)"
			}
			got[name] = strings.TrimSpace(cmd + " " + roles + " " + qual + " " + check)
		}
		return got
	}
	checkPolicies := func(r rel, want map[string]string) {
		got := policies(r.name)
		mig, ok := got["migrator_all"]
		if !ok || mig != "ALL "+ownerRole+" true true" {
			t.Errorf("%s: migrator_all = %q, want owner-only full access", r.name, mig)
		}
		delete(got, "migrator_all")
		if len(got) != len(want) {
			t.Errorf("%s: policies %v, want exactly %v (+ migrator_all)", r.name, got, want)
		}
		for name, w := range want {
			if got[name] != strings.TrimSpace(w) {
				t.Errorf("%s: policy %s = %q, want %q", r.name, name, got[name], strings.TrimSpace(w))
			}
		}
	}

	tenantTables := 0
	for _, r := range rels {
		switch {
		case r.schema != "public":
			t.Errorf("relation %s.%s outside the public schema", r.schema, r.name)
		case r.kind != "r":
			t.Errorf("relation %s has kind %q (view, materialized view, partitioned or foreign table): review RLS before allowing it", r.name, r.kind)
		case internal[r.name]:
		case !r.enabled || !r.forced:
			t.Errorf("table %s: RLS enabled=%v forced=%v", r.name, r.enabled, r.forced)
		case r.name == "tenants":
			checkPolicies(r, tenantsPolicies)
		case !r.hasTenant:
			t.Errorf("table %s has no tenant_id: add one or allow-list it here with a reason", r.name)
		default:
			tenantTables++
			checkPolicies(r, tenantPolicies)
		}
	}
	if tenantTables == 0 {
		t.Fatal("no tenant tables found")
	}
}
