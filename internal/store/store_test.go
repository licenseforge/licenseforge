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
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Tests need PostgreSQL: LICENSEFORGE_TEST_DATABASE_URL is a superuser URL
// (`make dev-db` prints one). Each run creates a non-superuser role and a
// database it owns, because superusers bypass row-level security and would
// make the isolation tests meaningless. In CI a missing URL is a failure.
var (
	adminURL string
	appURL   string
)

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
	cleanup, err := setupAppDatabase()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupAppDatabase() (func(), error) {
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		return nil, err
	}
	name := "lf_test_" + strings.TrimPrefix(ids.New("x"), "x_")[:12]
	stmts := []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' NOSUPERUSER NOBYPASSRLS`, name),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, name, name),
	}
	for _, s := range stmts {
		if _, err := admin.Exec(s); err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}
	u.User = url.UserPassword(name, "test")
	u.Path = "/" + name
	appURL = u.String()
	return func() {
		_, _ = admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, name))
		_, _ = admin.Exec(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, name))
		_ = admin.Close()
	}, nil
}

func openApp(t *testing.T) (*ent.Client, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	client, db, err := Open(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return client, db
}

func TestOpenRefusesSuperuser(t *testing.T) {
	if _, _, err := Open(context.Background(), adminURL); !errors.Is(err, ErrUnsafeRole) {
		t.Fatalf("got %v, want ErrUnsafeRole", err)
	}
}

func TestMigrateConcurrentAndIdempotent(t *testing.T) {
	_, db := openApp(t)
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- Migrate(context.Background(), db) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrateRefusesUnknownMigration(t *testing.T) {
	_, db := openApp(t)
	if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES ('29991231000000_future')`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.Exec(`DELETE FROM schema_migrations WHERE version = '29991231000000_future'`) }()
	if err := Migrate(context.Background(), db); err == nil {
		t.Fatal("Migrate must refuse a database newer than the binary")
	}
}

// TestTenantIsolation is the release blocker from ADR-0009: even with no
// application-level filter, a tenant can't see or change another tenant's rows.
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	client, _ := openApp(t)

	var a, b *ent.Tenant
	if err := WithPlatform(ctx, client, func(tx *ent.Tx) error {
		var err error
		if a, err = tx.Tenant.Create().SetSlug("iso-a-" + strings.ToLower(ids.New("x")[2:8])).SetName("A").Save(ctx); err != nil {
			return err
		}
		b, err = tx.Tenant.Create().SetSlug("iso-b-" + strings.ToLower(ids.New("x")[2:8])).SetName("B").Save(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var bProduct *ent.Product
	for _, tn := range []*ent.Tenant{a, b} {
		if err := WithTenant(ctx, client, tn.ID, func(tx *ent.Tx) error {
			p, err := tx.Product.Create().SetTenantID(tn.ID).SetSlug("db").SetName("DB").Save(ctx)
			if tn == b {
				bProduct = p
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	err := WithTenant(ctx, client, a.ID, func(tx *ent.Tx) error {
		// Unfiltered queries only return A's rows.
		ps, err := tx.Product.Query().All(ctx)
		if err != nil {
			return err
		}
		for _, p := range ps {
			if p.TenantID != a.ID {
				t.Errorf("tenant A saw product of tenant %s", p.TenantID)
			}
		}
		if n, _ := tx.Tenant.Query().Count(ctx); n != 1 {
			t.Errorf("tenant A sees %d tenants, want 1", n)
		}
		// B's product is invisible by ID, can't be changed or deleted.
		if _, err := tx.Product.Get(ctx, bProduct.ID); !ent.IsNotFound(err) {
			t.Errorf("Get B's product: %v, want not found", err)
		}
		if n, _ := tx.Product.Update().Where(product.ID(bProduct.ID)).SetName("pwned").Save(ctx); n != 0 {
			t.Errorf("updated %d of B's products", n)
		}
		if n, _ := tx.Product.Delete().Where(product.ID(bProduct.ID)).Exec(ctx); n != 0 {
			t.Errorf("deleted %d of B's products", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A can't insert rows into B (WITH CHECK).
	err = WithTenant(ctx, client, a.ID, func(tx *ent.Tx) error {
		_, err := tx.Product.Create().SetTenantID(b.ID).SetSlug("smuggled").SetName("x").Save(ctx)
		return err
	})
	if err == nil {
		t.Error("tenant A inserted a product into tenant B")
	}
	// Without any scope, nothing is visible and nothing can be written.
	if n, err := client.Product.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("unscoped query saw %d products (err %v), want 0", n, err)
	}
	if _, err := client.Product.Create().SetTenantID(a.ID).SetSlug("unscoped").SetName("x").Save(ctx); err == nil {
		t.Error("unscoped insert succeeded")
	}
	// The setting is transaction-local: it doesn't leak into later use of the pool.
	if n, _ := client.Tenant.Query().Count(ctx); n != 0 {
		t.Errorf("tenant scope leaked: unscoped query sees %d tenants", n)
	}
}

// TestEveryTenantTableHasRLS fails when a table with a tenant_id column (or the
// tenants table) lacks enabled and forced row-level security and a policy.
func TestEveryTenantTableHasRLS(t *testing.T) {
	_, db := openApp(t)
	rows, err := db.Query(`
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_policies p WHERE p.tablename = c.relname AND p.schemaname = 'public')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		  AND (c.relname = 'tenants' OR EXISTS (
		      SELECT 1 FROM information_schema.columns col
		      WHERE col.table_schema = 'public' AND col.table_name = c.relname AND col.column_name = 'tenant_id'))`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var name string
		var enabled, forced, hasPolicy bool
		if err := rows.Scan(&name, &enabled, &forced, &hasPolicy); err != nil {
			t.Fatal(err)
		}
		seen++
		if !enabled || !forced || !hasPolicy {
			t.Errorf("table %s: RLS enabled=%v forced=%v policy=%v; add it to a migration", name, enabled, forced, hasPolicy)
		}
	}
	if seen < 2 {
		t.Fatalf("found %d tenant tables, expected at least tenants and products", seen)
	}
}
