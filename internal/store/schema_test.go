package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	entsql "entgo.io/ent/dialect/sql"

	"licenseforge.io/licenseforge/internal/store/ent"
)

// describe returns a normalized description of the public schema: columns,
// indexes, CHECK constraints and foreign keys (as PostgreSQL renders them).
// Hand-written *_same_tenant keys are listed separately.
func describe(t *testing.T, db *sql.DB) (core []string, sameTenant []string) {
	t.Helper()
	queries := []string{
		`SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || ' ' ||
		        COALESCE(character_maximum_length::text, '') || ' nullable=' || is_nullable
		 FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`,
		`SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename <> 'schema_migrations'`,
		`SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ' ' || pg_get_constraintdef(oid)
		 FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND contype IN ('c', 'f', 'u', 'p')
		   AND conrelid::regclass::text <> 'schema_migrations'`,
	}
	for _, q := range queries {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(s, "_same_tenant ") {
				sameTenant = append(sameTenant, s)
			} else {
				core = append(core, s)
			}
		}
		_ = rows.Close()
	}
	sort.Strings(core)
	return core, sameTenant
}

// TestMigrationsMatchEntSchema builds a database straight from the ent schema
// and compares it with the migrated one, so changed CHECK expressions, removed
// columns or indexes, or other drift the migration diff doesn't report fail.
func TestMigrationsMatchEntSchema(t *testing.T) {
	ctx := context.Background()
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	ref := "lf_test_ref_" + suffix()
	addCleanup(fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, ref))
	if _, err := admin.Exec(`CREATE DATABASE ` + ref); err != nil {
		t.Fatal(err)
	}
	refDB, err := sql.Open("pgx", strings.Replace(adminURL, "/postgres?", "/"+ref+"?", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = refDB.Close() }()
	if err := ent.NewClient(ent.Driver(entsql.OpenDB("postgres", refDB))).Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	migrated, err := sql.Open("pgx", env.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migrated.Close() }()

	want, _ := describe(t, refDB)
	got, _ := describe(t, migrated)
	diff := func(a, b []string) []string {
		in := map[string]bool{}
		for _, s := range b {
			in[s] = true
		}
		var out []string
		for _, s := range a {
			if !in[s] {
				out = append(out, s)
			}
		}
		return out
	}
	for _, s := range diff(want, got) {
		t.Errorf("in ent schema, missing from migrations: %s", s)
	}
	for _, s := range diff(got, want) {
		t.Errorf("in migrations, not in ent schema: %s", s)
	}
}

// TestCrossTableReferencesAreSameTenant: foreign key checks bypass row-level
// security, so every plain foreign key between tenant tables (other than the
// tenant_id key to tenants) must be covered by a *_same_tenant composite key on
// the same table that includes its column. This also catches same-tenant keys
// silently dropped with a column, or names truncated past 63 characters.
func TestCrossTableReferencesAreSameTenant(t *testing.T) {
	owner, err := sql.Open("pgx", env.ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	rows, err := owner.Query(`
		SELECT f.conrelid::regclass::text, f.conname
		FROM pg_constraint f
		WHERE f.contype = 'f' AND f.connamespace = 'public'::regnamespace
		  AND f.conname NOT LIKE '%\_same\_tenant'
		  AND f.confrelid <> 'tenants'::regclass
		  AND NOT EXISTS (
		      SELECT 1 FROM pg_constraint s
		      WHERE s.contype = 'f' AND s.conrelid = f.conrelid
		        AND s.conname LIKE '%\_same\_tenant'
		        AND f.conkey <@ s.conkey AND array_length(s.conkey, 1) >= 2)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var table, name string
		if err := rows.Scan(&table, &name); err != nil {
			t.Fatal(err)
		}
		t.Errorf("%s: foreign key %s isn't covered by a *_same_tenant composite key", table, name)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conname LIKE '%\_same\_tenant'`).Scan(&n); err != nil || n < 5 {
		t.Fatalf("found %d same-tenant keys (err %v), expected at least 5", n, err)
	}
}
