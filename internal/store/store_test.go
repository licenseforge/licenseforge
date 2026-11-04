package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

// Tests need PostgreSQL; see package storetest.
var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, Migrate)) }

func openDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), testLogins())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenRefusesUnsafeRoles(t *testing.T) {
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	s := storetest.Suffix()
	ownerRole := "lf_own_" + strings.TrimPrefix(env.Name, "lf_test_")
	creator, byp, member := "lf_cr_"+s, "lf_byp_"+s, "lf_mem_"+s
	inOwner, inProgram, temp, creates, twoGroups := "lf_io_"+s, "lf_ip_"+s, "lf_tmp_"+s, "lf_cs_"+s, "lf_2g_"+s
	logins := []string{creator, member, inOwner, inProgram, temp, creates, twoGroups}
	for _, r := range append(logins, byp) {
		storetest.AddCleanup(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, r))
	}
	if err := storetest.AdminExec(admin,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' CREATEROLE IN ROLE licenseforge_app`, creator),
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN BYPASSRLS`, byp),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app, %s`, member, byp),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app, %s`, inOwner, ownerRole),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app, pg_execute_server_program`, inProgram),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app`, temp),
		fmt.Sprintf(`GRANT TEMPORARY ON DATABASE %s TO %s`, env.Name, temp),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app`, creates),
		fmt.Sprintf(`GRANT CREATE ON DATABASE %s TO %s`, env.Name, creates),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test' IN ROLE licenseforge_app, licenseforge_identity`, twoGroups),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, env.Name, strings.Join(logins, ", ")),
	); err != nil {
		t.Fatal(err)
	}
	tenantUser := "lf_api_" + strings.TrimPrefix(env.Name, "lf_test_")
	for name, dsn := range map[string]string{
		"superuser":                           strings.Replace(env.AdminURL, "/postgres?", "/"+env.Name+"?", 1),
		"schema owner":                        env.OwnerURL,
		"platform login":                      env.PlatformURL,
		"createrole":                          storetest.UserURL(env.AdminURL, creator, env.Name),
		"member of bypassrls":                 storetest.UserURL(env.AdminURL, member, env.Name),
		"member of owner role":                storetest.UserURL(env.AdminURL, inOwner, env.Name),
		"member of pg_execute_server_program": storetest.UserURL(env.AdminURL, inProgram, env.Name),
		"can create temp tables":              storetest.UserURL(env.AdminURL, temp, env.Name),
		"can create schemas":                  storetest.UserURL(env.AdminURL, creates, env.Name),
		"preset tenant":                       storetest.UserURL(env.AdminURL, tenantUser, env.Name, "app.tenant_id", "tnt_x"),
		"switched role":                       storetest.UserURL(env.AdminURL, tenantUser, env.Name, "role", "licenseforge_app"),
		"superuser switched too":              strings.Replace(env.AdminURL, "/postgres?", "/"+env.Name+"?role="+tenantUser+"&", 1),
	} {
		t.Run(name, func(t *testing.T) {
			l := testLogins()
			l.Tenant = dsn
			if _, err := Open(context.Background(), l); !errors.Is(err, ErrUnsafeRole) {
				t.Fatalf("got %v, want ErrUnsafeRole", err)
			}
		})
	}
	// A login in two groups is refused by both pools.
	twoGroupsURL := storetest.UserURL(env.AdminURL, twoGroups, env.Name)
	for name, l := range map[string]Logins{
		"two groups as tenant pool":   {Tenant: twoGroupsURL, Platform: env.PlatformURL, Identity: env.IdentityURL},
		"two groups as identity pool": {Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: twoGroupsURL},
	} {
		if _, err := Open(context.Background(), l); !errors.Is(err, ErrUnsafeRole) {
			t.Errorf("%s: got %v, want ErrUnsafeRole", name, err)
		}
	}
	// Every pool refuses the other pools' logins (ADR-0009, ADR-0029).
	for name, l := range map[string]Logins{
		"tenant login as platform pool":   {Tenant: env.TenantURL, Platform: env.TenantURL, Identity: env.IdentityURL},
		"tenant login as identity pool":   {Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.TenantURL},
		"platform login as identity pool": {Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.PlatformURL},
		"identity login as tenant pool":   {Tenant: env.IdentityURL, Platform: env.PlatformURL, Identity: env.IdentityURL},
		"identity login as platform pool": {Tenant: env.TenantURL, Platform: env.IdentityURL, Identity: env.IdentityURL},
		"owner login as identity pool":    {Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.OwnerURL},
	} {
		if _, err := Open(context.Background(), l); !errors.Is(err, ErrUnsafeRole) {
			t.Errorf("%s: got %v, want ErrUnsafeRole", name, err)
		}
	}
}

func testLogins() Logins {
	return Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	t.Run("concurrent and idempotent", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 5)
		for range 5 {
			wg.Add(1)
			go func() { defer wg.Done(); errs <- Migrate(ctx, env.OwnerURL) }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	owner, err := sql.Open("pgx", env.OwnerURL)
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
			if err := Migrate(ctx, env.OwnerURL); err == nil {
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
	owner, err := sql.Open("pgx", env.OwnerURL)
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
			tn, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(context.Background())
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
		"delete B's product": func(tx *ent.Tx) error {
			n, err := tx.Product.Delete().Where(product.ID(bProduct.ID)).Exec(ctx)
			if err == nil && n == 0 {
				return errors.New("no rows")
			}
			return err
		},
		"escalate to platform role": func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `SET LOCAL ROLE licenseforge_platform`)
			return err
		},
		"shadow a table with a temp table": func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE products (LIKE public.products)`)
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

// Nothing a request leaves in its session (settings, prepared statements)
// may survive to the next request on the same pooled connection.
func TestSessionStateIsResetBetweenRequests(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	d.tenantDB.SetMaxOpenConns(1) // force reuse of the same connection
	tn := createTenants(t, d, 1)[0]
	if err := d.WithTenant(ctx, tn.ID, func(tx *ent.Tx) error {
		// A buggy request leaves session-level state behind.
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, false), set_config('app.stolen', 'x', false)`, tn.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `PREPARE planted AS SELECT 1`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var tenantSetting, stolen string
	var prepared int
	if err := d.tenantDB.QueryRowContext(ctx, `SELECT COALESCE(current_setting('app.tenant_id', true), ''),
		COALESCE(current_setting('app.stolen', true), ''), (SELECT count(*) FROM pg_prepared_statements)`).
		Scan(&tenantSetting, &stolen, &prepared); err != nil {
		t.Fatal(err)
	}
	if tenantSetting != "" || stolen != "" || prepared != 0 {
		t.Fatalf("session state survived: app.tenant_id=%q app.stolen=%q prepared statements=%d", tenantSetting, stolen, prepared)
	}
	if n, err := d.tenant.Product.Query().Count(ctx); err != nil || n != 0 {
		t.Fatalf("unscoped query after a leaked session setting saw %d rows (err %v)", n, err)
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
	owner, err := sql.Open("pgx", env.OwnerURL)
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
	// Policies beyond the canonical ones, pinned: changing one means changing
	// this list, so it gets reviewed.
	extra := map[string]map[string]string{ // ADR-0029: identity role and the invitation rules
		"tenants": {
			"identity_read": `SELECT licenseforge_identity true`,
		},
		"audit_events": {
			"identity_audit": `ALL licenseforge_identity ((tenant_id)::text = app_tenant_id()) ((tenant_id)::text = app_tenant_id())`,
		},
		"invitations": {
			"identity_mark_accepted":          `UPDATE licenseforge_identity ((accepted_at IS NULL) AND (revoked_at IS NULL) AND (expires_at > clock_timestamp())) ((accepted_by IS NOT NULL) AND (EXISTS ( SELECT 1 FROM memberships m WHERE (((m.invitation_id)::text = (invitations.id)::text) AND ((m.user_id)::text = (invitations.accepted_by)::text)))))`,
			"identity_read":                   `SELECT licenseforge_identity true`,
			"revoke_only (restrictive)":       `UPDATE licenseforge_app ((revoked_at IS NULL) AND (accepted_at IS NULL)) (revoked_at IS NOT NULL)`,
			"inviter_is_member (restrictive)": `INSERT licenseforge_app (EXISTS ( SELECT 1 FROM memberships m WHERE (((m.tenant_id)::text = (invitations.tenant_id)::text) AND ((m.user_id)::text = (invitations.invited_by)::text))))`,
		},
		"invitation_products": {
			"identity_read": `SELECT licenseforge_identity true`,
		},
		"memberships": {
			"identity_accept": `INSERT licenseforge_identity (((tenant_id)::text = app_tenant_id()) AND (EXISTS ( SELECT 1 FROM (invitations i JOIN users u ON (((u.id)::text = (memberships.user_id)::text))) WHERE (((i.id)::text = (memberships.invitation_id)::text) AND ((i.tenant_id)::text = (memberships.tenant_id)::text) AND ((i.role)::text = (memberships.role)::text) AND (i.scope_all = memberships.scope_all) AND (i.accepted_at IS NULL) AND (i.revoked_at IS NULL) AND (i.expires_at > clock_timestamp()) AND u.email_verified AND (u.disabled_at IS NULL) AND (lower(NORMALIZE(u.email, NFC)) = lower(NORMALIZE(i.email, NFC))) AND ((i.issuer IS NULL) OR ((i.issuer)::text = (u.issuer)::text)) AND (i.token_hash = sha256(convert_to(current_setting('app.invite_token'::text, true), 'UTF8'::name)))))))`,
			"identity_read":   `SELECT licenseforge_identity true`,
		},
		"membership_products": {
			"identity_copy_scope": `INSERT licenseforge_identity (((tenant_id)::text = app_tenant_id()) AND (EXISTS ( SELECT 1 FROM ((memberships m JOIN invitations i ON (((i.id)::text = (m.invitation_id)::text))) JOIN invitation_products ip ON ((((ip.invitation_id)::text = (m.invitation_id)::text) AND ((ip.tenant_id)::text = (m.tenant_id)::text)))) WHERE (((m.id)::text = (membership_products.membership_id)::text) AND ((ip.product_id)::text = (membership_products.product_id)::text) AND (i.accepted_at IS NULL) AND (i.revoked_at IS NULL)))))`,
			"identity_read":       `SELECT licenseforge_identity true`,
		},
	}
	// Global tables (no tenant_id), each with its exact policies (ADR-0029).
	global := map[string]map[string]string{
		"users": {
			"users_member_of_tenant": `SELECT licenseforge_app (EXISTS ( SELECT 1 FROM memberships m WHERE (((m.user_id)::text = (users.id)::text) AND ((m.tenant_id)::text = app_tenant_id()))))`,
			"identity_all":           "ALL licenseforge_identity true true",
			"platform_all":           "ALL licenseforge_platform true true",
		},
	}
	with := func(base map[string]string, table string) map[string]string {
		out := maps.Clone(base)
		maps.Copy(out, extra[table])
		return out
	}
	ou, _ := url.Parse(env.OwnerURL)
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
			got[name] = strings.Join(strings.Fields(cmd+" "+roles+" "+qual+" "+check), " ")
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

	// Functions: only app_tenant_id, exactly as written, not SECURITY DEFINER,
	// not executable by PUBLIC. Triggers and rules run with owner rights and
	// are refused until reviewed.
	frows, err := owner.Query(`
		SELECT p.proname, p.prosecdef, p.prosrc, COALESCE(array_to_string(p.proconfig, ','), ''),
		       has_function_privilege('public', p.oid, 'EXECUTE')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'`)
	if err != nil {
		t.Fatal(err)
	}
	for frows.Next() {
		var name, src, config string
		var secdef, publicExec bool
		if err := frows.Scan(&name, &secdef, &src, &config, &publicExec); err != nil {
			t.Fatal(err)
		}
		switch {
		case name != "app_tenant_id":
			t.Errorf("function %s: only app_tenant_id is allowed in public; review any new function", name)
		case secdef || config != "" || publicExec:
			t.Errorf("app_tenant_id: security definer=%v config=%q executable by PUBLIC=%v", secdef, config, publicExec)
		case strings.TrimSpace(src) != `SELECT NULLIF(pg_catalog.current_setting('app.tenant_id', true), '')`:
			t.Errorf("app_tenant_id body changed: %q", src)
		}
	}
	_ = frows.Close()
	var triggers, rules int
	if err := owner.QueryRow(`SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND NOT t.tgisinternal`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`SELECT count(*) FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND r.rulename <> '_RETURN'`).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if triggers+rules != 0 {
		t.Errorf("%d triggers and %d rules on public tables: they run with owner rights, review before allowing", triggers, rules)
	}
	for _, role := range []string{AppRole, PlatformRole} {
		var any bool
		if err := owner.QueryRow(`SELECT has_table_privilege($1, 'schema_migrations', 'SELECT,INSERT,UPDATE,DELETE')`, role).Scan(&any); err != nil {
			t.Fatal(err)
		}
		if any {
			t.Errorf("%s has privileges on schema_migrations", role)
		}
	}

	var schemas sql.NullString
	if err := owner.QueryRow(`SELECT string_agg(nspname, ', ') FROM pg_namespace
		WHERE nspname NOT IN ('public','pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp%'`).Scan(&schemas); err != nil {
		t.Fatal(err)
	}
	if schemas.Valid {
		t.Errorf("schemas other than public: %s (functions or objects there escape these checks)", schemas.String)
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
			checkPolicies(r, with(tenantsPolicies, r.name))
		case global[r.name] != nil && !r.hasTenant:
			checkPolicies(r, global[r.name])
		case !r.hasTenant:
			t.Errorf("table %s has no tenant_id: add one or allow-list it here with a reason", r.name)
		default:
			tenantTables++
			checkPolicies(r, with(tenantPolicies, r.name))
		}
	}
	if tenantTables == 0 {
		t.Fatal("no tenant tables found")
	}
}

func TestNoTransactionMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	m := migration{version: "29990101000000_concurrent", checksum: "x",
		body: noTxMarker + "\nCREATE INDEX CONCURRENTLY products_name_idx ON products (name);"}
	if err := applyOne(ctx, conn, m); err != nil {
		t.Fatalf("CREATE INDEX CONCURRENTLY with the marker: %v", err)
	}
	_, _ = conn.ExecContext(ctx, `DROP INDEX products_name_idx`)
	_, _ = conn.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, m.version)
	m.body = "CREATE INDEX CONCURRENTLY products_name_idx ON products (name);"
	if err := applyOne(ctx, conn, m); err == nil {
		t.Fatal("without the marker the statement must fail inside a transaction")
	}
	// A leftover invalid index (failed concurrent build) stops the migration.
	if _, err := conn.ExecContext(ctx, `CREATE INDEX products_bad_idx ON products (name)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `DROP INDEX IF EXISTS products_bad_idx`) }()
	// Simulating the failed build needs superuser (pg_index is a catalog).
	su, err := sql.Open("pgx", strings.Replace(env.AdminURL, "/postgres?", "/"+env.Name+"?", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = su.Close() }()
	if _, err := su.Exec(`UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'products_bad_idx'::regclass`); err != nil {
		t.Fatal(err)
	}
	m = migration{version: "29990101000001_noop", checksum: "x", body: noTxMarker + "\nSELECT 1;"}
	if err := applyOne(ctx, conn, m); err == nil || !strings.Contains(err.Error(), "products_bad_idx") {
		t.Fatalf("got %v, want an error naming the invalid index", err)
	}
	var recorded bool
	_ = conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&recorded)
	if recorded {
		t.Fatal("migration recorded as applied despite an invalid index")
	}
}

func TestCheckVersion(t *testing.T) {
	if checkVersion(160009) == nil {
		t.Error("PostgreSQL 16 accepted")
	}
	if err := checkVersion(170000); err != nil {
		t.Error(err)
	}
	// Both entry points check: pretend the test server is too old.
	defer func(v int) { minPostgres = v }(minPostgres)
	minPostgres = 990000
	ctx := context.Background()
	if err := Migrate(ctx, env.OwnerURL); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("Migrate: %v", err)
	}
	if d, err := Open(ctx, testLogins()); err == nil || !strings.Contains(err.Error(), "not supported") {
		if d != nil {
			_ = d.Close()
		}
		t.Errorf("Open: %v", err)
	}
}

// Ping fails when any pool is unusable (/readyz).
func TestPingChecksEveryPool(t *testing.T) {
	for _, pool := range []string{"tenant", "platform", "identity"} {
		d, err := Open(context.Background(), testLogins())
		if err != nil {
			t.Fatal(err)
		}
		_ = map[string]*sql.DB{"tenant": d.tenantDB, "platform": d.platformDB, "identity": d.identityDB}[pool].Close()
		if err := d.Ping(context.Background()); err == nil {
			t.Errorf("Ping with the %s pool closed = nil", pool)
		}
		_ = d.Close()
	}
}
