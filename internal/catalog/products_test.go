package catalog

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db   *store.DB
	s    Products
	a, b string
}

func setup(t *testing.T) fixture {
	t.Helper()
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := fixture{db: d, s: Products{DB: d}}
	if err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(context.Background())
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// as is a token principal: the catalog services don't manage access, so a
// user's membership isn't re-read.
func as(tenant string, role authz.Role, products ...string) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: tenant, Role: role,
		Scope: authz.Scope{All: len(products) == 0, Products: products}})
}

func (f fixture) lastEvent(t *testing.T, tenant string) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		e, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).First(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func field(err error) string {
	var inv *InvalidError
	if errors.As(err, &inv) {
		return inv.Field
	}
	return ""
}

func TestProducts(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil || db.Slug != "db" || db.Name != "Database" {
		t.Fatalf("create = %+v, %v", db, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "product.create" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != db.ID {
		t.Errorf("audit = %+v", e)
	}
	cache, err := f.s.Create(admin, "cache", "Cache")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Create(as(f.b, authz.Admin), "db", "Other tenant, same slug"); err != nil {
		t.Errorf("slugs are per tenant: %v", err)
	}
	// List newest first; a product-scoped principal sees only its products.
	l, err := f.s.List(as(f.a, authz.Viewer), nil, 1, time.Time{}, "")
	if err != nil || len(l) != 1 || l[0].ID != cache.ID {
		t.Fatalf("page 1 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Viewer), nil, 5, l[0].CreatedAt, l[0].ID); err != nil || len(l) != 1 || l[0].ID != db.ID {
		t.Fatalf("page 2 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Support, db.ID), nil, 5, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID != db.ID {
		t.Errorf("scoped list = %v, %v", l, err)
	}
	// Get: hidden and missing alike.
	if p, err := f.s.Get(as(f.a, authz.Viewer, db.ID), db.ID); err != nil || p.ID != db.ID {
		t.Errorf("get = %v, %v", p, err)
	}
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {admin, ids.Product()},
		"malformed":        {admin, "x"},
		"another tenant's": {as(f.b, authz.Admin), db.ID},
		"out of scope":     {as(f.a, authz.Viewer, cache.ID), db.ID},
	} {
		if _, err := f.s.Get(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %s: %v", name, err)
		}
		if _, err := f.s.Update(c.ctx, c.id, Patch{Name: ptr("x")}); !errors.Is(err, ErrNotFound) {
			t.Errorf("update %s: %v", name, err)
		}
	}
	// Update: the name only (slugs are immutable).
	if p, err := f.s.Update(admin, db.ID, Patch{Name: ptr("DB")}); err != nil || p.Name != "DB" || p.Slug != "db" {
		t.Errorf("update = %+v, %v", p, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "product.update" || e.Outcome != auditevent.OutcomeSuccess {
		t.Errorf("update audit = %+v", e)
	}
	// A product-scoped admin may rename its own product.
	if _, err := f.s.Update(as(f.a, authz.Admin, db.ID), db.ID, Patch{Name: ptr("DB 2")}); err != nil {
		t.Errorf("scoped admin: %v", err)
	}
}

func TestProductRefusals(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	// Rights before values.
	for name, ctx := range map[string]context.Context{
		"manager":              as(f.a, authz.Manager),
		"product-scoped admin": as(f.a, authz.Admin, db.ID), // creating is tenant-wide
		"sdk":                  as(f.a, authz.SDK),
	} {
		if _, err := f.s.Create(ctx, "BAD SLUG", ""); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("create as %s: %v", name, err)
		}
	}
	if e := f.lastEvent(t, f.a); e.Action != "product.create" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied audit = %+v", e)
	}
	if _, err := f.s.Update(as(f.a, authz.Manager), db.ID, Patch{Name: ptr("")}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager update: %v", err)
	}
	for name, c := range map[string]struct{ slug, name, field string }{
		"slug uppercase": {"DB", "x", "/slug"},
		"slug too long":  {strings.Repeat("a", 64), "x", "/slug"},
		"slug empty":     {"", "x", "/slug"},
		"name blank":     {"ok", " ", "/name"},
		"name too long":  {"ok", strings.Repeat("n", 201), "/name"},
		"name control":   {"ok", "a\nb", "/name"},
	} {
		if _, err := f.s.Create(admin, c.slug, c.name); field(err) != c.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var inv *InvalidError
	if _, err := f.s.Create(admin, "db", "Again"); !errors.Is(err, ErrConflict) || !errors.As(err, &inv) || inv.Field != "/slug" {
		t.Errorf("slug taken: %v", err)
	}
	for name, p := range map[string]Patch{"blank name": {Name: ptr(" ")}, "null name": {Null: []string{"name"}}} {
		if _, err := f.s.Update(admin, db.ID, p); field(err) != "/name" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func TestProductArchive(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := f.s.Create(admin, "cache", "Cache")
	if err != nil {
		t.Fatal(err)
	}
	// Rights: catalog:write on that product; hidden and missing are not found.
	if _, err := f.s.Archive(as(f.a, authz.Manager), db.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager: %v", err)
	}
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {admin, ids.Product()},
		"another tenant's": {as(f.b, authz.Admin), db.ID},
		"out of scope":     {as(f.a, authz.Admin, cache.ID), db.ID},
	} {
		if _, err := f.s.Archive(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	a, err := f.s.Archive(as(f.a, authz.Admin, db.ID), db.ID) // a scoped admin may archive its own product
	if err != nil || a.ArchivedAt == nil || a.Slug != "db" {
		t.Fatalf("archive = %+v, %v", a, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "product.archive" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != db.ID {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.s.Archive(admin, db.ID); !errors.Is(err, ErrState) {
		t.Errorf("archive twice: %v", err)
	}
	// Archived products stay listed; ?archived filters.
	no, yes := false, true
	for name, c := range map[string]struct {
		archived *bool
		want     []string
	}{"all": {nil, []string{cache.ID, db.ID}}, "active": {&no, []string{cache.ID}}, "archived": {&yes, []string{db.ID}}} {
		l, err := f.s.List(as(f.a, authz.Viewer), c.archived, 10, time.Time{}, "")
		var got []string
		for _, p := range l {
			got = append(got, p.ID)
		}
		if err != nil || strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
	// Still readable and renamable.
	if _, err := f.s.Update(admin, db.ID, Patch{Name: ptr("Old DB")}); err != nil {
		t.Errorf("rename archived: %v", err)
	}
}

// An archive or rename that waits for a concurrent archive sees the
// archived product (it looks again after archive_once filters the row it
// waited for): a second archive is ErrState, a rename succeeds.
func TestChangeWaitsForArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin := as(f.a, authz.Admin)
	adminDB, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminDB.Close() }()
	for name, c := range map[string]struct {
		slug string
		op   func(id string) error
		want error
	}{
		"archive": {"a", func(id string) error { _, err := f.s.Archive(admin, id); return err }, ErrState},
		"rename":  {"r", func(id string) error { _, err := f.s.Update(admin, id, Patch{Name: ptr("Renamed")}); return err }, nil},
	} {
		p, err := f.s.Create(admin, c.slug, "P")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE products SET archived_at = clock_timestamp() WHERE id = $1`, p.ID); err != nil {
				return err
			}
			go func() { done <- c.op(p.ID) }()
			for i := 0; ; i++ {
				var n int
				if err := adminDB.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					return nil
				}
				if i == 100 {
					return errors.New("never waited")
				}
				time.Sleep(20 * time.Millisecond)
			}
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Errorf("%s after a concurrent archive: %v, want %v", name, err, c.want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s didn't finish", name)
		}
	}
}
