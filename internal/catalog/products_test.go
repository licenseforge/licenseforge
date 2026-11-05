package catalog

import (
	"context"
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
	l, err := f.s.List(as(f.a, authz.Viewer), 1, time.Time{}, "")
	if err != nil || len(l) != 1 || l[0].ID != cache.ID {
		t.Fatalf("page 1 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Viewer), 5, l[0].CreatedAt, l[0].ID); err != nil || len(l) != 1 || l[0].ID != db.ID {
		t.Fatalf("page 2 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Support, db.ID), 5, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID != db.ID {
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
