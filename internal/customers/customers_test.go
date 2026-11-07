package customers

import (
	"context"
	"errors"
	"fmt"
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
	s    Service
	a, b string
}

func setup(t *testing.T) fixture {
	t.Helper()
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := fixture{db: d, s: Service{DB: d}}
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

func as(tenant string, role authz.Role, products ...string) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: tenant, Role: role,
		Scope: authz.Scope{All: len(products) == 0, Products: products}})
}

func (f fixture) lastEvent(t *testing.T) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
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

func ptr[T any](v T) *T { return &v }

func TestCustomers(t *testing.T) {
	f := setup(t)
	mgr := as(f.a, authz.Manager)
	c, err := f.s.Create(mgr, Input{Name: "Contoso", Email: ptr("it@contoso.example"), ExternalRefs: map[string]string{"stripe": "cus_1"}})
	if err != nil || c.Name != "Contoso" || *c.Email != "it@contoso.example" || c.ExternalRefs["stripe"] != "cus_1" {
		t.Fatalf("create = %+v, %v", c, err)
	}
	e := f.lastEvent(t)
	if e.Action != "customer.create" || e.Outcome != auditevent.OutcomeSuccess || strings.Contains(e.Details, "contoso") || strings.Contains(e.Details, "Contoso") {
		t.Errorf("audit (no name or email) = %+v", e)
	}
	c2, err := f.s.Create(mgr, Input{Name: "Fabrikam"})
	if err != nil || c2.Email != nil || len(c2.ExternalRefs) != 0 {
		t.Fatalf("create minimal = %+v, %v", c2, err)
	}
	if _, err := f.s.Create(as(f.b, authz.Manager), Input{Name: "B"}); err != nil {
		t.Fatal(err)
	}
	// List newest first; tenant-wide: a product-scoped principal sees none.
	l, err := f.s.List(as(f.a, authz.Viewer), 1, time.Time{}, "")
	if err != nil || len(l) != 1 || l[0].ID != c2.ID {
		t.Fatalf("page 1 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Viewer), 5, l[0].CreatedAt, l[0].ID); err != nil || len(l) != 1 || l[0].ID != c.ID {
		t.Fatalf("page 2 = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, authz.Support, ids.Product()), 5, time.Time{}, ""); err != nil || len(l) != 0 {
		t.Errorf("scoped list = %v, %v", l, err)
	}
	// Hidden and missing alike, for get, update and archive.
	for name, x := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {mgr, ids.Customer()},
		"malformed":        {mgr, "x"},
		"another tenant's": {as(f.b, authz.Manager), c.ID},
		"product-scoped":   {as(f.a, authz.Manager, ids.Product()), c.ID},
	} {
		if _, err := f.s.Get(x.ctx, x.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %s: %v", name, err)
		}
		if _, err := f.s.Update(x.ctx, x.id, Patch{Name: ptr("x")}); !errors.Is(err, ErrNotFound) {
			t.Errorf("update %s: %v", name, err)
		}
		if _, err := f.s.Archive(x.ctx, x.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("archive %s: %v", name, err)
		}
	}
	// Merge patch (RFC 7396): absent stays; refs merge per key; email is
	// nullable (null clears it).
	u, err := f.s.Update(mgr, c.ID, Patch{Name: ptr("Contoso Ltd"), ExternalRefs: map[string]*string{"crm": ptr("42")}})
	if err != nil || u.Name != "Contoso Ltd" || *u.Email != "it@contoso.example" || u.ExternalRefs["crm"] != "42" || u.ExternalRefs["stripe"] != "cus_1" {
		t.Fatalf("update = %+v, %v", u, err)
	}
	// A null value removes its key (not stored as "").
	if u, err = f.s.Update(mgr, c.ID, Patch{ExternalRefs: map[string]*string{"stripe": nil, "gone": nil}}); err != nil || len(u.ExternalRefs) != 1 || u.ExternalRefs["crm"] != "42" {
		t.Fatalf("remove ref = %+v, %v", u.ExternalRefs, err)
	}
	if _, ok := u.ExternalRefs["stripe"]; ok {
		t.Error("a null ref was stored")
	}
	if u, err = f.s.Update(mgr, c.ID, Patch{Null: []string{"email"}}); err != nil || u.Email != nil || u.Name != "Contoso Ltd" {
		t.Fatalf("clear email = %+v, %v", u, err)
	}
	if e := f.lastEvent(t); e.Action != "customer.update" || !strings.Contains(e.Details, `"email"`) || strings.Contains(e.Details, "contoso") {
		t.Errorf("update audit = %s", e.Details)
	}
	// Archive: once (409 after), still readable and editable.
	a, err := f.s.Archive(mgr, c.ID)
	if err != nil || a.ArchivedAt == nil {
		t.Fatalf("archive = %+v, %v", a, err)
	}
	if _, err := f.s.Archive(mgr, c.ID); !errors.Is(err, ErrState) {
		t.Errorf("archive twice: %v", err)
	}
	// Rights before state: a viewer is refused for its role, not told it's archived.
	if _, err := f.s.Archive(as(f.a, authz.Viewer), c.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer archives an archived customer: %v", err)
	}
	if g, err := f.s.Get(mgr, c.ID); err != nil || g.ArchivedAt == nil {
		t.Errorf("get archived = %v, %v", g, err)
	}
}

// The 20-entry limit applies to the merged refs.
func TestMergedRefsLimit(t *testing.T) {
	f := setup(t)
	mgr := as(f.a, authz.Manager)
	refs := map[string]string{}
	for i := range 20 {
		refs[fmt.Sprintf("k%d", i)] = "v"
	}
	c, err := f.s.Create(mgr, Input{Name: "Full", ExternalRefs: refs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Update(mgr, c.ID, Patch{ExternalRefs: map[string]*string{"one_more": ptr("v")}}); field(err) != "/external_refs" {
		t.Errorf("21st ref: %v", err)
	}
	if _, err := f.s.Update(mgr, c.ID, Patch{ExternalRefs: map[string]*string{"k0": nil, "one_more": ptr("v")}}); err != nil {
		t.Errorf("swap a ref: %v", err)
	}
}

func TestCustomerRefusals(t *testing.T) {
	f := setup(t)
	mgr := as(f.a, authz.Manager)
	c, err := f.s.Create(mgr, Input{Name: "Contoso"})
	if err != nil {
		t.Fatal(err)
	}
	// Rights before values: support and viewers read, managers write.
	for name, ctx := range map[string]context.Context{"support": as(f.a, authz.Support), "viewer": as(f.a, authz.Viewer), "sdk": as(f.a, authz.SDK)} {
		if _, err := f.s.Create(ctx, Input{Name: ""}); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("create as %s: %v", name, err)
		}
		if name == "sdk" {
			continue // sdk can't read customers either: not found
		}
		if _, err := f.s.Update(ctx, c.ID, Patch{Name: ptr("")}); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("update as %s: %v", name, err)
		}
		if _, err := f.s.Archive(ctx, c.ID); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("archive as %s: %v", name, err)
		}
	}
	if e := f.lastEvent(t); e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied audit = %+v", e)
	}
	for name, x := range map[string]struct {
		in    Input
		field string
	}{
		"blank name":        {Input{Name: " "}, "/name"},
		"long name":         {Input{Name: strings.Repeat("n", 201)}, "/name"},
		"email without @":   {Input{Name: "x", Email: ptr("nope")}, "/email"},
		"email with space":  {Input{Name: "x", Email: ptr("a b@example.com")}, "/email"},
		"email two @":       {Input{Name: "x", Email: ptr("a@b@c")}, "/email"},
		"email no local":    {Input{Name: "x", Email: ptr("@b")}, "/email"},
		"email no domain":   {Input{Name: "x", Email: ptr("a@")}, "/email"},
		"email @@":          {Input{Name: "x", Email: ptr("a@@b")}, "/email"},
		"ref key uppercase": {Input{Name: "x", ExternalRefs: map[string]string{"Stripe": "1"}}, "/external_refs"},
		"ref value newline": {Input{Name: "x", ExternalRefs: map[string]string{"stripe": "a\nb"}}, "/external_refs"},
	} {
		if _, err := f.s.Create(mgr, x.in); field(err) != x.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, x := range map[string]struct {
		p     Patch
		field string
	}{
		"null name":           {Patch{Null: []string{"name"}}, "/name"},
		"null external_refs":  {Patch{Null: []string{"external_refs"}}, "/external_refs"},
		"bad email":           {Patch{Email: ptr("x")}, "/email"},
		"two @ email":         {Patch{Email: ptr("a@b@c")}, "/email"},
		"merged refs invalid": {Patch{ExternalRefs: map[string]*string{"Bad": ptr("1")}}, "/external_refs"},
	} {
		if _, err := f.s.Update(mgr, c.ID, x.p); field(err) != x.field {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// CountActive counts non-archived customers of the caller's tenant, exactly,
// and only for callers who see every customer (customer:read on every
// product); for anyone else it reports "not available", never a partial count.
func TestCountActive(t *testing.T) {
	f := setup(t)
	mgrA := as(f.a, authz.Manager)
	var archived string
	for i, name := range []string{"Contoso", "Fabrikam", "Northwind"} {
		c, err := f.s.Create(mgrA, Input{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			archived = c.ID
		}
	}
	if _, err := f.s.Archive(mgrA, archived); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Create(as(f.b, authz.Manager), Input{Name: "Other tenant"}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		ctx context.Context
		n   int
		ok  bool
	}{
		"manager, every product":  {mgrA, 2, true},
		"viewer, every product":   {as(f.a, authz.Viewer), 2, true},
		"other tenant":            {as(f.b, authz.Viewer), 1, true},
		"product-scoped caller":   {as(f.a, authz.Owner, ids.Product()), 0, false},
		"sdk token (no customer)": {as(f.a, authz.SDK), 0, false},
	} {
		n, ok, err := f.s.CountActive(c.ctx)
		if err != nil || n != c.n || ok != c.ok {
			t.Errorf("%s: %d, %v, %v; want %d, %v", name, n, ok, err, c.n, c.ok)
		}
	}
}

// An archive or update that waits for a concurrent archive sees the archived
// customer (lookup looks again after archive_once filters the row it waited
// for): a second archive is ErrState, an update succeeds.
func TestChangeWaitsForArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a, authz.Manager)
	for name, c := range map[string]struct {
		op   func(id string) error
		want error
	}{
		"archive": {func(id string) error { _, err := f.s.Archive(mgr, id); return err }, ErrState},
		"update":  {func(id string) error { _, err := f.s.Update(mgr, id, Patch{Name: ptr("Renamed")}); return err }, nil},
	} {
		cus, err := f.s.Create(mgr, Input{Name: "C"})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE customers SET archived_at = clock_timestamp() WHERE id = $1`, cus.ID); err != nil {
				return err
			}
			go func() { done <- c.op(cus.ID) }()
			storetest.WaitForLockWaiter(t, env)
			return nil
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
