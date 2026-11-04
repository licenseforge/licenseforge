package invitations

import (
	"context"
	"crypto/rand"
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
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db                                       *store.DB
	s                                        Service
	a, b                                     string // tenants
	prodA, prodB                             string // prodB is tenant b's
	ownerA, adminA, viewerA, scopedA, ownerB string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := &fixture{db: d, s: Service{DB: d}}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		for tenant, id := range map[string]*string{f.a: &f.prodA, f.b: &f.prodB} {
			p, err := tx.Product.Create().SetTenantID(tenant).SetSlug("db").SetName("DB").Save(ctx)
			if err != nil {
				return err
			}
			*id = p.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.ownerA = f.join(t, f.a, invitation.RoleOwner, "")
	f.ownerB = f.join(t, f.b, invitation.RoleOwner, "")
	f.adminA = f.join(t, f.a, invitation.RoleAdmin, f.ownerA)
	f.viewerA = f.join(t, f.a, invitation.RoleViewer, f.ownerA)
	f.scopedA = f.join(t, f.a, invitation.RoleAdmin, f.ownerA, f.prodA)
	return f
}

// join makes a new user a member through an invitation written directly
// (the fixture doesn't depend on the service under test).
func (f *fixture) join(t *testing.T, tenant string, role invitation.Role, inviter string, products ...string) string {
	t.Helper()
	ctx := context.Background()
	email := f.email()
	tok := rand.Text()
	create := func(tx *ent.Tx) error {
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(email).SetRole(role).SetScopeAll(len(products) == 0).
			SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour))
		if inviter != "" {
			c.SetInvitedBy(inviter)
		}
		inv, err := c.Save(ctx)
		for _, p := range products {
			if err == nil {
				_, err = tx.InvitationProduct.Create().SetTenantID(tenant).SetInvitationID(inv.ID).SetProductID(p).Save(ctx)
			}
		}
		return err
	}
	var err error
	if inviter == "" {
		err = f.db.WithPlatform(ctx, create)
	} else {
		err = f.db.WithTenant(ctx, tenant, create)
	}
	if err != nil {
		t.Fatal(err)
	}
	uid := f.user(t, email, true)
	if _, err := f.db.AcceptInvitation(ctx, tok, uid, func(*ent.Tx, *ent.Membership) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return uid
}

func (f *fixture) email() string { return strings.ToLower(ids.New("u")[2:14]) + "@example.com" }

func (f *fixture) user(t *testing.T, email string, verified bool) string {
	t.Helper()
	var uid string
	if err := f.db.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(verified).Save(context.Background())
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

func as(tenant, user string, role authz.Role, products ...string) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: user, TenantID: tenant, Role: role,
		Scope: authz.Scope{All: len(products) == 0, Products: products}})
}

func (f *fixture) lastEvent(t *testing.T, tenant string) *ent.AuditEvent {
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

var all = authz.Scope{All: true}

func TestCreateListAccept(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner := as(f.a, f.ownerA, authz.Owner)
	email := f.email()
	c, err := f.s.Create(owner, email, authz.Support, authz.Scope{Products: []string{f.prodA}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Token == "" || string(c.Row.TokenHash) != string(store.InvitationTokenHash(c.Token)) || c.Row.Email != email ||
		*c.Row.InvitedBy != f.ownerA || c.Row.ExpiresAt.Before(time.Now().Add(DefaultTTL-time.Minute)) {
		t.Fatalf("created %+v", c.Row)
	}
	e := f.lastEvent(t, f.a)
	if e.Action != "invitation.create" || e.Outcome != auditevent.OutcomeSuccess || strings.Contains(e.Details, email) || strings.Contains(e.Details, c.Token) {
		t.Errorf("audit = %+v", e)
	}
	// Listed newest first with its scope; never in another tenant or for a
	// product-scoped member.
	l, err := f.s.List(as(f.a, f.viewerA, authz.Viewer), 1, time.Time{}, "")
	if err != nil || len(l) != 1 || l[0].ID != c.Row.ID || len(l[0].Edges.Products) != 1 {
		t.Fatalf("list = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.a, f.scopedA, authz.Admin, f.prodA), 10, time.Time{}, ""); err != nil || len(l) != 0 {
		t.Errorf("scoped list = %v, %v", l, err)
	}
	if l, err := f.s.List(as(f.b, f.ownerB, authz.Owner), 10, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID == c.Row.ID { // ownerB's own
		t.Errorf("tenant b list = %v, %v", l, err)
	}
	// Accept: the user with that verified email, with the link's token, once.
	other := f.user(t, f.email(), true)
	if _, err := f.s.Accept(ctx, other, c.Token); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("another user's accept: %v", err)
	}
	if _, err := f.s.Accept(ctx, f.user(t, email, false), c.Token); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("unverified email: %v", err)
	}
	u := f.user(t, email, true)
	if _, err := f.s.Accept(ctx, u, rand.Text()); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("unknown token: %v", err)
	}
	m, err := f.s.Accept(ctx, u, c.Token)
	if err != nil || m.TenantID != f.a || m.Role != "support" || m.ScopeAll {
		t.Fatalf("accept = %+v, %v", m, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "invitation.accept" || e.Outcome != auditevent.OutcomeSuccess || *e.ActorID != u || *e.ObjectID != c.Row.ID {
		t.Errorf("accept audit = %+v", e)
	}
	if _, err := f.s.Accept(ctx, u, c.Token); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("used twice: %v", err)
	}
}

func TestAcceptRefusesClosedInvitations(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner := as(f.a, f.ownerA, authz.Owner)
	mk := func() (Created, string) {
		email := f.email()
		c, err := f.s.Create(owner, email, authz.Viewer, all)
		if err != nil {
			t.Fatal(err)
		}
		return c, f.user(t, email, true)
	}
	revoked, ru := mk()
	if _, err := f.s.Revoke(owner, revoked.Row.ID); err != nil {
		t.Fatal(err)
	}
	expired, eu := mk()
	ownerDB, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()
	if _, err := ownerDB.Exec(`UPDATE invitations SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, expired.Row.ID); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ user, token string }{"revoked": {ru, revoked.Token}, "expired": {eu, expired.Token}} {
		if _, err := f.s.Accept(ctx, c.user, c.token); !errors.Is(err, store.ErrInvitation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCreateRefusals(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	tok := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: f.a, Role: authz.Owner, Scope: all})
	for name, c := range map[string]struct {
		ctx   context.Context
		email string
		role  authz.Role
	}{
		"viewer":                     {as(f.a, f.viewerA, authz.Viewer), f.email(), authz.Viewer},
		"viewer, invalid value":      {as(f.a, f.viewerA, authz.Viewer), "nope", "root"}, // 403 before 422
		"admin invites an owner":     {as(f.a, f.adminA, authz.Admin), f.email(), authz.Owner},
		"product-scoped admin":       {as(f.a, f.scopedA, authz.Admin, f.prodA), f.email(), authz.Viewer},
		"API token":                  {tok, f.email(), authz.Viewer},
		"stale principal (is admin)": {as(f.a, f.adminA, authz.Owner), f.email(), authz.Owner},
		"another tenant's member":    {as(f.a, f.ownerB, authz.Owner), f.email(), authz.Viewer},
	} {
		if _, err := f.s.Create(c.ctx, c.email, c.role, all); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e := f.lastEvent(t, f.a); e.Action != "invitation.create" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied audit = %+v", e)
	}
	for name, c := range map[string]struct {
		email string
		role  authz.Role
		scope authz.Scope
		field string
	}{
		"no @":                     {"nope", authz.Viewer, all, "/email"},
		"space":                    {"a b@example.com", authz.Viewer, all, "/email"},
		"bidi override":            {"a‮@example.com", authz.Viewer, all, "/email"},
		"too long":                 {strings.Repeat("a", 320) + "@x", authz.Viewer, all, "/email"},
		"unknown role":             {f.email(), "root", all, "/role"},
		"sdk":                      {f.email(), authz.SDK, all, "/role"},
		"empty scope":              {f.email(), authz.Viewer, authz.Scope{}, "/product_ids"},
		"malformed product":        {f.email(), authz.Viewer, authz.Scope{Products: []string{""}}, "/product_ids"},
		"repeated product":         {f.email(), authz.Viewer, authz.Scope{Products: []string{f.prodA, f.prodA}}, "/product_ids"},
		"another tenant's product": {f.email(), authz.Viewer, authz.Scope{Products: []string{f.prodB}}, "/product_ids"},
		"unknown product":          {f.email(), authz.Viewer, authz.Scope{Products: []string{ids.Product()}}, "/product_ids"},
	} {
		_, err := f.s.Create(owner, c.email, c.role, c.scope)
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != c.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRevoke(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	ownerInv, err := f.s.Create(owner, f.email(), authz.Owner, all)
	if err != nil {
		t.Fatal(err)
	}
	viewerInv, err := f.s.Create(owner, f.email(), authz.Viewer, all)
	if err != nil {
		t.Fatal(err)
	}
	bInv, err := f.s.Create(as(f.b, f.ownerB, authz.Owner), f.email(), authz.Viewer, all)
	if err != nil {
		t.Fatal(err)
	}
	// Missing, hidden and closed: the same not-found, before any rights check.
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {owner, ids.Invitation()},
		"malformed":        {owner, "x"},
		"another tenant's": {owner, bInv.Row.ID},
		"scoped caller":    {as(f.a, f.scopedA, authz.Admin, f.prodA), viewerInv.Row.ID},
		"viewer, missing":  {as(f.a, f.viewerA, authz.Viewer), ids.Invitation()},
	} {
		if _, err := f.s.Revoke(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Visible, but the role can't take it back.
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"viewer":                  {as(f.a, f.viewerA, authz.Viewer), viewerInv.Row.ID},
		"admin, owner invitation": {as(f.a, f.adminA, authz.Admin), ownerInv.Row.ID},
		"stale principal":         {as(f.a, f.adminA, authz.Owner), ownerInv.Row.ID},
	} {
		if _, err := f.s.Revoke(c.ctx, c.id); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r, err := f.s.Revoke(as(f.a, f.adminA, authz.Admin), viewerInv.Row.ID)
	if err != nil || r.RevokedAt == nil {
		t.Fatalf("revoke = %+v, %v", r, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "invitation.revoke" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != r.ID {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.s.Revoke(owner, viewerInv.Row.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked twice: %v", err)
	}
	// An accepted invitation can't be revoked (remove the member instead).
	email := f.email()
	acc, err := f.s.Create(owner, email, authz.Viewer, all)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Accept(context.Background(), f.user(t, email, true), acc.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Revoke(owner, acc.Row.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke accepted: %v", err)
	}
}
