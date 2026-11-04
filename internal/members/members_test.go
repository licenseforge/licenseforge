package members

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db           *store.DB
	s            Service
	a, b         string // tenants
	prodA, prodB string // prodB is tenant b's
	// users; mem holds their membership IDs
	ownerA, owner2A, adminA, viewerA, scopedA, ownerB string
	mem                                               map[string]string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := &fixture{db: d, s: Service{DB: d}, mem: map[string]string{}}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		for tenant, id := range map[string]*string{f.a: &f.prodA, f.b: &f.prodB} {
			pr, err := tx.Product.Create().SetTenantID(tenant).SetSlug("db").SetName("DB").Save(ctx)
			if err != nil {
				return err
			}
			*id = pr.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.ownerA = f.Join(t, f.a, invitation.RoleOwner, "")
	f.ownerB = f.Join(t, f.b, invitation.RoleOwner, "")
	f.owner2A = f.Join(t, f.a, invitation.RoleOwner, f.ownerA)
	f.adminA = f.Join(t, f.a, invitation.RoleAdmin, f.ownerA)
	f.viewerA = f.Join(t, f.a, invitation.RoleViewer, f.ownerA)
	f.scopedA = f.Join(t, f.a, invitation.RoleAdmin, f.ownerA, f.prodA)
	return f
}

// Join creates a user and makes them a member through an invitation (the
// real path): by the platform for the first owner, else by inviter.
func (f *fixture) Join(t *testing.T, tenant string, role invitation.Role, inviter string, products ...string) string {
	t.Helper()
	ctx := context.Background()
	email := strings.ToLower(ids.New("u")[2:14]) + "@example.com"
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
	var uid string
	if err := f.db.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(ctx)
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	m, err := f.db.AcceptInvitation(ctx, tok, uid, func(*ent.Tx, *ent.Membership) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.mem[uid] = m.ID
	return uid
}

// as acts in tenant as user with role (every product unless products).
func as(tenant, user string, role authz.Role, products ...string) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: user, TenantID: tenant, Role: role,
		Scope: authz.Scope{All: len(products) == 0, Products: products}})
}

func (f *fixture) member(t *testing.T, tenant, id string) *ent.Membership {
	t.Helper()
	var m *ent.Membership
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		m, err = tx.Membership.Query().Where(membership.ID(id)).WithProducts().Only(context.Background())
		if ent.IsNotFound(err) {
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return m
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

func role(r authz.Role) *authz.Role { return &r }

func TestList(t *testing.T) {
	f := setup(t)
	ms, err := f.s.List(as(f.a, f.viewerA, authz.Viewer), 3, time.Time{}, "")
	if err != nil || len(ms) != 3 || ms[0].ID != f.mem[f.scopedA] || ms[0].Edges.User == nil || ms[0].Edges.User.Email == nil ||
		len(ms[0].Edges.Products) != 1 {
		t.Fatalf("page 1 = %v, %v", ms, err)
	}
	rest, err := f.s.List(as(f.a, f.viewerA, authz.Viewer), 10, ms[2].CreatedAt, ms[2].ID)
	if err != nil || len(rest) != 2 || rest[1].ID != f.mem[f.ownerA] {
		t.Fatalf("page 2 = %v, %v", rest, err)
	}
	// Tenant-wide: a product-scoped member sees none; nobody sees another tenant's.
	if ms, err := f.s.List(as(f.a, f.scopedA, authz.Admin, f.prodA), 10, time.Time{}, ""); err != nil || len(ms) != 0 {
		t.Errorf("scoped: %v, %v", ms, err)
	}
	if ms, err := f.s.List(as(f.b, f.ownerB, authz.Owner), 10, time.Time{}, ""); err != nil || len(ms) != 1 {
		t.Errorf("tenant b: %v, %v", ms, err)
	}
}

func TestUpdate(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	m, err := f.s.Update(owner, f.mem[f.viewerA], Change{Role: role(authz.Manager), Scope: &authz.Scope{Products: []string{f.prodA}}})
	if err != nil || m.Role != membership.RoleManager || m.ScopeAll || len(m.Edges.Products) != 1 {
		t.Fatalf("update = %+v, %v", m, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "member.update" || e.Outcome != auditevent.OutcomeSuccess || e.ObjectID == nil || *e.ObjectID != m.ID {
		t.Errorf("audit = %+v", e)
	}
	// Back to every product; role unchanged.
	if m, err = f.s.Update(owner, m.ID, Change{Scope: &authz.Scope{All: true}}); err != nil || !m.ScopeAll || len(m.Edges.Products) != 0 || m.Role != membership.RoleManager {
		t.Fatalf("all products = %+v, %v", m, err)
	}
	// Hidden and missing: the same not-found, also for another tenant's member
	// and for a product-scoped admin.
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {owner, ids.Membership()},
		"malformed":        {owner, "x"},
		"another tenant's": {owner, f.mem[f.ownerB]},
		"scoped caller":    {as(f.a, f.scopedA, authz.Admin, f.prodA), f.mem[f.viewerA]},
	} {
		if _, err := f.s.Update(c.ctx, c.id, Change{Role: role(authz.Viewer)}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	admin := as(f.a, f.adminA, authz.Admin)
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
		ch  Change
	}{
		"escalate to owner":     {admin, f.mem[f.viewerA], Change{Role: role(authz.Owner)}},
		"change an owner":       {admin, f.mem[f.owner2A], Change{Role: role(authz.Viewer)}},
		"self to owner":         {admin, f.mem[f.adminA], Change{Role: role(authz.Owner)}},
		"viewer changes anyone": {as(f.a, f.viewerA, authz.Viewer), f.mem[f.adminA], Change{Role: role(authz.Viewer)}},
		"viewer, invalid value": {as(f.a, f.viewerA, authz.Viewer), f.mem[f.adminA], Change{Role: role("root")}}, // 403 before 422
		"token caller":          {authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: f.a, Role: authz.Owner, Scope: authz.Scope{All: true}}), f.mem[f.viewerA], Change{Role: role(authz.Admin)}},
	} {
		if _, err := f.s.Update(c.ctx, c.id, c.ch); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e := f.lastEvent(t, f.a); e.Action != "member.update" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied audit = %+v", e)
	}
	for name, c := range map[string]struct {
		ch    Change
		field string
	}{
		"unknown role":             {Change{Role: role("root")}, "/role"},
		"sdk":                      {Change{Role: role(authz.SDK)}, "/role"},
		"empty scope":              {Change{Scope: &authz.Scope{}}, "/product_ids"},
		"malformed product":        {Change{Scope: &authz.Scope{Products: []string{"prd_x"}}}, "/product_ids"},
		"repeated product":         {Change{Scope: &authz.Scope{Products: []string{f.prodA, f.prodA}}}, "/product_ids"},
		"another tenant's product": {Change{Scope: &authz.Scope{Products: []string{f.prodB}}}, "/product_ids"},
		"unknown product":          {Change{Scope: &authz.Scope{Products: []string{ids.Product()}}}, "/product_ids"},
	} {
		_, err := f.s.Update(owner, f.mem[f.viewerA], c.ch)
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != c.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if m := f.member(t, f.a, f.mem[f.viewerA]); m.Role != membership.RoleManager || !m.ScopeAll {
		t.Errorf("refused updates changed the member: %+v", m)
	}
}

func TestLastOwner(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	if _, err := f.s.Update(owner, f.mem[f.owner2A], Change{Role: role(authz.Admin)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Update(owner, f.mem[f.ownerA], Change{Role: role(authz.Admin)}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("demote last owner: %v", err)
	}
	if _, err := f.s.Remove(owner, f.mem[f.ownerA], false); !errors.Is(err, ErrLastOwner) {
		t.Errorf("remove last owner: %v", err)
	}
	// Scope changes keep an owner an owner.
	if _, err := f.s.Update(owner, f.mem[f.ownerA], Change{Scope: &authz.Scope{All: true}}); err != nil {
		t.Errorf("owner scope change: %v", err)
	}
}

// Two owners demoting each other at once can't leave the tenant without one.
func TestLastOwnerConcurrent(t *testing.T) {
	f := setup(t)
	for range 5 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		pairs := [][2]string{{f.ownerA, f.owner2A}, {f.owner2A, f.ownerA}}
		for i, p := range pairs {
			wg.Go(func() {
				_, errs[i] = f.s.Update(as(f.a, p[0], authz.Owner), f.mem[p[1]], Change{Role: role(authz.Admin)})
			})
		}
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), ErrLastOwner) {
			t.Fatalf("want one success and one ErrLastOwner: %v", errs)
		}
		// Restore: the remaining owner promotes the other back.
		promoter := f.ownerA
		if errs[1] == nil {
			promoter = f.owner2A
		}
		other := f.ownerA
		if promoter == f.ownerA {
			other = f.owner2A
		}
		if _, err := f.s.Update(as(f.a, promoter, authz.Owner), f.mem[other], Change{Role: role(authz.Owner)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemove(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tokens := apitokens.Service{DB: f.db}
	adminTok, err := tokens.Create(as(f.a, f.adminA, authz.Admin), "CI", authz.Viewer, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	keptTok, err := tokens.Create(as(f.a, f.owner2A, authz.Owner), "kept", authz.Viewer, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	owner := as(f.a, f.ownerA, authz.Owner)
	// Rights first: an admin can't remove an owner; a viewer nobody.
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], true); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin removes owner: %v", err)
	}
	if _, err := f.s.Remove(as(f.a, f.viewerA, authz.Viewer), f.mem[f.adminA], true); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer removes admin: %v", err)
	}
	for name, id := range map[string]string{"missing": ids.Membership(), "another tenant's": f.mem[f.ownerB]} {
		if _, err := f.s.Remove(owner, id, true); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Removal revokes the member's tokens by default, each audited.
	n, err := f.s.Remove(owner, f.mem[f.adminA], true)
	if err != nil || n != 1 {
		t.Fatalf("remove = %d, %v", n, err)
	}
	if f.member(t, f.a, f.mem[f.adminA]) != nil {
		t.Error("membership still there")
	}
	if e := f.lastEvent(t, f.a); e.Action != "member.remove" || e.Outcome != auditevent.OutcomeSuccess || !strings.Contains(e.Details, `"tokens_revoked":1`) {
		t.Errorf("audit = %+v", e)
	}
	if _, err := tokens.Authenticate(ctx, f.a, adminTok.Token); !errors.Is(err, apitokens.ErrUnauthenticated) {
		t.Errorf("removed member's token still works: %v", err)
	}
	// Keeping tokens is explicit.
	if n, err := f.s.Remove(owner, f.mem[f.owner2A], false); err != nil || n != 0 {
		t.Fatalf("remove keeping tokens = %d, %v", n, err)
	}
	if _, err := tokens.Authenticate(ctx, f.a, keptTok.Token); err != nil {
		t.Errorf("kept token: %v", err)
	}
	// Already removed: not found.
	if _, err := f.s.Remove(owner, f.mem[f.adminA], true); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed twice: %v", err)
	}
}

// A member holding tokens above the remover's role can't be removed with
// them: nothing changes (no partial revocation).
func TestRemoveRefusesTokensAboveRemover(t *testing.T) {
	f := setup(t)
	tokens := apitokens.Service{DB: f.db}
	ownerTok, err := tokens.Create(as(f.a, f.owner2A, authz.Owner), "CI", authz.Owner, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Update(as(f.a, f.ownerA, authz.Owner), f.mem[f.owner2A], Change{Role: role(authz.Admin)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], true); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin revokes an owner token: %v", err)
	}
	if f.member(t, f.a, f.mem[f.owner2A]) == nil {
		t.Error("member removed although refused")
	}
	if _, err := tokens.Authenticate(context.Background(), f.a, ownerTok.Token); err != nil {
		t.Errorf("token revoked although refused: %v", err)
	}
}
