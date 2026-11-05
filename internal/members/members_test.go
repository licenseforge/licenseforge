package members

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/invitations"
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
	m, _, err := f.s.Update(owner, f.mem[f.viewerA], Change{Role: role(authz.Manager), Scope: &authz.Scope{Products: []string{f.prodA}}}, Revoke{Tokens: true, Invitations: true})
	if err != nil || m.Role != membership.RoleManager || m.ScopeAll || len(m.Edges.Products) != 1 {
		t.Fatalf("update = %+v, %v", m, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "member.update" || e.Outcome != auditevent.OutcomeSuccess || e.ObjectID == nil || *e.ObjectID != m.ID {
		t.Errorf("audit = %+v", e)
	}
	// Back to every product; role unchanged.
	if m, _, err = f.s.Update(owner, m.ID, Change{Scope: &authz.Scope{All: true}}, Revoke{Tokens: true, Invitations: true}); err != nil || !m.ScopeAll || len(m.Edges.Products) != 0 || m.Role != membership.RoleManager {
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
		if _, _, err := f.s.Update(c.ctx, c.id, Change{Role: role(authz.Viewer)}, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrNotFound) {
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
		if _, _, err := f.s.Update(c.ctx, c.id, c.ch, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
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
		_, _, err := f.s.Update(owner, f.mem[f.viewerA], c.ch, Revoke{Tokens: true, Invitations: true})
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
	if _, _, err := f.s.Update(owner, f.mem[f.owner2A], Change{Role: role(authz.Admin)}, Revoke{Tokens: true, Invitations: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Update(owner, f.mem[f.ownerA], Change{Role: role(authz.Admin)}, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("demote last owner: %v", err)
	}
	if _, err := f.s.Remove(owner, f.mem[f.ownerA], Revoke{}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("remove last owner: %v", err)
	}
	// Scope changes keep an owner an owner.
	if _, _, err := f.s.Update(owner, f.mem[f.ownerA], Change{Scope: &authz.Scope{All: true}}, Revoke{Tokens: true, Invitations: true}); err != nil {
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
				_, _, errs[i] = f.s.Update(as(f.a, p[0], authz.Owner), f.mem[p[1]], Change{Role: role(authz.Admin)}, Revoke{Tokens: true, Invitations: true})
			})
		}
		wg.Wait()
		// The loser waited on the owners' lock: it finds itself demoted
		// (stale principal) or the other the last owner.
		if loser := errors.Join(errs...); (errs[0] == nil) == (errs[1] == nil) || !errors.Is(loser, ErrLastOwner) && !errors.Is(loser, authz.ErrDenied) {
			t.Fatalf("want one success and one refusal: %v", errs)
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
		if _, _, err := f.s.Update(as(f.a, promoter, authz.Owner), f.mem[other], Change{Role: role(authz.Owner)}, Revoke{Tokens: true, Invitations: true}); err != nil {
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
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin removes owner: %v", err)
	}
	if _, err := f.s.Remove(as(f.a, f.viewerA, authz.Viewer), f.mem[f.adminA], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer removes admin: %v", err)
	}
	for name, id := range map[string]string{"missing": ids.Membership(), "another tenant's": f.mem[f.ownerB]} {
		if _, err := f.s.Remove(owner, id, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Removal revokes the member's tokens by default, each audited.
	n, err := f.s.Remove(owner, f.mem[f.adminA], Revoke{Tokens: true, Invitations: true})
	if err != nil || len(n.Tokens) != 1 || n.Tokens[0] != adminTok.Row.ID {
		t.Fatalf("remove = %v, %v", n, err)
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
	if n, err := f.s.Remove(owner, f.mem[f.owner2A], Revoke{}); err != nil || len(n.Tokens) != 0 {
		t.Fatalf("remove keeping tokens = %v, %v", n, err)
	}
	if _, err := tokens.Authenticate(ctx, f.a, keptTok.Token); err != nil {
		t.Errorf("kept token: %v", err)
	}
	// Already removed: not found.
	if _, err := f.s.Remove(owner, f.mem[f.adminA], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrNotFound) {
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
	if _, _, err := f.s.Update(as(f.a, f.ownerA, authz.Owner), f.mem[f.owner2A], Change{Role: role(authz.Admin)}, Revoke{}); err != nil { // keeps the owner token
		t.Fatal(err)
	}
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin revokes an owner token: %v", err)
	}
	if f.member(t, f.a, f.mem[f.owner2A]) == nil {
		t.Error("member removed although refused")
	}
	if _, err := tokens.Authenticate(context.Background(), f.a, ownerTok.Token); err != nil {
		t.Errorf("token revoked although refused: %v", err)
	}
	// An expired token is no access: it doesn't block the removal.
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.Exec(`UPDATE api_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, ownerTok.Row.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], Revoke{Tokens: true, Invitations: true}); err != nil || len(n.Tokens) != 0 {
		t.Errorf("removal with only an expired token above the remover: %v, %v", n, err)
	}
}

func (f *fixture) tokenActive(t *testing.T, tok string) bool {
	t.Helper()
	_, err := apitokens.Service{DB: f.db}.Authenticate(context.Background(), f.a, tok)
	if err != nil && !errors.Is(err, apitokens.ErrUnauthenticated) {
		t.Fatal(err)
	}
	return err == nil
}

// ADR-0035: a demotion or narrower scope revokes the member's tokens the new
// grant wouldn't allow, unless the caller opts out.
func TestDemotionCapsTokens(t *testing.T) {
	f := setup(t)
	tokens := apitokens.Service{DB: f.db}
	admin := as(f.a, f.adminA, authz.Admin)
	mk := func(r authz.Role, scope authz.Scope) string {
		c, err := tokens.Create(admin, "CI", r, scope, 0)
		if err != nil {
			t.Fatal(err)
		}
		return c.Token
	}
	allP, onlyA := authz.Scope{All: true}, authz.Scope{Products: []string{f.prodA}}
	adminTok, viewerAll, viewerA, sdkAll, sdkA := mk(authz.Admin, allP), mk(authz.Viewer, allP), mk(authz.Viewer, onlyA), mk(authz.SDK, allP), mk(authz.SDK, onlyA)
	other := f.product(t, f.a)
	viewerOther := mk(authz.Viewer, authz.Scope{Products: []string{other}})
	owner := as(f.a, f.ownerA, authz.Owner)
	// Opting out keeps everything.
	if _, _, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Manager)}, Revoke{}); err != nil {
		t.Fatal(err)
	}
	if !f.tokenActive(t, adminTok) {
		t.Fatal("opt-out revoked a token")
	}
	if _, _, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Admin)}, Revoke{}); err != nil {
		t.Fatal(err)
	}
	// Role: the admin token goes; viewer and sdk tokens stay.
	if _, _, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Manager)}, Revoke{Tokens: true, Invitations: true}); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent(t, f.a); !strings.Contains(e.Details, `"tokens_revoked":1`) || !strings.Contains(e.Details, `"from_scope_all":true`) {
		t.Errorf("audit = %s", e.Details)
	}
	for tok, want := range map[string]bool{adminTok: false, viewerAll: true, viewerA: true, sdkAll: true, sdkA: true} {
		if f.tokenActive(t, tok) != want {
			t.Errorf("after demotion, token active = %v, want %v", !want, want)
		}
	}
	// A token an earlier change kept stays: only what a change newly
	// excludes is capped (ADR-0035).
	if _, _, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Admin)}, Revoke{}); err != nil {
		t.Fatal(err)
	}
	adminTok2 := mk(authz.Admin, allP)
	if _, revoked, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Manager)}, Revoke{}); err != nil || len(revoked.Tokens) != 0 {
		t.Fatalf("opt-out: %v, %v", revoked, err)
	}
	if _, revoked, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Support)}, Revoke{Tokens: true, Invitations: true}); err != nil || len(revoked.Tokens) != 0 || !f.tokenActive(t, adminTok2) {
		t.Errorf("a later change revoked a token kept earlier: %v, %v", revoked, err)
	}
	if _, _, err := f.s.Update(owner, f.mem[f.adminA], Change{Role: role(authz.Manager)}, Revoke{Tokens: true, Invitations: true}); err != nil {
		t.Fatal(err)
	}
	// Scope: tokens beyond prodA go, and their IDs are returned.
	_, revoked, err := f.s.Update(owner, f.mem[f.adminA], Change{Scope: &onlyA}, Revoke{Tokens: true, Invitations: true})
	if err != nil || len(revoked.Tokens) != 3 {
		t.Fatalf("narrowing revoked %v, %v", revoked, err)
	}
	for tok, want := range map[string]bool{viewerAll: false, viewerA: true, sdkAll: false, sdkA: true, viewerOther: false} {
		if f.tokenActive(t, tok) != want {
			t.Errorf("after narrowing, token active = %v, want %v", !want, want)
		}
	}
}

// A token an earlier demotion kept (revoke_tokens=false) isn't revoked by a
// later one: here an owner token above the member's admin role survives a
// demotion to viewer, which an admin may do. (Capping is all or nothing like
// removal, but with built-in roles a newly excluded token is always one the
// caller may revoke: it was within the member's old grant, which the caller
// may change.)
func TestDemotionKeepsEarlierOptOut(t *testing.T) {
	f := setup(t)
	ownerTok, err := apitokens.Service{DB: f.db}.Create(as(f.a, f.owner2A, authz.Owner), "CI", authz.Owner, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Update(as(f.a, f.ownerA, authz.Owner), f.mem[f.owner2A], Change{Role: role(authz.Admin)}, Revoke{}); err != nil {
		t.Fatal(err)
	}
	_, revoked, err := f.s.Update(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], Change{Role: role(authz.Viewer)}, Revoke{Tokens: true, Invitations: true})
	if err != nil || len(revoked.Tokens) != 0 || !f.tokenActive(t, ownerTok.Token) {
		t.Errorf("later demotion: revoked %v, %v, token active %v", revoked, err, f.tokenActive(t, ownerTok.Token))
	}
}

func TestNullFields(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	ch := Change{Scope: &authz.Scope{Products: []string{f.prodA}}, Null: []string{"all_products"}}
	var inv *InvalidError
	if _, _, err := f.s.Update(owner, f.mem[f.viewerA], ch, Revoke{Tokens: true, Invitations: true}); !errors.As(err, &inv) || inv.Field != "/all_products" {
		t.Errorf("null all_products: %v", err)
	}
	// Rights and lookup come first.
	if _, _, err := f.s.Update(as(f.a, f.viewerA, authz.Viewer), f.mem[f.adminA], ch, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer: %v", err)
	}
	if _, _, err := f.s.Update(owner, ids.Membership(), ch, Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}

func TestSelfRemoval(t *testing.T) {
	f := setup(t)
	if _, err := f.s.Remove(as(f.a, f.viewerA, authz.Viewer), f.mem[f.viewerA], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer leaves (needs member:write): %v", err)
	}
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.adminA], Revoke{Tokens: true, Invitations: true}); err != nil {
		t.Errorf("admin leaves: %v", err)
	}
	if _, err := f.s.Remove(as(f.a, f.owner2A, authz.Owner), f.mem[f.owner2A], Revoke{}); err != nil {
		t.Errorf("owner leaves while another owner remains: %v", err)
	}
	if e := f.lastEvent(t, f.a); !strings.Contains(e.Details, `"revoke_tokens":false`) || !strings.Contains(e.Details, `"tokens_kept":0`) {
		t.Errorf("audit = %s", e.Details)
	}
	if _, err := f.s.Remove(as(f.a, f.ownerA, authz.Owner), f.mem[f.ownerA], Revoke{Tokens: true, Invitations: true}); !errors.Is(err, ErrLastOwner) {
		t.Errorf("last owner leaves: %v", err)
	}
}

// A caller demoted while its request waits on the owners' lock is refused:
// the principal is re-checked in the transaction.
func TestStaleCaller(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	done := make(chan error, 1)
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT id FROM memberships WHERE role = 'owner' ORDER BY id FOR UPDATE`); err != nil {
			return err
		}
		go func() {
			_, _, err := f.s.Update(as(f.a, f.owner2A, authz.Owner), f.mem[f.viewerA], Change{Role: role(authz.Owner)}, Revoke{Tokens: true, Invitations: true})
			done <- err
		}()
		for i := 0; ; i++ { // until the promotion waits on the lock
			var n int
			if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				break
			}
			if i == 100 {
				return errors.New("the promotion never waited")
			}
			time.Sleep(20 * time.Millisecond)
		}
		_, err := tx.ExecContext(ctx, `UPDATE memberships SET role = 'admin' WHERE id = $1`, f.mem[f.owner2A])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, authz.ErrDenied) {
			t.Errorf("stale owner's promotion: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("promotion didn't finish")
	}
	if m := f.member(t, f.a, f.mem[f.viewerA]); m.Role != membership.RoleViewer {
		t.Errorf("promoted by a demoted owner: %s", m.Role)
	}
}

func (f *fixture) product(t *testing.T, tenant string) string {
	t.Helper()
	var id string
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(tenant).SetSlug("p" + strings.ToLower(storetest.Suffix())).SetName("P").Save(context.Background())
		if err == nil {
			id = p.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// store.RecheckPrincipal accepts only a principal equal to the membership.
func TestRecheckPrincipal(t *testing.T) {
	f := setup(t)
	other := f.product(t, f.a)
	user := func(id string, r authz.Role, s authz.Scope) authz.Principal {
		return authz.Principal{Kind: authz.User, ID: id, TenantID: f.a, Role: r, Scope: s}
	}
	for name, c := range map[string]struct {
		p    authz.Principal
		want error
	}{
		"current":         {user(f.scopedA, authz.Admin, authz.Scope{Products: []string{f.prodA}}), nil},
		"other products":  {user(f.scopedA, authz.Admin, authz.Scope{Products: []string{other}}), authz.ErrDenied},
		"more products":   {user(f.scopedA, authz.Admin, authz.Scope{Products: []string{f.prodA, other}}), authz.ErrDenied},
		"all products":    {user(f.scopedA, authz.Admin, authz.Scope{All: true}), authz.ErrDenied},
		"other role":      {user(f.scopedA, authz.Viewer, authz.Scope{Products: []string{f.prodA}}), authz.ErrDenied},
		"not a member":    {user(f.ownerB, authz.Owner, authz.Scope{All: true}), authz.ErrDenied},
		"token principal": {authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: f.a, Role: authz.Admin, Scope: authz.Scope{All: true}}, nil},
	} {
		if err := f.db.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
			return store.RecheckPrincipal(context.Background(), tx, c.p)
		}); !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// invite has inviter send a pending invitation with role r to every product.
func (f *fixture) invite(t *testing.T, inviter string, inviterRole, r authz.Role) string {
	t.Helper()
	c, err := invitations.Service{DB: f.db}.Create(as(f.a, inviter, inviterRole), strings.ToLower(ids.New("i")[2:14])+"@example.com", r, authz.Scope{All: true})
	if err != nil {
		t.Fatal(err)
	}
	return c.Row.ID
}

func (f *fixture) pending(t *testing.T, id string) bool {
	t.Helper()
	var inv *ent.Invitation
	if err := f.db.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		var err error
		inv, err = tx.Invitation.Get(context.Background(), id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return inv.RevokedAt == nil && inv.AcceptedAt == nil
}

var both = Revoke{Tokens: true, Invitations: true}

// ADR-0035 extended to invitations: a change revokes the member's pending
// invitations it newly excludes (the new grant couldn't have sent them);
// one an earlier change kept stays; opting out keeps them.
func TestInvitationsFollowInviter(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	invOwner := f.invite(t, f.owner2A, authz.Owner, authz.Owner)
	invAdmin := f.invite(t, f.owner2A, authz.Owner, authz.Admin)
	invViewer := f.invite(t, f.owner2A, authz.Owner, authz.Viewer)
	// Opting out keeps everything.
	if _, r, err := f.s.Update(owner, f.mem[f.owner2A], Change{Role: role(authz.Admin)}, Revoke{Tokens: true}); err != nil || len(r.Invitations) != 0 || !f.pending(t, invOwner) {
		t.Fatalf("opt-out: %v, %v", r, err)
	}
	// Admin to manager (no member:write): admin and viewer invitations are
	// newly excluded; the owner one was kept by the earlier change.
	_, r, err := f.s.Update(owner, f.mem[f.owner2A], Change{Role: role(authz.Manager)}, both)
	if err != nil || len(r.Invitations) != 2 || f.pending(t, invAdmin) || f.pending(t, invViewer) || !f.pending(t, invOwner) {
		t.Fatalf("demotion: %v, %v", r, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "member.update" || !strings.Contains(e.Details, `"invitations_revoked":2`) {
		t.Errorf("audit = %s", e.Details)
	}
	// Narrowing the scope excludes every invitation (inviting needs every product).
	admin2 := f.Join(t, f.a, invitation.RoleAdmin, f.ownerA)
	inv := f.invite(t, admin2, authz.Admin, authz.Viewer)
	if _, r, err := f.s.Update(owner, f.mem[admin2], Change{Scope: &authz.Scope{Products: []string{f.prodA}}}, both); err != nil || len(r.Invitations) != 1 || f.pending(t, inv) {
		t.Errorf("narrowing: %v, %v", r, err)
	}
	// A role change that keeps inviting rights keeps the invitation.
	admin3 := f.Join(t, f.a, invitation.RoleOwner, f.ownerA)
	kept := f.invite(t, admin3, authz.Owner, authz.Viewer)
	if _, r, err := f.s.Update(owner, f.mem[admin3], Change{Role: role(authz.Admin)}, both); err != nil || len(r.Invitations) != 0 || !f.pending(t, kept) {
		t.Errorf("still allowed: %v, %v", r, err)
	}
}

func TestRemovalRevokesInvitations(t *testing.T) {
	f := setup(t)
	owner := as(f.a, f.ownerA, authz.Owner)
	inv := f.invite(t, f.adminA, authz.Admin, authz.Viewer)
	keptInv := f.invite(t, f.owner2A, authz.Owner, authz.Viewer)
	r, err := f.s.Remove(owner, f.mem[f.adminA], both)
	if err != nil || len(r.Invitations) != 1 || r.Invitations[0] != inv || f.pending(t, inv) {
		t.Fatalf("remove: %v, %v", r, err)
	}
	if _, err := f.s.Remove(owner, f.mem[f.owner2A], Revoke{Tokens: true}); err != nil || !f.pending(t, keptInv) {
		t.Errorf("remove keeping invitations: %v, pending %v", err, f.pending(t, keptInv))
	}
}

// All or nothing: an admin can't remove a member whose pending owner
// invitation it couldn't revoke (sent while the member was an owner).
func TestInvitationRevocationAllOrNothing(t *testing.T) {
	f := setup(t)
	inv := f.invite(t, f.owner2A, authz.Owner, authz.Owner)
	if _, _, err := f.s.Update(as(f.a, f.ownerA, authz.Owner), f.mem[f.owner2A], Change{Role: role(authz.Admin)}, Revoke{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Remove(as(f.a, f.adminA, authz.Admin), f.mem[f.owner2A], both); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin revokes an owner invitation: %v", err)
	}
	if f.member(t, f.a, f.mem[f.owner2A]) == nil || !f.pending(t, inv) {
		t.Error("refused removal changed something")
	}
}

// waitForLockWaiter returns once a backend of the test database waits on a
// lock (at most 2 s).
func waitForLockWaiter(t *testing.T) {
	t.Helper()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	for range 100 {
		var n int
		if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("nothing waited on a lock")
}

func auditLock(ctx context.Context, tx *ent.Tx, tenant string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.audit:' || $1, 0))`, tenant)
	return err
}

// Lock order (owners, memberships, tokens, invitations, audit): a demotion
// that revokes a token and waits on an invitation lock holds no audit lock,
// so the invitation's holder (an acceptance or revocation, which audits
// next) can finish. With the audit lock taken before the invitation lock,
// this deadlocks (40P01).
func TestMemberChangeVsInvitationLock(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := (apitokens.Service{DB: f.db}).Create(as(f.a, f.owner2A, authz.Owner), "CI", authz.Owner, authz.Scope{All: true}, 0); err != nil {
		t.Fatal(err)
	}
	inv := f.invite(t, f.owner2A, authz.Owner, authz.Owner)
	done := make(chan error, 1)
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT id FROM invitations WHERE id = $1 FOR UPDATE`, inv); err != nil {
			return err
		}
		go func() {
			_, _, err := f.s.Update(as(f.a, f.ownerA, authz.Owner), f.mem[f.owner2A], Change{Role: role(authz.Admin)}, both)
			done <- err
		}()
		waitForLockWaiter(t)
		return auditLock(ctx, tx, f.a) // as accept or revoke would next
	}); err != nil {
		t.Fatalf("invitation holder: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("demotion: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("demotion didn't finish")
	}
	if f.pending(t, inv) {
		t.Error("the demotion didn't revoke the owner invitation")
	}
}

// A member revoking their own invitation while being changed: the revoke
// re-checks the member's membership before locking the invitation (the
// member change's order), so it can't hold the invitation while waiting
// for the membership.
func TestOwnInvitationRevokeVsMemberChange(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	inv := f.invite(t, f.adminA, authz.Admin, authz.Viewer)
	done := make(chan error, 1)
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		// As a member change does: the membership, then its invitations.
		if _, err := tx.ExecContext(ctx, `SELECT id FROM memberships WHERE id = $1 FOR UPDATE`, f.mem[f.adminA]); err != nil {
			return err
		}
		go func() {
			_, err := invitations.Service{DB: f.db}.Revoke(as(f.a, f.adminA, authz.Admin), inv)
			done <- err
		}()
		waitForLockWaiter(t)
		_, err := tx.ExecContext(ctx, `SELECT id FROM invitations WHERE id = $1 FOR UPDATE`, inv)
		return err
	}); err != nil {
		t.Fatalf("member change: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoke didn't finish")
	}
}
