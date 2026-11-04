package apitokens

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/apitoken"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	entapitoken "licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db              *store.DB
	s               Service
	a, b            string // tenants
	prodA           string
	ownerA, ownerB  string
	adminA, viewerA string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := fixture{db: d, s: Service{DB: d}}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		p, err := tx.Product.Create().SetTenantID(f.a).SetSlug("db").SetName("DB").Save(ctx)
		f.prodA = p.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.ownerA = f.join(t, f.a, invitation.RoleOwner, "")
	f.ownerB = f.join(t, f.b, invitation.RoleOwner, "")
	f.adminA = f.join(t, f.a, invitation.RoleAdmin, f.ownerA)
	f.viewerA = f.join(t, f.a, invitation.RoleViewer, f.ownerA)
	return f
}

// join creates a user and makes them a member through an invitation (the
// real path): by the platform for the first owner, else by inviter.
func (f fixture) join(t *testing.T, tenant string, role invitation.Role, inviter string) string {
	t.Helper()
	ctx := context.Background()
	email := strings.ToLower(ids.New("u")[2:14]) + "@example.com"
	tok := rand.Text()
	create := func(tx *ent.Tx) error {
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(email).SetRole(role).SetScopeAll(true).
			SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour))
		if inviter != "" {
			c.SetInvitedBy(inviter)
		}
		_, err := c.Save(ctx)
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
	if _, err := f.db.AcceptInvitation(ctx, tok, uid, func(*ent.Tx, *ent.Membership) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return uid
}

func (f fixture) as(tenant, user string, role authz.Role) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: user, TenantID: tenant, Role: role, Scope: authz.Scope{All: true}})
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

var all = authz.Scope{All: true}

func TestCreateAndAuthenticate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c, err := f.s.Create(f.as(f.a, f.ownerA, authz.Owner), "CI", authz.SDK, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	if apitoken.Check(c.Token) != nil || c.Row.ExpiresAt.Before(time.Now().Add(DefaultTTL-time.Minute)) {
		t.Errorf("created %+v", c.Row)
	}
	e := f.lastEvent(t, f.a)
	if e.Action != "api_token.create" || e.Outcome != auditevent.OutcomeSuccess || strings.Contains(e.Details, c.Token) || !strings.Contains(e.Details, `"role":"sdk"`) {
		t.Errorf("audit = %+v", e)
	}
	p, err := f.s.Authenticate(ctx, f.a, c.Token)
	if err != nil || p.Kind != authz.Token || p.ID != c.Row.ID || p.Role != authz.SDK || !p.Scope.All || p.TenantID != f.a {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}
	// Use is recorded, at most once a minute.
	used := func() *time.Time {
		var r *ent.APIToken
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error { var err error; r, err = tx.APIToken.Get(ctx, c.Row.ID); return err }); err != nil {
			t.Fatal(err)
		}
		return r.LastUsedAt
	}
	first := used()
	if first == nil {
		t.Fatal("use not recorded")
	}
	if _, err := f.s.Authenticate(ctx, f.a, c.Token); err != nil {
		t.Fatal(err)
	}
	if second := used(); !second.Equal(*first) {
		t.Errorf("use recorded twice within a minute: %v %v", first, second)
	}
}

// Every way a token can be invalid gives the same error.
func TestAuthenticateRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mk := func(tenant, owner string) Created {
		c, err := f.s.Create(f.as(tenant, owner, authz.Owner), "CI", authz.SDK, all, 0)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	other := mk(f.b, f.ownerB)
	revoked := mk(f.a, f.ownerA)
	if _, err := f.s.Revoke(f.as(f.a, f.ownerA, authz.Owner), revoked.Row.ID); err != nil {
		t.Fatal(err)
	}
	expired := mk(f.a, f.ownerA)
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.Exec(`UPDATE api_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, expired.Row.ID); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ tenant, token string }{
		"malformed":        {f.a, "lf_live_nope"},
		"unknown":          {f.a, apitoken.New()},
		"another tenant's": {f.a, other.Token},
		"revoked":          {f.a, revoked.Token},
		"expired":          {f.a, expired.Token},
		"bad tenant ID":    {"tnt_x", other.Token},
		"unknown tenant":   {ids.Tenant(), other.Token},
	} {
		if _, err := f.s.Authenticate(ctx, c.tenant, c.token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCreateRefusals(t *testing.T) {
	f := setup(t)
	tokenCtx := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: f.a, Role: authz.Owner, Scope: all})
	for name, c := range map[string]struct {
		ctx     context.Context
		role    authz.Role
		ttl     time.Duration
		want    error
		outcome auditevent.Outcome
	}{
		"viewer":            {f.as(f.a, f.viewerA, authz.Viewer), authz.SDK, 0, authz.ErrDenied, auditevent.OutcomeDenied},
		"admin owner token": {f.as(f.a, f.adminA, authz.Admin), authz.Owner, 0, authz.ErrDenied, auditevent.OutcomeDenied},
		"token creates":     {tokenCtx, authz.SDK, 0, authz.ErrDenied, auditevent.OutcomeDenied},
		"over a year":       {f.as(f.a, f.ownerA, authz.Owner), authz.SDK, MaxTTL + time.Hour, ErrInvalid, auditevent.OutcomeFailure},
	} {
		if _, err := f.s.Create(c.ctx, "CI", c.role, all, c.ttl); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
			continue
		}
		if e := f.lastEvent(t, f.a); e.Action != "api_token.create" || e.Outcome != c.outcome {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
}

func TestScopedToken(t *testing.T) {
	f := setup(t)
	c, err := f.s.Create(f.as(f.a, f.ownerA, authz.Owner), "support bot", authz.Support, authz.Scope{Products: []string{f.prodA}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.Authenticate(context.Background(), f.a, c.Token)
	if err != nil || p.Scope.All || len(p.Scope.Products) != 1 || p.Scope.Products[0] != f.prodA {
		t.Errorf("scope = %+v, %v", p.Scope, err)
	}
}

func TestRevoke(t *testing.T) {
	f := setup(t)
	owner := f.as(f.a, f.ownerA, authz.Owner)
	ownerTok, err := f.s.Create(owner, "root", authz.Owner, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	// An admin can't revoke an owner token (couldn't have given that role).
	if _, err := f.s.Revoke(f.as(f.a, f.adminA, authz.Admin), ownerTok.Row.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("admin revokes owner token: %v", err)
	}
	if _, err := f.s.Revoke(owner, ownerTok.Row.ID); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "api_token.revoke" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != ownerTok.Row.ID {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.s.Revoke(owner, ownerTok.Row.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revoke: %v", err)
	}
	// Another tenant's token is not found, and malformed IDs too.
	b, err := f.s.Create(f.as(f.b, f.ownerB, authz.Owner), "CI", authz.SDK, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{b.Row.ID, "tok_\x00"} {
		if _, err := f.s.Revoke(owner, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoke %q: %v", id, err)
		}
	}
	var n int
	if err := f.db.WithTenant(context.Background(), f.b, func(tx *ent.Tx) error {
		var err error
		n, err = tx.APIToken.Query().Where(entapitoken.ID(b.Row.ID), entapitoken.RevokedAtIsNil()).Count(context.Background())
		return err
	}); err != nil || n != 1 {
		t.Errorf("tenant B's token was revoked: %d %v", n, err)
	}
}

func TestCreateInputRefusals(t *testing.T) {
	f := setup(t)
	owner := f.as(f.a, f.ownerA, authz.Owner)
	var prodB string
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(f.b).SetSlug("db").SetName("DB").Save(context.Background())
		prodB = p.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		name     string
		ttl      time.Duration
		products []string
	}{
		"blank name":               {"   ", 0, nil},
		"NUL in name":              {"a\x00b", 0, nil},
		"invalid UTF-8":            {"\xff", 0, nil},
		"name too long":            {strings.Repeat("x", 201), 0, nil},
		"zero-width only":          {"\u200b\u200b", 0, nil},
		"bidi override":            {"ok\u202Eevil", 0, nil},
		"line separator":           {"a\u2028b", 0, nil},
		"lifetime under 1m":        {"CI", time.Second, nil},
		"malformed product":        {"CI", 0, []string{"prd_x"}},
		"duplicate products":       {"CI", 0, []string{f.prodA, f.prodA}},
		"another tenant's product": {"CI", 0, []string{prodB}},
	} {
		scope := all
		if c.products != nil {
			scope = authz.Scope{Products: c.products}
		}
		if _, err := f.s.Create(owner, c.name, authz.Support, scope, c.ttl); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
			continue
		}
		if e := f.lastEvent(t, f.a); e.Action != "api_token.create" || e.Outcome != auditevent.OutcomeFailure || e.ObjectID != nil {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
	c, err := f.s.Create(owner, "longest", authz.SDK, all, MaxTTL)
	if err != nil {
		t.Fatalf("MaxTTL refused: %v", err)
	}
	if d := time.Until(c.Row.ExpiresAt); d > MaxTTL-skew || d < MaxTTL-skew-time.Minute {
		t.Errorf("MaxTTL token expires in %v, want just under %v", d, MaxTTL-skew)
	}
	// The limit is 200 bytes: 100 two-byte characters fit.
	if _, err := f.s.Create(owner, strings.Repeat("é", 100), authz.SDK, all, 0); err != nil {
		t.Errorf("100 two-byte characters: %v", err)
	}
}

// The database's creator_is_member check backs a stale principal: the
// context says owner, the membership says viewer (or there is none).
func TestCreateWithStalePrincipal(t *testing.T) {
	f := setup(t)
	outsider := f.join(t, f.b, invitation.RoleViewer, f.ownerB) // member of B only
	for name, user := range map[string]string{"demoted to viewer": f.viewerA, "not a member": outsider} {
		if _, err := f.s.Create(f.as(f.a, user, authz.Owner), "CI", authz.SDK, all, 0); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v, want ErrDenied", name, err)
			continue
		}
		if e := f.lastEvent(t, f.a); e.Action != "api_token.create" || e.Outcome != auditevent.OutcomeDenied {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
}

func TestRevokeAuditAndRights(t *testing.T) {
	f := setup(t)
	owner, admin := f.as(f.a, f.ownerA, authz.Owner), f.as(f.a, f.adminA, authz.Admin)
	adminTok, err := f.s.Create(owner, "ops", authz.Admin, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	ownerTok, err := f.s.Create(owner, "root", authz.Owner, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Revoke(admin, ownerTok.Row.ID); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("admin revokes owner token: %v", err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "api_token.revoke" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied revoke audit = %+v", e)
	}
	if _, err := f.s.Revoke(admin, adminTok.Row.ID); err != nil {
		t.Errorf("admin revokes admin token: %v", err)
	}
	bTok, err := f.s.Create(f.as(f.b, f.ownerB, authz.Owner), "CI", authz.SDK, all, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Not-found revokes are audited without naming an object that isn't the
	// tenant's (unknown, or another tenant's token).
	for _, id := range []string{ids.APIToken(), bTok.Row.ID} {
		if _, err := f.s.Revoke(owner, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoke %s: %v", id, err)
		}
		if e := f.lastEvent(t, f.a); e.Action != "api_token.revoke" || e.Outcome != auditevent.OutcomeFailure || e.ObjectID != nil {
			t.Errorf("not-found revoke audit = %+v", e)
		}
	}
	// Without token:write, existing and unknown IDs look the same.
	viewer := f.as(f.a, f.viewerA, authz.Viewer)
	for _, id := range []string{ownerTok.Row.ID, ids.APIToken()} {
		if _, err := f.s.Revoke(viewer, id); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("viewer revoke %s: %v, want ErrDenied", id, err)
		}
	}
}

func TestList(t *testing.T) {
	f := setup(t)
	owner := f.as(f.a, f.ownerA, authz.Owner)
	var made []string
	for range 3 {
		c, err := f.s.Create(owner, "CI", authz.Viewer, all, 0)
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, c.Row.ID)
	}
	if _, err := f.s.Create(f.as(f.b, f.ownerB, authz.Owner), "other", authz.Viewer, all, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Revoke(owner, made[0]); err != nil {
		t.Fatal(err)
	}
	// Newest first, two pages, revoked included, never another tenant's.
	viewer := f.as(f.a, f.viewerA, authz.Viewer)
	p1, err := f.s.List(viewer, 2, time.Time{}, "")
	if err != nil || len(p1) != 2 || p1[0].ID != made[2] || p1[1].ID != made[1] {
		t.Fatalf("page 1 = %v, %v", p1, err)
	}
	p2, err := f.s.List(viewer, 2, p1[1].CreatedAt, p1[1].ID)
	if err != nil || len(p2) != 1 || p2[0].ID != made[0] || p2[0].RevokedAt == nil {
		t.Fatalf("page 2 = %v, %v", p2, err)
	}
	// Tokens are tenant-wide: a product-scoped principal sees none.
	scoped := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: f.viewerA, TenantID: f.a, Role: authz.Viewer, Scope: authz.Scope{Products: []string{f.prodA}}})
	if rows, err := f.s.List(scoped, 10, time.Time{}, ""); err != nil || len(rows) != 0 {
		t.Errorf("scoped list: %v, %v", rows, err)
	}
	sdk := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.APIToken(), TenantID: f.a, Role: authz.SDK, Scope: all})
	for name, ctx := range map[string]context.Context{"no principal": context.Background(), "sdk": sdk} {
		if _, err := f.s.List(ctx, 10, time.Time{}, ""); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
