package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/membershipproduct"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// identityFixture: two tenants, each with a product and an owner who joined
// through a (platform-created) invitation, like the bootstrap admin will.
type identityFixture struct {
	d                    *DB
	a, b                 string // tenant IDs
	prodA, prodA2, prodB string
	ownerA, ownerB       string            // user IDs
	tokens               map[string]string // invitation ID -> invite link token
}

func newIdentityFixture(t *testing.T) identityFixture {
	t.Helper()
	ctx := context.Background()
	d, err := Open(ctx, testLogins())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := identityFixture{d: d, tokens: map[string]string{}}
	err = d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + strings.ToLower(ids.New("x")[2:12])).SetName("T").Save(ctx)
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		mk := func(tenant, slug string) (string, error) {
			p, err := tx.Product.Create().SetTenantID(tenant).SetSlug(slug).SetName(slug).Save(ctx)
			if err != nil {
				return "", err
			}
			return p.ID, nil
		}
		if f.prodA, err = mk(f.a, "db"); err != nil {
			return err
		}
		if f.prodA2, err = mk(f.a, "cache"); err != nil {
			return err
		}
		if f.prodB, err = mk(f.b, "db"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Bootstrap like production: the platform invites each tenant's first
	// owner, who logs in and accepts on the identity pool.
	for _, o := range []struct {
		tenant, email string
		id            *string
	}{{f.a, "owner-a@example.com", &f.ownerA}, {f.b, "owner-b@example.com", &f.ownerB}} {
		tok := newToken()
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			_, err := tx.Invitation.Create().SetTenantID(o.tenant).SetEmail(o.email).SetRole(invitation.RoleOwner).
				SetScopeAll(true).SetTokenHash(InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour)).Save(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		*o.id = f.newUser(t, o.email, true)
		if _, err := d.AcceptInvitation(ctx, tok, *o.id, noRecord); err != nil {
			t.Fatalf("bootstrap owner of %s: %v", o.tenant, err)
		}
	}
	return f
}

// newToken returns an invite link token (the real format is up to the
// handler; the database only sees its SHA-256).
func newToken() string { return rand.Text() }

// newUser logs a user in (identity pool).
func (f identityFixture) newUser(t *testing.T, email string, verified bool) string {
	t.Helper()
	var id string
	err := f.d.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).
			SetEmail(email).SetEmailVerified(verified).Save(context.Background())
		if err == nil {
			id = u.ID
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type inviteOpts struct {
	email    string
	role     invitation.Role
	products []string // nil: all products
	issuer   string
}

// invite creates an invitation as tenant's owner (tenant pool).
func (f identityFixture) invite(t *testing.T, tenant, inviter string, o inviteOpts) *ent.Invitation {
	t.Helper()
	var inv *ent.Invitation
	err := f.d.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		tok := newToken()
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(o.email).SetRole(o.role).SetScopeAll(o.products == nil).
			SetInvitedBy(inviter).SetTokenHash(InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(7 * 24 * time.Hour))
		if o.issuer != "" {
			c.SetIssuer(o.issuer)
		}
		var err error
		if inv, err = c.Save(context.Background()); err != nil {
			return err
		}
		f.tokens[inv.ID] = tok
		for _, p := range o.products {
			if _, err := tx.InvitationProduct.Create().SetTenantID(tenant).SetInvitationID(inv.ID).SetProductID(p).Save(context.Background()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

type acceptOpts struct {
	token    *string // app.invite_token; default the invitation's token
	tenant   string  // app.tenant_id; default the invitation's
	role     membership.Role
	scopeAll *bool
	products []string
}

// accept writes an acceptance directly, bypassing AcceptInvitation, so tests
// can probe what the database itself allows (wrong role, scope, tenant...):
// membership and products first, then the mark, in one transaction.
func (f identityFixture) accept(inv *ent.Invitation, userID string, o acceptOpts) error {
	ctx := context.Background()
	if o.tenant == "" {
		o.tenant = inv.TenantID
	}
	if o.role == "" {
		o.role = membership.Role(inv.Role)
	}
	scopeAll := inv.ScopeAll
	if o.scopeAll != nil {
		scopeAll = *o.scopeAll
	}
	tok := f.tokens[inv.ID]
	if o.token != nil {
		tok = *o.token
	}
	return f.d.WithIdentity(ctx, o.tenant, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.invite_token', $1, true)`, tok); err != nil {
			return err
		}
		m, err := tx.Membership.Create().SetTenantID(inv.TenantID).SetUserID(userID).SetRole(o.role).
			SetScopeAll(scopeAll).SetInvitationID(inv.ID).Save(ctx)
		if err != nil {
			return err
		}
		for _, p := range o.products {
			if _, err := tx.MembershipProduct.Create().SetTenantID(inv.TenantID).SetMembershipID(m.ID).SetProductID(p).Save(ctx); err != nil {
				return err
			}
		}
		return tx.Invitation.UpdateOneID(inv.ID).SetAcceptedAt(time.Now()).SetAcceptedBy(userID).Exec(ctx)
	})
}

// sees reports whether tenant's pool can read userID (id, email, name only).
func (f identityFixture) sees(t *testing.T, tenant, userID string) bool {
	t.Helper()
	var n int
	err := f.d.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		us, err := tx.User.Query().Where(user.ID(userID)).Select(user.FieldID, user.FieldEmail, user.FieldName).All(context.Background())
		n = len(us)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func TestInvitationAcceptance(t *testing.T) {
	f := newIdentityFixture(t)
	// The invitation is written composed and in another case than the
	// user's (decomposed) address: NFC + case-insensitive match.
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "José@Example.com", role: invitation.RoleViewer})
	u := f.newUser(t, "josé@example.COM", true)
	if f.sees(t, f.a, u) {
		t.Fatal("tenant sees a user before they joined")
	}
	if err := f.accept(inv, u, acceptOpts{}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !f.sees(t, f.a, u) || f.sees(t, f.b, u) {
		t.Error("after joining A: A must see the user, B must not")
	}
	// The tenant pool reads only id, email and name.
	err := f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		_, err := tx.User.Query().Where(user.ID(u)).Only(context.Background()) // all columns, incl. issuer
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("tenant read of users.issuer: %v, want permission denied", err)
	}
}

func TestAcceptanceRefusals(t *testing.T) {
	f := newIdentityFixture(t)
	no := false
	for name, c := range map[string]struct {
		inv      inviteOpts
		email    string
		verified bool
		accept   acceptOpts
		prepare  func(*ent.Invitation)
	}{
		"no token":      {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{token: ptrTo("")}, nil},
		"wrong token":   {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{token: ptrTo("not-the-token")}, nil},
		"other tenant":  {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{tenant: "B"}, nil},
		"higher role":   {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{role: membership.RoleOwner}, nil},
		"wider scope":   {inviteOpts{email: "a@example.com", role: invitation.RoleSupport, products: []string{"A"}}, "a@example.com", true, acceptOpts{scopeAll: ptrTo(true)}, nil},
		"unverified":    {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", false, acceptOpts{}, nil},
		"other email":   {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "b@example.com", true, acceptOpts{}, nil},
		"other issuer":  {inviteOpts{email: "a@example.com", role: invitation.RoleViewer, issuer: "https://corp.example"}, "a@example.com", true, acceptOpts{}, nil},
		"extra product": {inviteOpts{email: "a@example.com", role: invitation.RoleSupport, products: []string{"A"}}, "a@example.com", true, acceptOpts{scopeAll: &no, products: []string{"A2"}}, nil},
		"revoked": {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{}, func(i *ent.Invitation) {
			f.platform(t, `UPDATE invitations SET revoked_at = now() WHERE id = $1`, i.ID)
		}},
		"expired": {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{}, func(i *ent.Invitation) {
			f.owner(t, `UPDATE invitations SET created_at = now() - interval '9 days', expires_at = now() - interval '1 day' WHERE id = $1`, i.ID)
		}},
		"disabled user": {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{}, nil},
		"marked accepted": {inviteOpts{email: "a@example.com", role: invitation.RoleViewer}, "a@example.com", true, acceptOpts{}, func(i *ent.Invitation) {
			f.platform(t, `UPDATE invitations SET accepted_at = now(), accepted_by = $2 WHERE id = $1`, i.ID, f.ownerA)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			for i, p := range c.inv.products {
				c.inv.products[i] = map[string]string{"A": f.prodA, "A2": f.prodA2}[p]
			}
			for i, p := range c.accept.products {
				c.accept.products[i] = map[string]string{"A": f.prodA, "A2": f.prodA2}[p]
			}
			if c.accept.tenant == "B" {
				c.accept.tenant = f.b
			}
			inv := f.invite(t, f.a, f.ownerA, c.inv)
			u := f.newUser(t, c.email, c.verified)
			if name == "disabled user" {
				f.platform(t, `UPDATE users SET disabled_at = now() WHERE id = $1`, u)
			}
			if c.prepare != nil {
				c.prepare(inv)
			}
			if err := f.accept(inv, u, c.accept); err == nil || !strings.Contains(err.Error(), "row-level security") {
				t.Fatalf("accept = %v, want a row-level security refusal", err)
			}
			if f.sees(t, f.a, u) {
				t.Error("the user became visible to the tenant")
			}
		})
	}
}

func ptrTo[T any](v T) *T { return &v }

// platform and owner run raw SQL with the given login (setup for refusals).
func (f identityFixture) platform(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.d.platformDB.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

func (f identityFixture) owner(t *testing.T, q string, args ...any) {
	t.Helper()
	db, err := openPool(env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestInvitationUsedOnce(t *testing.T) {
	f := newIdentityFixture(t)
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "a@example.com", role: invitation.RoleViewer})
	u1, u2 := f.newUser(t, "a@example.com", true), f.newUser(t, "A@example.com", true) // same email, two accounts
	if err := f.accept(inv, u1, acceptOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := f.accept(inv, u2, acceptOpts{}); err == nil {
		t.Error("a second account accepted the same invitation")
	}
}

func TestScopedAcceptance(t *testing.T) {
	f := newIdentityFixture(t)
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "s@example.com", role: invitation.RoleSupport, products: []string{f.prodA}})
	u := f.newUser(t, "s@example.com", true)
	no := false
	if err := f.accept(inv, u, acceptOpts{scopeAll: &no, products: []string{f.prodA}}); err != nil {
		t.Fatalf("scoped accept: %v", err)
	}
	// A membership can't switch to all products while it has product rows.
	err := f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		return tx.Membership.Update().Where(membership.UserID(u)).SetScopeAll(true).Exec(context.Background())
	})
	if err == nil {
		t.Error("scope_all set with product rows present")
	}
	// No product rows on an all-products invitation.
	all := f.invite(t, f.a, f.ownerA, inviteOpts{email: "x@example.com", role: invitation.RoleViewer})
	err = f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		_, err := tx.InvitationProduct.Create().SetTenantID(f.a).SetInvitationID(all.ID).SetProductID(f.prodA).Save(context.Background())
		return err
	})
	if err == nil {
		t.Error("product row on an all-products invitation")
	}
	// Another tenant's product can't be in scope.
	err = f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		scoped := f.invite(t, f.a, f.ownerA, inviteOpts{email: "y@example.com", role: invitation.RoleViewer, products: []string{f.prodA}})
		_, err := tx.InvitationProduct.Create().SetTenantID(f.a).SetInvitationID(scoped.ID).SetProductID(f.prodB).Save(context.Background())
		return err
	})
	if err == nil {
		t.Error("another tenant's product in an invitation's scope")
	}
}

func TestTenantPoolCantAddMembers(t *testing.T) {
	f := newIdentityFixture(t)
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "m@example.com", role: invitation.RoleViewer})
	u := f.newUser(t, "m@example.com", true)
	err := f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		_, err := tx.Membership.Create().SetTenantID(f.a).SetUserID(u).SetRole(membership.RoleViewer).
			SetScopeAll(true).SetInvitationID(inv.ID).Save(context.Background())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("tenant pool insert into memberships: %v, want permission denied", err)
	}
}

func TestInviterMustBeMember(t *testing.T) {
	f := newIdentityFixture(t)
	for name, inviter := range map[string]string{"another tenant's owner": f.ownerB, "no inviter": ""} {
		err := f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
			c := tx.Invitation.Create().SetTenantID(f.a).SetEmail("z@example.com").SetRole(invitation.RoleViewer).SetScopeAll(true).
				SetTokenHash(InvitationTokenHash(newToken())).SetExpiresAt(time.Now().Add(time.Hour))
			if inviter != "" {
				c.SetInvitedBy(inviter)
			}
			_, err := c.Save(context.Background())
			return err
		})
		if err == nil {
			t.Errorf("%s as inviter accepted", name)
		}
	}
}

func TestIdentityMarksOnlyItsOwnAcceptance(t *testing.T) {
	f := newIdentityFixture(t)
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "k@example.com", role: invitation.RoleViewer})
	u := f.newUser(t, "k@example.com", true)
	err := f.d.WithIdentity(context.Background(), f.a, func(tx *ent.Tx) error {
		return tx.Invitation.UpdateOneID(inv.ID).SetAcceptedAt(time.Now()).SetAcceptedBy(u).Exec(context.Background())
	})
	if err == nil {
		t.Error("invitation marked accepted without a membership")
	}
	err = f.d.WithIdentity(context.Background(), f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE invitations SET role = 'owner' WHERE id = $1`, inv.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("identity changed an invitation's role: %v", err)
	}
}

// The identity pool has no access to licensing tables (ADR-0029).
func TestIdentityHasNoLicensingAccess(t *testing.T) {
	f := newIdentityFixture(t)
	for _, table := range []string{"products", "plans", "customers", "licenses", "activations", "signing_keys", "features"} {
		err := f.d.WithIdentity(context.Background(), f.a, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(context.Background(), `SELECT 1 FROM `+table+` LIMIT 1`)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("identity read %s: %v, want permission denied", table, err)
		}
	}
}

func TestMemberRolesMatchAuthz(t *testing.T) {
	for _, r := range []authz.Role{authz.Owner, authz.Admin, authz.Manager, authz.Support, authz.Viewer, authz.SDK} {
		for name, valid := range map[string]error{
			"invitations": invitation.RoleValidator(invitation.Role(r)),
			"memberships": membership.RoleValidator(membership.Role(r)),
		} {
			if (valid == nil) != r.ForMembership() {
				t.Errorf("%s role %q: valid=%v, authz ForMembership=%v", name, r, valid == nil, r.ForMembership())
			}
		}
	}
}

func TestAcceptInvitation(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "s@example.com", role: invitation.RoleSupport, products: []string{f.prodA, f.prodA2}})
	u := f.newUser(t, "s@example.com", true)
	// record runs in the acceptance's transaction: its error undoes the membership.
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], u, func(*ent.Tx, *ent.Membership) error { return context.Canceled }); err == nil || f.sees(t, f.a, u) {
		t.Fatalf("a failed record left the membership: %v", err)
	}
	if _, err := f.d.AcceptInvitation(ctx, "not-the-token", u, noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("wrong token: %v", err)
	}
	m, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], u, noRecord)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != membership.RoleSupport || m.ScopeAll || m.TenantID != f.a {
		t.Errorf("membership = %+v", m)
	}
	var n int
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		var err error
		n, err = tx.MembershipProduct.Query().Where(membershipproduct.MembershipID(m.ID)).Count(ctx)
		return err
	}); err != nil || n != 2 {
		t.Errorf("copied products = %d, %v", n, err)
	}
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], f.newUser(t, "s@example.com", true), noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("second use: %v", err)
	}
}

// A revoke holding the invitation's row lock makes a concurrent accept wait,
// then refuse; it never leaves a membership on a revoked invitation.
func TestAcceptWaitsForConcurrentRevoke(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "r@example.com", role: invitation.RoleViewer})
	u := f.newUser(t, "r@example.com", true)
	locked, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			if err := tx.Invitation.UpdateOneID(inv.ID).SetRevokedAt(time.Now()).Exec(ctx); err != nil {
				return err
			}
			close(locked)
			time.Sleep(500 * time.Millisecond)
			return nil
		})
	}()
	<-locked
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], u, noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("accept during revoke: %v, want ErrInvitation", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.sees(t, f.a, u) {
		t.Error("membership on a revoked invitation")
	}
}

// After acceptance, the identity pool can't re-add a product an admin removed.
func TestScopeCantBeReaddedAfterAcceptance(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "q@example.com", role: invitation.RoleSupport, products: []string{f.prodA, f.prodA2}})
	u := f.newUser(t, "q@example.com", true)
	m, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], u, noRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		_, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID), membershipproduct.ProductID(f.prodA2)).Exec(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err = f.d.WithIdentity(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.invite_token', $1, true)`, f.tokens[inv.ID]); err != nil {
			return err
		}
		_, err := tx.MembershipProduct.Create().SetTenantID(f.a).SetMembershipID(m.ID).SetProductID(f.prodA2).Save(ctx)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("re-added product: %v", err)
	}
}

// The tenant pool creates open invitations and revokes them; nothing else.
func TestTenantPoolInvitationRights(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "w@example.com", role: invitation.RoleViewer})
	tenantExec := func(q string, args ...any) error {
		return f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err })
	}
	for name, q := range map[string]string{
		"pre-accepted": `INSERT INTO invitations (id, tenant_id, email, role, scope_all, invited_by, token_hash, expires_at, created_at, updated_at, accepted_at, accepted_by) VALUES ('` + ids.Invitation() + `', $1, 'p@example.com', 'owner', true, $2, $3, now() + interval '1 day', now(), now(), now(), $2)`,
		"change role":  `UPDATE invitations SET role = 'owner' WHERE tenant_id = $1 AND invited_by = $2 AND token_hash <> $3`,
		"change email": `UPDATE invitations SET email = 'evil@example.com' WHERE tenant_id = $1 AND invited_by = $2 AND token_hash <> $3`,
	} {
		if err := tenantExec(q, f.a, f.ownerA, InvitationTokenHash(newToken())); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
	if err := tenantExec(`UPDATE invitations SET revoked_at = now() WHERE id = $1`, inv.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Un-revoking matches no row (revoke_only hides revoked invitations from UPDATE).
	if err := tenantExec(`UPDATE invitations SET revoked_at = NULL WHERE id = $1`, inv.ID); err != nil {
		t.Fatal(err)
	}
	var revoked int
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		var err error
		revoked, err = tx.Invitation.Query().Where(invitation.ID(inv.ID), invitation.RevokedAtNotNil()).Count(ctx)
		return err
	}); err != nil || revoked != 1 {
		t.Errorf("un-revoke took effect: %d, %v", revoked, err)
	}
}

// Grants are part of the design (column grants carry most of the identity
// rules); pin the ones that matter.
func TestIdentityGrants(t *testing.T) {
	owner, err := openPool(env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	for _, g := range []struct {
		role, table, column, priv string
		want                      bool
	}{
		{AppRole, "users", "id", "SELECT", true},
		{AppRole, "users", "issuer", "SELECT", false},
		{AppRole, "users", "email", "UPDATE", false},
		{AppRole, "memberships", "id", "INSERT", false},
		{AppRole, "memberships", "role", "UPDATE", true},
		{AppRole, "memberships", "user_id", "UPDATE", false},
		{AppRole, "invitations", "accepted_at", "INSERT", false},
		{AppRole, "invitations", "accepted_by", "INSERT", false},
		{AppRole, "invitations", "revoked_at", "INSERT", false},
		{AppRole, "invitations", "role", "UPDATE", false},
		{AppRole, "invitations", "revoked_at", "UPDATE", true},
		{IdentityRole, "users", "disabled_at", "UPDATE", false},
		{IdentityRole, "users", "issuer", "UPDATE", false},
		{IdentityRole, "users", "disabled_at", "INSERT", false},
		{IdentityRole, "users", "email", "UPDATE", true},
		{IdentityRole, "invitations", "role", "UPDATE", false},
		{IdentityRole, "invitations", "accepted_at", "UPDATE", true},
		{IdentityRole, "invitations", "id", "INSERT", false},
		{IdentityRole, "memberships", "role", "UPDATE", false},
		{IdentityRole, "tenants", "slug", "SELECT", true},
		{IdentityRole, "tenants", "created_at", "SELECT", false},
		{IdentityRole, "audit_events", "id", "UPDATE", false},
		// ADR-0038: the tenant pool changes only its tenant's MFA policy; a
		// session's authentication is written once by the login path.
		{AppRole, "tenants", "mfa_policy", "UPDATE", true},
		{AppRole, "tenants", "name", "UPDATE", false},
		{AppRole, "tenants", "slug", "UPDATE", false},
		{AppRole, "tenants", "id", "UPDATE", false},
		{IdentityRole, "tenants", "mfa_policy", "UPDATE", false},
		{IdentityRole, "sessions", "assurance", "INSERT", true},
		{IdentityRole, "sessions", "amr", "INSERT", true},
		{IdentityRole, "sessions", "assurance", "UPDATE", false},
		{IdentityRole, "sessions", "amr", "UPDATE", false},
		{IdentityRole, "sessions", "auth_time", "UPDATE", false},
		{AppRole, "api_tokens", "revoked_at", "INSERT", false},
		{AppRole, "api_tokens", "last_used_at", "INSERT", false},
		{AppRole, "api_tokens", "role", "UPDATE", false},
		{AppRole, "api_tokens", "expires_at", "UPDATE", false},
		{AppRole, "api_tokens", "revoked_at", "UPDATE", true},
		{IdentityRole, "api_tokens", "id", "SELECT", false},
		{AppRole, "api_token_products", "product_id", "UPDATE", false},
		{IdentityRole, "api_token_products", "id", "SELECT", false},
	} {
		var got bool
		if err := owner.QueryRow(`SELECT has_column_privilege($1, $2, $3, $4)`, g.role, g.table, g.column, g.priv).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != g.want {
			t.Errorf("%s %s on %s.%s = %v, want %v", g.role, g.priv, g.table, g.column, got, g.want)
		}
	}
}

// noRecord stands in for the audit write in tests that don't check it.
func noRecord(*ent.Tx, *ent.Membership) error { return nil }

func TestAcceptInvitationRefusals(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	if _, err := f.d.AcceptInvitation(ctx, "", f.ownerA, noRecord); err == nil {
		t.Error("empty token accepted")
	}
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "n@example.com", role: invitation.RoleViewer})
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], f.newUser(t, "n@example.com", true), nil); err == nil {
		t.Error("accepted without an audit record func")
	}
	// Already a member (owner A invited again under her own email).
	again := f.invite(t, f.a, f.ownerA, inviteOpts{email: "owner-a@example.com", role: invitation.RoleViewer})
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[again.ID], f.ownerA, noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("already a member: %v", err)
	}
	expired := f.invite(t, f.a, f.ownerA, inviteOpts{email: "e@example.com", role: invitation.RoleViewer})
	f.owner(t, `UPDATE invitations SET created_at = now() - interval '9 days', expires_at = now() - interval '1 day' WHERE id = $1`, expired.ID)
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[expired.ID], f.newUser(t, "e@example.com", true), noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("expired: %v", err)
	}
	disabled := f.invite(t, f.a, f.ownerA, inviteOpts{email: "d@example.com", role: invitation.RoleViewer})
	du := f.newUser(t, "d@example.com", true)
	f.platform(t, `UPDATE users SET disabled_at = now() WHERE id = $1`, du)
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[disabled.ID], du, noRecord); !errors.Is(err, ErrInvitation) {
		t.Errorf("disabled user: %v", err)
	}
}

// Two users accepting at once: one wins, the other is refused.
func TestConcurrentAccepts(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "c@example.com", role: invitation.RoleViewer})
	users := []string{f.newUser(t, "c@example.com", true), f.newUser(t, "C@example.com", true)}
	errs := make(chan error, 2)
	for _, u := range users {
		go func() { _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], u, noRecord); errs <- err }()
	}
	var ok, refused int
	for range users {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrInvitation):
			refused++
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 1 || refused != 1 {
		t.Errorf("ok=%d refused=%d, want 1 and 1", ok, refused)
	}
}

// Whatever code writes it, a membership whose invitation isn't marked accepted
// by that member doesn't commit (deferred key).
func TestUnmarkedMembershipDoesntCommit(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "um@example.com", role: invitation.RoleViewer})
	u := f.newUser(t, "um@example.com", true)
	err := f.d.WithIdentity(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.invite_token', $1, true)`, f.tokens[inv.ID]); err != nil {
			return err
		}
		_, err := tx.Membership.Create().SetTenantID(f.a).SetUserID(u).SetRole(membership.RoleViewer).
			SetScopeAll(true).SetInvitationID(inv.ID).Save(ctx)
		return err // no mark
	})
	if err == nil || !strings.Contains(err.Error(), "memberships_invitation_same_tenant") {
		t.Errorf("unmarked membership committed: %v", err)
	}
	if f.sees(t, f.a, u) {
		t.Error("member visible")
	}
}

// No products can be added to an accepted invitation.
func TestNoScopeChangeOnClosedInvitation(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "sc@example.com", role: invitation.RoleSupport, products: []string{f.prodA}})
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], f.newUser(t, "sc@example.com", true), noRecord); err != nil {
		t.Fatal(err)
	}
	err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		_, err := tx.InvitationProduct.Create().SetTenantID(f.a).SetInvitationID(inv.ID).SetProductID(f.prodA2).Save(ctx)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("product added to an accepted invitation: %v", err)
	}
}

// An invitation whose token hashes the empty string still needs a token.
func TestEmptyTokenNeverMatches(t *testing.T) {
	f := newIdentityFixture(t)
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "et@example.com", role: invitation.RoleViewer})
	f.platform(t, `UPDATE invitations SET token_hash = $2 WHERE id = $1`, inv.ID, InvitationTokenHash(""))
	err := f.accept(inv, f.newUser(t, "et@example.com", true), acceptOpts{token: ptrTo("")})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("accepted with no token: %v", err)
	}
}

func TestRefusedKeepsOutages(t *testing.T) {
	for _, c := range []struct {
		code, msg string
		refusal   bool
	}{
		{"42501", `new row violates row-level security policy for table "memberships"`, true},
		{"23505", `duplicate key value violates unique constraint "membership_tenant_id_user_id"`, true},
		{"42501", "permission denied for table memberships", false}, // a missing grant is an outage
		{"08006", "connection failure", false},
	} {
		err := refused(&pgconn.PgError{Code: c.code, Message: c.msg})
		if errors.Is(err, ErrInvitation) != c.refusal {
			t.Errorf("%s %q: ErrInvitation=%v, want %v", c.code, c.msg, !c.refusal, c.refusal)
		}
	}
}

// The column grants on sessions and tenants are pinned exactly (ADR-0038):
// a column added to a grant by mistake fails here.
func TestSessionAndTenantGrantsPinned(t *testing.T) {
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	cols := func(role, table, priv string) string {
		rows, err := owner.Query(`SELECT column_name FROM information_schema.column_privileges
			WHERE grantee = $1 AND table_name = $2 AND privilege_type = $3 ORDER BY column_name`, role, table, priv)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct{ role, table, priv, want string }{
		{AppRole, "tenants", "UPDATE", "audit_retention_days,mfa_policy,updated_at"},
		{IdentityRole, "tenants", "UPDATE", ""},
		{PlatformRole, "tenants", "UPDATE", "audit_retention_days,created_at,id,mfa_policy,name,slug,updated_at"},
		{IdentityRole, "sessions", "UPDATE", "last_seen_at"},
		{AppRole, "sessions", "UPDATE", ""},
		{PlatformRole, "sessions", "UPDATE", ""},
		{IdentityRole, "sessions", "INSERT", "acr,acrs,amr,assurance,auth_time,created_at,expires_at,id,last_seen_at,token_hash,user_id"},
	} {
		if got := cols(tc.role, tc.table, tc.priv); got != tc.want {
			t.Errorf("%s %s on %s: %q, want %q", tc.role, tc.priv, tc.table, got, tc.want)
		}
	} // No serving role may pass its rights on (table or column grant options).
	var grantable int
	if err := owner.QueryRow(`SELECT count(*) FROM (
			SELECT grantee, table_name FROM information_schema.column_privileges WHERE is_grantable = 'YES'
			UNION ALL SELECT grantee, table_name FROM information_schema.table_privileges WHERE is_grantable = 'YES') g
		JOIN pg_tables t ON t.tablename = g.table_name AND t.schemaname = 'public'
		WHERE g.table_name IN ('tenants', 'sessions') AND g.grantee <> t.tableowner`).Scan(&grantable); err != nil {
		t.Fatal(err)
	}
	if grantable != 0 {
		t.Errorf("%d grant options on tenants/sessions held by a role other than the owner", grantable)
	}
}
