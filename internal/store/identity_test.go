package store

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// identityFixture: two tenants, each with a product and an owner who joined
// through a (platform-created) invitation, like the bootstrap admin will.
type identityFixture struct {
	d                    *DB
	a, b                 string // tenant IDs
	prodA, prodA2, prodB string
	ownerA, ownerB       string // user IDs
}

func newIdentityFixture(t *testing.T) identityFixture {
	t.Helper()
	ctx := context.Background()
	d, err := Open(ctx, testLogins())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := identityFixture{d: d}
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
		var inv *ent.Invitation
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			var err error
			inv, err = tx.Invitation.Create().SetTenantID(o.tenant).SetEmail(o.email).SetRole(invitation.RoleOwner).
				SetScopeAll(true).SetTokenHash(token()).SetExpiresAt(time.Now().Add(time.Hour)).Save(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		*o.id = f.newUser(t, o.email, true)
		if err := f.accept(inv, *o.id, acceptOpts{}); err != nil {
			t.Fatalf("bootstrap owner of %s: %v", o.tenant, err)
		}
	}
	return f
}

func token() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

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
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(o.email).SetRole(o.role).SetScopeAll(o.products == nil).
			SetInvitedBy(inviter).SetTokenHash(token()).SetExpiresAt(time.Now().Add(7 * 24 * time.Hour))
		if o.issuer != "" {
			c.SetIssuer(o.issuer)
		}
		var err error
		if inv, err = c.Save(context.Background()); err != nil {
			return err
		}
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
	tenant   string // app.tenant_id; default the invitation's
	role     membership.Role
	scopeAll *bool
	products []string
}

// accept runs the acceptance as the login path would: membership (and its
// products) first, then mark the invitation accepted, in one transaction.
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
	return f.d.WithIdentity(ctx, o.tenant, func(tx *ent.Tx) error {
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
			if err := f.accept(inv, u, c.accept); err == nil {
				t.Fatal("accepted")
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
	for name, inviter := range map[string]string{"another tenant's owner": f.ownerB, "unknown user": ids.User()} {
		err := f.d.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
			_, err := tx.Invitation.Create().SetTenantID(f.a).SetEmail("z@example.com").SetRole(invitation.RoleViewer).SetScopeAll(true).
				SetInvitedBy(inviter).SetTokenHash(token()).SetExpiresAt(time.Now().Add(time.Hour)).Save(context.Background())
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
