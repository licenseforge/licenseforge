package platform

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

// member adds userID to tenantID with role, through an accepted invitation.
func (f fixture) member(t *testing.T, tenantID, userID, email string, role invitation.Role) {
	t.Helper()
	token := rand.Text()
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		return tx.Invitation.Create().SetTenantID(tenantID).SetEmail(email).SetRole(role).SetScopeAll(true).
			SetTokenHash(store.InvitationTokenHash(token)).SetExpiresAt(time.Now().Add(time.Hour)).Exec(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.accept(token, userID); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) role(t *testing.T, tenantID, userID string) membership.Role {
	t.Helper()
	var m *ent.Membership
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) (err error) {
		m, err = tx.Membership.Query().Where(membership.TenantID(tenantID), membership.UserID(userID)).Only(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return m.Role
}

func lastAction(es []*ent.AuditEvent) string { return es[len(es)-1].Action }

// A tenant whose owner can't sign in any more gets one back: the remaining
// member with the email is promoted, someone new is invited. Operators
// only, audited on both chains.
func TestRecoverOwner(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	slug := "orphan-" + storetest.Suffix()
	c, err := f.s.CreateTenant(ctx, Actor{}, slug, "Orphan", "left@orphan.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.accept(c.Token, f.user(t, "left@orphan.example")); err != nil {
		t.Fatal(err)
	}
	admin := f.user(t, "admin@orphan.example")
	f.member(t, c.Tenant.ID, admin, "admin@orphan.example", invitation.RoleAdmin)

	// Never from the API, whoever asks.
	if _, err := f.s.RecoverOwner(ctx, Actor{UserID: f.admin}, slug, "admin@orphan.example"); !errors.Is(err, ErrNotAdmin) || f.role(t, c.Tenant.ID, admin) != membership.RoleAdmin {
		t.Fatalf("API caller: %v", err)
	}
	if _, err := f.s.RecoverOwner(ctx, Actor{}, "no-such-"+storetest.Suffix(), "admin@orphan.example"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	// The remaining admin, by email in any case, becomes an owner.
	r, err := f.s.RecoverOwner(ctx, Actor{}, slug, "Admin@Orphan.example")
	if err != nil || r.Promoted == nil || r.Promoted.Role != membership.RoleOwner || !r.Promoted.ScopeAll || r.Token != "" {
		t.Fatalf("promote = %+v, %v", r, err)
	}
	if es := f.chain(t, c.Tenant.ID); lastAction(es) != "member.update" || es[len(es)-1].ActorType != "system" {
		t.Errorf("tenant chain ends with %s", lastAction(es))
	}
	if es := f.chain(t, audit.PlatformTenant); lastAction(es) != "tenant.owner_recovery" {
		t.Errorf("platform chain ends with %s", lastAction(es))
	}
	var inv *InvalidError
	if _, err := f.s.RecoverOwner(ctx, Actor{}, slug, "admin@orphan.example"); !errors.As(err, &inv) || !inv.Conflict {
		t.Errorf("already an owner: %v", err)
	}
	// Nobody with the email: an owner invitation, which works although the
	// tenant has members.
	r, err = f.s.RecoverOwner(ctx, Actor{}, slug, "new@orphan.example")
	if err != nil || r.Promoted != nil || r.Invitation == nil || r.Invitation.Role != invitation.RoleOwner || r.Token == "" {
		t.Fatalf("invite = %+v, %v", r, err)
	}
	newcomer := f.user(t, "new@orphan.example")
	if err := f.accept(r.Token, newcomer); err != nil || f.role(t, c.Tenant.ID, newcomer) != membership.RoleOwner {
		t.Fatalf("accept the recovery invitation: %v", err)
	}
}

// Only lowering, only operators, audited on the tenant's chain.
func TestLowerMFAPolicy(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	slug := "locked-" + storetest.Suffix()
	c, err := f.s.CreateTenant(ctx, Actor{}, slug, "Locked", "o@locked.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		return tx.Tenant.UpdateOneID(c.Tenant.ID).SetMfaPolicy(tenant.MfaPolicyPhishingResistant).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.LowerMFAPolicy(ctx, Actor{UserID: f.admin}, slug, authz.AssuranceNone); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("API caller: %v", err)
	}
	for name, p := range map[string]authz.Assurance{"same": authz.AssurancePhishingResistant, "invalid": "weak"} {
		if _, err := f.s.LowerMFAPolicy(ctx, Actor{}, slug, p); !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := f.s.LowerMFAPolicy(ctx, Actor{}, slug, authz.AssuranceMFA)
	if err != nil || got.MfaPolicy != tenant.MfaPolicyMfa {
		t.Fatalf("lower = %v, %v", got, err)
	}
	if es := f.chain(t, c.Tenant.ID); lastAction(es) != "tenant.mfa_policy.update" {
		t.Errorf("tenant chain ends with %s", lastAction(es))
	}
	if _, err := f.s.LowerMFAPolicy(ctx, Actor{}, slug, authz.AssurancePhishingResistant); !errors.Is(err, ErrConflict) {
		t.Errorf("raise: %v", err)
	}
}
