package identity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
)

// platformChain returns the platform chain's entries after seq (verified).
func platformChain(t *testing.T, d *store.DB, after int64) []*ent.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var out []*ent.AuditEvent
	if _, err := audit.Verify(ctx, d.ReadPlatform, audit.PlatformTenant, audit.Head{}); err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		var err error
		out, err = tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.SeqGT(after)).
			Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func platformHead(t *testing.T, d *store.DB) int64 {
	t.Helper()
	if es := platformChain(t, d, 0); len(es) > 0 {
		return es[len(es)-1].Seq
	}
	return 0
}

// emptyAdmins gives the test an empty platform_admins table (global).
func emptyAdmins(t *testing.T) {
	t.Helper()
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	clear := func() {
		if _, err := owner.Exec(`DELETE FROM platform_admins`); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	t.Cleanup(func() { clear(); _ = owner.Close() })
}

func admins(t *testing.T, d *store.DB) []*ent.PlatformAdmin {
	t.Helper()
	var out []*ent.PlatformAdmin
	if err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		var err error
		out, err = tx.PlatformAdmin.Query().Order(ent.Asc(platformadmin.FieldCreatedAt)).All(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBootstrap(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	emptyAdmins(t)
	src := Source{IP: "192.0.2.7", UserAgent: "browser/1"}
	login := func(c Claims) *ent.User {
		t.Helper()
		u, err := s.Login(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	first := login(Claims{Issuer: "https://idp.example", Subject: sub(), Email: "root@example.com", EmailVerified: true})
	setting := "https://idp.example|" + first.Subject
	head := platformHead(t, d)

	// A user who doesn't match isn't granted, and nothing is recorded.
	other := login(Claims{Issuer: "https://idp.example", Subject: sub(), Email: "root@example.com", EmailVerified: true})
	if ok, err := s.Bootstrap(ctx, setting, other, src); ok || err != nil {
		t.Errorf("non-matching user: %v %v", ok, err)
	}
	if ok, err := s.Bootstrap(ctx, "", first, src); ok || err != nil {
		t.Errorf("empty setting: %v %v", ok, err)
	}
	if n := len(admins(t, d)); n != 0 || len(platformChain(t, d, head)) != 0 {
		t.Fatalf("non-matching: %d admins, chain grew", n)
	}

	// The grant and its record are one transaction: a record that fails
	// (invalid source IP) grants nothing.
	if ok, err := s.Bootstrap(ctx, setting, first, Source{IP: "not-an-ip"}); ok || err == nil {
		t.Errorf("bootstrap with a failing record: %v %v", ok, err)
	}
	if n := len(admins(t, d)); n != 0 {
		t.Fatalf("granted without a record: %d admins", n)
	}

	// The matching user is granted once, audited on the platform chain.
	if ok, err := s.Bootstrap(ctx, setting, first, src); !ok || err != nil {
		t.Fatalf("bootstrap: %v %v", ok, err)
	}
	as := admins(t, d)
	if len(as) != 1 || as[0].UserID != first.ID || !as[0].Bootstrap {
		t.Fatalf("admins after bootstrap: %+v", as)
	}
	es := platformChain(t, d, head)
	if len(es) != 1 {
		t.Fatalf("platform chain entries: %d, want 1", len(es))
	}
	e := es[0]
	if e.Action != "platform_admin.bootstrap" || e.ActorType != auditevent.ActorTypeSystem || e.Outcome != auditevent.OutcomeSuccess ||
		e.ObjectType == nil || *e.ObjectType != "user" || e.ObjectID == nil || *e.ObjectID != first.ID ||
		e.SourceIP == nil || *e.SourceIP != "192.0.2.7" || e.UserAgent == nil || *e.UserAgent != "browser/1" {
		t.Errorf("bootstrap entry: %+v", e)
	}

	// Once an admin exists, matching logins aren't granted again: neither the
	// same user nor another one matching by email (ADR-0029, ADR-0031).
	head = platformHead(t, d)
	if ok, err := s.Bootstrap(ctx, setting, first, src); ok || err != nil {
		t.Errorf("second bootstrap of the same user: %v %v", ok, err)
	}
	if ok, err := s.Bootstrap(ctx, "root@example.com", other, src); ok || err != nil {
		t.Errorf("bootstrap while an admin exists: %v %v", ok, err)
	}
	if n := len(admins(t, d)); n != 1 || len(platformChain(t, d, head)) != 0 {
		t.Errorf("after repeat bootstraps: %d admins, chain grew", n)
	}
}

func TestBootstrapRefusesDisabledUser(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	emptyAdmins(t)
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub()})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error { return tx.User.UpdateOne(u).SetDisabledAt(time.Now()).Exec(ctx) }); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Bootstrap(ctx, u.Issuer+"|"+u.Subject, u, Source{}); ok || err != nil || len(admins(t, d)) != 0 {
		t.Errorf("disabled user bootstrapped: %v %v", ok, err)
	}
}

func TestRecordLogin(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	head := platformHead(t, d)
	if err := s.RecordLogin(ctx, "usr_x", auditevent.OutcomeDenied, "user_disabled", Source{IP: "::ffff:10.1.2.3", UserAgent: "ua"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordLogin(ctx, "", auditevent.OutcomeFailure, "invalid_claims", Source{}, nil); err != nil {
		t.Fatal(err)
	}
	es := platformChain(t, d, head)
	if len(es) != 2 {
		t.Fatalf("entries: %d", len(es))
	}
	if e := es[0]; e.Action != "user.login" || e.ActorType != auditevent.ActorTypeUser || e.ActorID == nil || *e.ActorID != "usr_x" ||
		e.Outcome != auditevent.OutcomeDenied || e.Details != `{"reason":"user_disabled"}` || e.SourceIP == nil || *e.SourceIP != "10.1.2.3" {
		t.Errorf("denied entry: %+v", e)
	}
	if e := es[1]; e.ActorID != nil || e.ActorType != auditevent.ActorTypeUser || e.Outcome != auditevent.OutcomeFailure {
		t.Errorf("failure entry: %+v", e)
	}
}

func TestLoginReturnsDisabledUser(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	c := Claims{Issuer: "https://idp.example", Subject: sub()}
	u, err := s.Login(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error { return tx.User.UpdateOne(u).SetDisabledAt(time.Now()).Exec(ctx) }); err != nil {
		t.Fatal(err)
	}
	// The refused user is returned for the audit entry, never as a login.
	if got, err := s.Login(ctx, c); !errors.Is(err, ErrDisabled) || got == nil || got.ID != u.ID {
		t.Errorf("disabled login: %+v, %v", got, err)
	}
}

// A membership in a tenant the identity login can't see (one the platform
// pool created under the reserved platform tenant) is left out of the tenant
// switcher instead of breaking it.
func TestMembershipsSkipsHiddenTenant(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub(), Email: "h@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		inv, err := tx.Invitation.Create().SetTenantID(audit.PlatformTenant).SetEmail("h@example.com").SetRole(invitation.RoleOwner).
			SetScopeAll(true).SetTokenHash(store.InvitationTokenHash(sub())).SetExpiresAt(time.Now().Add(time.Hour)).
			SetAcceptedAt(time.Now()).SetAcceptedBy(u.ID).Save(ctx)
		if err != nil {
			return err
		}
		return tx.Membership.Create().SetTenantID(audit.PlatformTenant).SetUserID(u.ID).SetInvitationID(inv.ID).
			SetRole(membership.RoleOwner).SetScopeAll(true).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if ms, err := s.Memberships(ctx, u.ID); err != nil || len(ms) != 0 {
		t.Errorf("memberships = %+v, %v", ms, err)
	}
}
