package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db                 *store.DB
	s                  Service
	admin, other, gone string // users: a platform admin, a plain user, a disabled admin
}

var (
	once  sync.Once
	users fixture
)

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	once.Do(func() {
		newUser := func(email string) string {
			var id string
			if err := d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
				u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(ctx)
				if err == nil {
					id = u.ID
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return id
		}
		users.admin, users.other, users.gone = newUser("admin@example.com"), newUser("user@example.com"), newUser("gone@example.com")
		noop := func(*ent.Tx) error { return nil }
		if ok, err := d.BootstrapPlatformAdmin(ctx, users.admin, noop); err != nil || !ok {
			t.Fatalf("bootstrap: %v %v", ok, err)
		}
		if err := d.GrantPlatformAdmin(ctx, users.gone, users.admin, noop); err != nil {
			t.Fatal(err)
		}
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error { return tx.User.UpdateOneID(users.gone).SetDisabledAt(time.Now()).Exec(ctx) }); err != nil {
			t.Fatal(err)
		}
	})
	f := users
	f.db, f.s = d, Service{DB: d}
	return f
}

func TestIsAdmin(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for name, c := range map[string]struct {
		user string
		want bool
	}{
		"platform admin": {f.admin, true},
		"plain user":     {f.other, false},
		"disabled admin": {f.gone, false},
		"unknown":        {ids.User(), false},
	} {
		if got, err := f.s.IsAdmin(ctx, c.user); err != nil || got != c.want {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

// A platform admin creates a tenant and its owner's invitation in one
// transaction (ADR-0042); the admin doesn't join the tenant.
func TestCreateTenant(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	slug := "acme-" + storetest.Suffix()
	c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, slug, "Acme Corp", "owner@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant.Slug != slug || c.Tenant.Name != "Acme Corp" || len(c.Token) < 20 {
		t.Fatalf("created %+v", c)
	}
	inv := c.Invitation
	if inv.TenantID != c.Tenant.ID || inv.Email != "owner@acme.example" || inv.Role != invitation.RoleOwner || !inv.ScopeAll ||
		inv.InvitedBy == nil || *inv.InvitedBy != f.admin || !bytesEqual(inv.TokenHash, store.InvitationTokenHash(c.Token)) ||
		time.Until(inv.ExpiresAt) < 6*24*time.Hour {
		t.Errorf("invitation %+v", inv)
	}
	// Audit: tenant.create on the platform chain, invitation.create as the
	// new tenant's first entry, never the email.
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		created, err := tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.Action("tenant.create"), auditevent.ObjectID(c.Tenant.ID)).Only(ctx)
		if err != nil {
			return err
		}
		if created.Outcome != auditevent.OutcomeSuccess || *created.ActorID != f.admin || !strings.Contains(created.Details, slug) {
			t.Errorf("tenant.create %+v", created)
		}
		first, err := tx.AuditEvent.Query().Where(auditevent.TenantID(c.Tenant.ID)).Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
		if err != nil {
			return err
		}
		if len(first) != 1 || first[0].Seq != 1 || first[0].Action != "invitation.create" || *first[0].ObjectID != inv.ID || strings.Contains(first[0].Details, "acme.example") {
			t.Errorf("tenant chain %+v", first)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The admin isn't a member of it.
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		n, err := tx.Membership.Query().Where(membership.TenantID(c.Tenant.ID)).Count(ctx)
		if err == nil && n != 0 {
			t.Errorf("%d memberships in the new tenant", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The CLI's system actor.
	if c, err := f.s.CreateTenant(ctx, Actor{}, "cli-"+storetest.Suffix(), "Via CLI", "o@cli.example"); err != nil || c.Invitation.InvitedBy != nil {
		t.Errorf("system actor: %+v, %v", c.Invitation, err)
	}
}

func TestCreateTenantRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	taken := "taken-" + storetest.Suffix()
	if _, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, taken, "Taken", "a@b.example"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		actor            Actor
		slug, name, mail string
		want             error
		field            string
	}{
		"not an admin":    {Actor{UserID: f.other}, "x-" + storetest.Suffix(), "X", "a@b.example", ErrNotAdmin, ""},
		"disabled admin":  {Actor{UserID: f.gone}, "x-" + storetest.Suffix(), "X", "a@b.example", ErrNotAdmin, ""},
		"bad slug":        {Actor{UserID: f.admin}, "Bad Slug", "X", "a@b.example", ErrInvalid, "/slug"},
		"blank name":      {Actor{UserID: f.admin}, "x-" + storetest.Suffix(), "  ", "a@b.example", ErrInvalid, "/name"},
		"bad email":       {Actor{UserID: f.admin}, "x-" + storetest.Suffix(), "X", "not an email", ErrInvalid, "/owner_email"},
		"slug taken":      {Actor{UserID: f.admin}, taken, "X", "a@b.example", ErrConflict, "/slug"},
		"platform's slug": {Actor{UserID: f.admin}, "platform", "X", "a@b.example", ErrConflict, "/slug"},
	} {
		before := countTenants(t, f)
		_, err := f.s.CreateTenant(ctx, c.actor, c.slug, c.name, c.mail)
		var inv *InvalidError
		if !errors.Is(err, c.want) || (c.field != "" && (!errors.As(err, &inv) || inv.Field != c.field)) {
			t.Errorf("%s: %v", name, err)
		}
		if countTenants(t, f) != before {
			t.Errorf("%s: a tenant was created", name)
		}
	}
	// Refused by role: audited on the platform chain as denied.
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		e, err := tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.Action("tenant.create"), auditevent.ActorID(f.other)).Only(ctx)
		if err == nil && e.Outcome != auditevent.OutcomeDenied {
			t.Errorf("refusal %+v", e)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTenants(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var made []string
	for range 3 {
		c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, "page-"+storetest.Suffix(), "P", "p@p.example")
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, c.Tenant.ID)
	}
	page, err := f.s.Tenants(ctx, 2, time.Time{}, "")
	if err != nil || len(page) != 2 || page[0].ID != made[2] || page[1].ID != made[1] {
		t.Fatalf("page 1: %v %v", tenantIDs(page), err)
	}
	next, err := f.s.Tenants(ctx, 200, page[1].CreatedAt, page[1].ID)
	if err != nil || len(next) == 0 || next[0].ID != made[0] {
		t.Fatalf("page 2: %v %v", tenantIDs(next), err)
	}
	all, err := f.s.Tenants(ctx, 200, time.Time{}, "")
	for _, tn := range all {
		if tn.ID == audit.PlatformTenant {
			t.Error("the platform tenant is listed")
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func countTenants(t *testing.T, f fixture) int {
	t.Helper()
	var n int
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		var err error
		n, err = tx.Tenant.Query().Where(tenant.IDNEQ(audit.PlatformTenant)).Count(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func tenantIDs(ts []*ent.Tenant) []string {
	out := make([]string, len(ts))
	for i, tn := range ts {
		out[i] = tn.ID
	}
	return out
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// A platform admin's removal waits for a transaction that rechecked the
// admin under the shared admin-set lock, as CreateTenant does (ADR-0031).
func TestRemovalWaitsForRecheck(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	extra := ""
	if err := f.db.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail("extra@example.com").SetEmailVerified(true).Save(ctx)
		if err == nil {
			extra = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.GrantPlatformAdmin(ctx, extra, f.admin, func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		if ok, err := isAdmin(ctx, tx, extra, true); err != nil || !ok {
			return fmt.Errorf("recheck: %v %v", ok, err)
		}
		go func() { done <- f.db.RemovePlatformAdmin(ctx, extra, func(*ent.Tx) error { return nil }) }()
		select {
		case err := <-done:
			return fmt.Errorf("the removal didn't wait: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("removal after commit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the removal never finished")
	}
}
