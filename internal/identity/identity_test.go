package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

func open(t *testing.T) (Service, *store.DB) {
	t.Helper()
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return Service{DB: d}, d
}

func sub() string { return ids.New("sub") }

func TestLoginCreatesAndRefreshes(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	c := Claims{Issuer: "https://idp.example", Subject: sub(), Email: "a@example.com", EmailVerified: true, Name: " Ada \u202e\x00Lovelace "}
	u, err := s.Login(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email == nil || *u.Email != "a@example.com" || !u.EmailVerified || u.Name == nil || *u.Name != "Ada Lovelace" || u.LastLoginAt == nil {
		t.Errorf("created %+v", u)
	}
	// Same (issuer, subject): same user, refreshed.
	c.Email, c.Name = "ada@example.com", "Ada"
	u2, err := s.Login(ctx, c)
	if err != nil || u2.ID != u.ID || *u2.Email != "ada@example.com" || *u2.Name != "Ada" {
		t.Errorf("refreshed %+v, %v", u2, err)
	}
	// An unverified email claim doesn't change the email and clears the flag.
	c.Email, c.EmailVerified = "boss@example.com", false
	u3, err := s.Login(ctx, c)
	if err != nil || *u3.Email != "ada@example.com" || u3.EmailVerified {
		t.Errorf("unverified claim: %+v, %v", u3, err)
	}
	// Another issuer with the same subject is another user.
	other, err := s.Login(ctx, Claims{Issuer: "https://other.example", Subject: c.Subject})
	if err != nil || other.ID == u.ID || other.Email != nil {
		t.Errorf("other issuer: %+v, %v", other, err)
	}
}

func TestLoginRefusals(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	for name, c := range map[string]Claims{
		"no issuer":              {Subject: sub()},
		"no subject":             {Issuer: "https://idp.example"},
		"blank subject":          {Issuer: "https://idp.example", Subject: "  "},
		"NUL in subject":         {Issuer: "https://idp.example", Subject: "a\x00b"},
		"verified, no email":     {Issuer: "https://idp.example", Subject: sub(), EmailVerified: true},
		"verified, not an email": {Issuer: "https://idp.example", Subject: sub(), Email: "nope", EmailVerified: true},
		"subject too long":       {Issuer: "https://idp.example", Subject: strings.Repeat("s", 256)},
	} {
		if _, err := s.Login(ctx, c); !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := Claims{Issuer: "https://idp.example", Subject: sub()}
	u, err := s.Login(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error { return tx.User.UpdateOne(u).SetDisabledAt(time.Now()).Exec(ctx) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, c); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled user: %v", err)
	}
}

func TestMemberships(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub(), Email: "m@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	var tn *ent.Tenant
	tok := rand.Text()
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		var err error
		if tn, err = tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("Acme").Save(ctx); err != nil {
			return err
		}
		_, err = tx.Invitation.Create().SetTenantID(tn.ID).SetEmail("m@example.com").SetRole(invitation.RoleOwner).SetScopeAll(true).
			SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour)).Save(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if ms, err := s.Memberships(ctx, u.ID); err != nil || len(ms) != 0 {
		t.Fatalf("before joining: %v %v", ms, err)
	}
	if _, err := d.AcceptInvitation(ctx, tok, u.ID, func(*ent.Tx, *ent.Membership) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ms, err := s.Memberships(ctx, u.ID)
	if err != nil || len(ms) != 1 || ms[0].TenantID != tn.ID || ms[0].TenantSlug != tn.Slug || ms[0].TenantName != "Acme" || ms[0].Role != "owner" || !ms[0].ScopeAll {
		t.Errorf("memberships = %+v, %v", ms, err)
	}
}

func TestBootstrapMatches(t *testing.T) {
	email := "Admin@Example.com"
	u := &ent.User{Issuer: "https://idp.example", Subject: "abc", Email: &email, EmailVerified: true}
	unverified := &ent.User{Issuer: "https://idp.example", Subject: "abc", Email: &email}
	for _, c := range []struct {
		setting string
		u       *ent.User
		want    bool
	}{
		{"https://idp.example|abc", u, true},
		{"https://idp.example|abd", u, false},
		{"https://other.example|abc", u, false},
		{"admin@example.com", u, true},
		{"admin@example.com", unverified, false},
		{"other@example.com", u, false},
		{"", u, false},
		{"  ", u, false},
		{"admin@example.com", nil, false},
	} {
		if got := BootstrapMatches(c.setting, c.u); got != c.want {
			t.Errorf("BootstrapMatches(%q, %v) = %v", c.setting, c.u != nil, got)
		}
	}
}
