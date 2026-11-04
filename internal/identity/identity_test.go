package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
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
		"no issuer":        {Subject: sub()},
		"no subject":       {Issuer: "https://idp.example"},
		"blank subject":    {Issuer: "https://idp.example", Subject: "  "},
		"NUL in subject":   {Issuer: "https://idp.example", Subject: "a\x00b"},
		"subject too long": {Issuer: "https://idp.example", Subject: strings.Repeat("s", 256)},
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
	// The API's tenant resolution and grant.
	for ref, want := range map[string]string{tn.Slug: tn.ID, tn.ID: tn.ID, "nope-" + storetest.Suffix(): "", ids.Tenant(): "", "": ""} {
		if id, err := s.TenantID(ctx, ref); id != want || (want == "") != errors.Is(err, ErrNotMember) {
			t.Errorf("TenantID(%q) = %q, %v", ref, id, err)
		}
	}
	if g, err := s.Grant(ctx, u.ID, tn.ID); err != nil || g.Role != authz.Owner || !g.Scope.All || len(g.Scope.Products) != 0 {
		t.Errorf("grant = %+v, %v", g, err)
	}
	for _, c := range [][2]string{{ids.User(), tn.ID}, {u.ID, ids.Tenant()}} {
		if _, err := s.Grant(ctx, c[0], c[1]); !errors.Is(err, ErrNotMember) {
			t.Errorf("grant of non-member %v: %v", c, err)
		}
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

// Two first logins of the same new user at once both succeed, as one user.
func TestConcurrentFirstLogin(t *testing.T) {
	s, _ := open(t)
	c := Claims{Issuer: "https://idp.example", Subject: sub(), Email: "race@example.com", EmailVerified: true}
	for range 10 {
		c.Subject = sub()
		type res struct {
			u   *ent.User
			err error
		}
		out := make(chan res, 2)
		for range 2 {
			go func() { u, err := s.Login(context.Background(), c); out <- res{u, err} }()
		}
		a, b := <-out, <-out
		if a.err != nil || b.err != nil || a.u.ID != b.u.ID {
			t.Fatalf("concurrent first login: %v / %v", a.err, b.err)
		}
	}
}

func TestLoginEdgeCases(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if _, err := s.Login(ctx, Claims{Issuer: "https://" + strings.Repeat("i", 500), Subject: sub()}); !errors.Is(err, ErrInvalidClaims) {
		t.Errorf("issuer too long: %v", err)
	}
	// An unusable "verified" email is treated as unverified: the user still
	// signs in, with no email stored and the flag off.
	for name, email := range map[string]string{
		"no email":      "",
		"not an email":  "nope",
		"too long":      strings.Repeat("e", 320) + "@x.io",
		"spaces":        " a@example.com",
		"bidi override": "a\u202e@example.com",
		"zero-width":    "a\u200b@example.com",
	} {
		u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub(), Email: email, EmailVerified: true})
		if err != nil || u.Email != nil || u.EmailVerified {
			t.Errorf("%s: %+v %v", name, u, err)
		}
	}
	// A name of only format characters leaves the stored name as it was.
	c := Claims{Issuer: "https://idp.example", Subject: sub(), Name: "Grace"}
	if _, err := s.Login(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Name = "\u200b\u202e"
	u, err := s.Login(ctx, c)
	if err != nil || u.Name == nil || *u.Name != "Grace" {
		t.Errorf("format-only name: %+v %v", u, err)
	}
}

func TestBootstrapMatchesEdgeCases(t *testing.T) {
	mk := func(iss, sub, email string) *ent.User {
		return &ent.User{Issuer: iss, Subject: sub, Email: &email, EmailVerified: true}
	}
	for _, c := range []struct {
		setting string
		u       *ent.User
		want    bool
	}{
		// Auth0: the subject itself contains '|'; split at the first one.
		{"https://t.auth0.com/|auth0|abc", mk("https://t.auth0.com/", "auth0|abc", "x@example.com"), true},
		// The issuer must match exactly, trailing slash included.
		{"https://t.auth0.com|auth0|abc", mk("https://t.auth0.com/", "auth0|abc", "x@example.com"), false},
		// No Unicode look-alike folding (long s, Kelvin sign).
		{"boss@acme.com", mk("i", "s", "bo\u017f\u017f@acme.com"), false},
		{"kim@acme.com", mk("i", "s", "\u212aim@acme.com"), false},
		{"BOSS@ACME.COM", mk("i", "s", "boss@acme.com"), true},
	} {
		if got := BootstrapMatches(c.setting, c.u); got != c.want {
			t.Errorf("BootstrapMatches(%q, %q|%q %q) = %v", c.setting, c.u.Issuer, c.u.Subject, *c.u.Email, got)
		}
	}
}

func TestMembershipsSorted(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub(), Email: "s@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"zeta-" + storetest.Suffix(), "alpha-" + storetest.Suffix()} {
		tok := rand.Text()
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			tn, err := tx.Tenant.Create().SetSlug(slug).SetName(slug).Save(ctx)
			if err != nil {
				return err
			}
			_, err = tx.Invitation.Create().SetTenantID(tn.ID).SetEmail("s@example.com").SetRole(invitation.RoleViewer).SetScopeAll(true).
				SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour)).Save(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.AcceptInvitation(ctx, tok, u.ID, func(*ent.Tx, *ent.Membership) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := s.Memberships(ctx, u.ID)
	if err != nil || len(ms) != 2 || !strings.HasPrefix(ms[0].TenantSlug, "alpha-") {
		t.Errorf("memberships = %+v, %v", ms, err)
	}
}
