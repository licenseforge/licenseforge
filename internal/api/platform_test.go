package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// newUser creates a user with a verified email (the identity pool, as login does).
func (f *fixture) newUser(t *testing.T, email string) string {
	t.Helper()
	var uid string
	if err := f.db.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(context.Background())
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

// platformAdmin makes a new user a platform admin: the bootstrap on an
// empty set, else a grant by an existing admin (ADR-0031).
func (f *fixture) platformAdmin(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	uid := f.newUser(t, strings.ToLower(ids.New("p")[2:14])+"@example.com")
	noop := func(*ent.Tx) error { return nil }
	ok, err := f.db.BootstrapPlatformAdmin(ctx, uid, noop)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		var granter string
		if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
			a, err := tx.PlatformAdmin.Query().First(ctx)
			if err == nil {
				granter = a.UserID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := f.db.GrantPlatformAdmin(ctx, uid, granter, noop); err != nil {
			t.Fatal(err)
		}
	}
	return uid
}

// Platform admins create a tenant with its owner's invitation; the owner
// joins through the normal invitation flow (ADR-0042).
func TestPlatformTenants(t *testing.T) {
	f := setup(t)
	admin := f.platformAdmin(t)
	as := f.session(t, admin, true)
	p := Prefix + "/platform/tenants"
	slug := "onboard-" + strings.ToLower(ids.New("x")[2:10])
	r := f.do(t, "POST", p, fmt.Sprintf(`{"slug":%q,"name":"Onboard Co","owner_email":"first.owner@onboard.example"}`, slug), as)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	tn := r.body["tenant"].(map[string]any)
	inv := r.body["invitation"].(map[string]any)
	if tn["slug"] != slug || tn["mfa_policy"] != "none" || inv["role"] != "owner" || inv["email"] != "first.owner@onboard.example" || len(inv["token"].(string)) < 20 {
		t.Fatalf("created: %s", r.raw)
	}
	// Listed, newest first; the platform admin isn't a member.
	list := f.do(t, "GET", p+"?limit=200", "", as)
	if list.code != 200 || !strings.Contains(list.raw, slug) || strings.Contains(list.raw, `"slug":"platform"`) {
		t.Errorf("list: %d %s", list.code, list.raw)
	}
	if r := f.do(t, "GET", Prefix+"/me/tenants", "", as); strings.Contains(r.raw, slug) {
		t.Errorf("the admin joined the tenant: %s", r.raw)
	}
	// The owner signs in with the invited email and accepts.
	owner := f.newUser(t, "first.owner@onboard.example")
	if r := f.do(t, "POST", Prefix+"/invitations/accept", fmt.Sprintf(`{"token":%q}`, inv["token"]), f.session(t, owner, true)); r.code != 200 || r.body["role"] != "owner" {
		t.Fatalf("accept: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "GET", Prefix+"/tenants/"+slug+"/members", "", f.session(t, owner, false)); r.code != 200 {
		t.Errorf("the owner can't use the tenant: %d %s", r.code, r.raw)
	}
	// Refusals.
	f.do(t, "POST", p, fmt.Sprintf(`{"slug":%q,"name":"Again","owner_email":"a@b.example"}`, slug), as).problem(t, 409, "conflict")
	f.do(t, "POST", p, `{"slug":"platform","name":"Nope","owner_email":"a@b.example"}`, as).problem(t, 409, "conflict")
	for body, field := range map[string]string{
		`{"slug":"Bad Slug","name":"X","owner_email":"a@b.example"}`:  "/slug",
		`{"slug":"ok-slug-1","name":" ","owner_email":"a@b.example"}`: "/name",
		`{"slug":"ok-slug-2","name":"X","owner_email":"nope"}`:        "/owner_email",
	} {
		if r := f.do(t, "POST", p, body, as).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), field) {
			t.Errorf("%s: %v", body, r)
		}
	}
	f.do(t, "POST", p, `{"slug":"x","name":"X","owner_email":"a@b.example","extra":1}`, as).problem(t, 400, "invalid_request")
	f.do(t, "POST", p, `{"slug":"csrf-x","name":"X","owner_email":"a@b.example"}`, f.session(t, admin, false)).problem(t, 403, "csrf_failed")
	// Not a platform admin: a tenant owner gets 403 on both routes; a token 401.
	for _, m := range []string{"GET", "POST"} {
		f.do(t, m, p, `{"slug":"denied-x","name":"X","owner_email":"a@b.example"}`, f.session(t, f.ownerA, true)).problem(t, 403, "forbidden")
	}
	f.do(t, "GET", p, "", bearer(f.token(t, f.a.ID, f.ownerA, authz.Owner).Token)).problem(t, 401, "unauthenticated")
	f.do(t, "GET", p, "").problem(t, 401, "unauthenticated")
}

// The platform MFA policy gates every platform request (ADR-0038).
func TestPlatformMFAPolicy(t *testing.T) {
	f := setup(t)
	admin := f.platformAdmin(t)
	f.srv.PlatformMFAPolicy = authz.AssurancePhishingResistant
	p := Prefix + "/platform/tenants"
	got := f.do(t, "GET", p, "", f.sessionAt(t, admin, false, authz.AssuranceMFA)).problem(t, 403, "mfa_required")
	u, err := url.Parse(fmt.Sprint(got["step_up_url"]))
	if err != nil || u.Path != "/auth/login" || u.Query().Get("assurance") != "phishing_resistant" || u.Query().Get("return") != "/platform/" ||
		got["required_assurance"] != "phishing_resistant" || got["session_assurance"] != "mfa" {
		t.Errorf("refusal: %v", got)
	}
	if r := f.do(t, "GET", p, "", f.sessionAt(t, admin, false, authz.AssurancePhishingResistant)); r.code != 200 {
		t.Errorf("strong session: %d %s", r.code, r.raw)
	}
	f.srv.PlatformMFAPolicy = authz.AssuranceNone
	if r := f.do(t, "GET", p, "", f.session(t, admin, false)); r.code != 200 {
		t.Errorf("policy none: %d %s", r.code, r.raw)
	}
}
