package api

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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
	// Not a platform admin: a tenant owner gets 403 on both routes, audited
	// once per session on the platform chain; a token 401.
	plain := f.newUser(t, "plain."+strings.ToLower(ids.New("x")[2:10])+"@example.com")
	ps := f.session(t, plain, true)
	for _, m := range []string{"GET", "POST", "GET"} {
		f.do(t, m, p, `{"slug":"denied-x","name":"X","owner_email":"a@b.example"}`, ps).problem(t, 403, "forbidden")
	}
	f.do(t, "GET", p, "", f.session(t, plain, false)).problem(t, 403, "forbidden")
	if es := f.platformRefusals(t, "session.platform_denied", plain); len(es) != 2 || es[0].Outcome != auditevent.OutcomeDenied || *es[0].ObjectType != "session" {
		t.Errorf("denied audit: %d entries %+v", len(es), es)
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
	before := testutil.ToFloat64(metrics.MFARefusals.WithLabelValues("phishing_resistant"))
	weak := f.sessionAt(t, admin, false, authz.AssuranceMFA)
	f.do(t, "GET", p, "", weak).problem(t, 403, "mfa_required")
	got := f.do(t, "GET", p, "", weak).problem(t, 403, "mfa_required")
	// Counted every time, audited once for the session on the platform chain.
	if n := testutil.ToFloat64(metrics.MFARefusals.WithLabelValues("phishing_resistant")) - before; n != 2 {
		t.Errorf("counted %v refusals", n)
	}
	if es := f.platformRefusals(t, "session.mfa_required", admin); len(es) != 1 || es[0].Outcome != auditevent.OutcomeDenied ||
		!strings.Contains(es[0].Details, `"required":"phishing_resistant"`) || !strings.Contains(es[0].Details, `"session_assurance":"mfa"`) {
		t.Errorf("mfa audit: %+v", es)
	}
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

// platformRefusals returns the platform chain's action entries for userID.
func (f *fixture) platformRefusals(t *testing.T, action, userID string) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		var err error
		es, err = tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.Action(action), auditevent.ActorID(userID)).All(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return es
}

// holdPlatformChain holds the platform chain's audit lock until release is
// closed; the returned channel gets the holder's result.
func (f *fixture) holdPlatformChain(t *testing.T, release chan struct{}) chan error {
	t.Helper()
	locked, held := make(chan struct{}), make(chan error, 1)
	go func() {
		held <- f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
			if err := audit.Lock(context.Background(), tx, audit.PlatformTenant); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	return held
}

// A gate refusal already on the platform chain is found without the chain
// lock, so a repeat never queues behind the platform's audited writes.
func TestPlatformRefusalRepeatSkipsChainLock(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	user, sid := f.newUser(t, "rep."+strings.ToLower(ids.New("x")[2:10])+"@example.com"), ids.New("ses")
	if err := f.srv.Platform.RecordSessionRefusal(ctx, "session.platform_denied", user, sid, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	held := f.holdPlatformChain(t, release)
	done := make(chan error, 1)
	go func() {
		done <- f.srv.Platform.RecordSessionRefusal(ctx, "session.platform_denied", user, sid, map[string]any{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the repeated refusal waited for the chain lock")
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
		release = nil
	}
	if release != nil {
		close(release)
	}
	if err := <-held; err != nil {
		t.Fatal(err)
	}
}

// Refusals racing on several replicas record one entry: the check is
// repeated under the chain lock.
func TestPlatformRefusalRaceRecordsOnce(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	user, sid := f.newUser(t, "race."+strings.ToLower(ids.New("x")[2:10])+"@example.com"), ids.New("ses")
	release := make(chan struct{})
	held := f.holdPlatformChain(t, release)
	const n = 4
	var wg sync.WaitGroup
	for range n { // all past the unlocked check, then queued on the lock
		wg.Go(func() {
			if err := f.srv.Platform.RecordSessionRefusal(ctx, "session.platform_denied", user, sid, map[string]any{}); err != nil {
				t.Error(err)
			}
		})
	}
	for deadline := time.Now().Add(5 * time.Second); waitingAdvisory(t, f, audit.PlatformTenant) < n; {
		if time.Now().After(deadline) {
			t.Fatalf("%d refusals waiting for the chain lock", waitingAdvisory(t, f, audit.PlatformTenant))
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if got := len(f.platformRefusals(t, "session.platform_denied", user)); got != 1 {
		t.Errorf("%d entries", got)
	}
}

// Both gate refusal lookups on the platform chain are served by a partial
// index, not a scan of the chain.
func TestPlatformRefusalLookupUsesIndex(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for action, index := range map[string]string{
		"session.platform_denied": "auditevent_platform_denied",
		"session.mfa_required":    "auditevent_tenant_id_object_id",
	} {
		var plan strings.Builder
		if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
			if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
				return err
			}
			rows, err := tx.QueryContext(ctx, `EXPLAIN SELECT id FROM audit_events WHERE tenant_id = $1 AND action = $2
				AND object_type = $3 AND object_id = $4 LIMIT 1`, audit.PlatformTenant, action, "session", "ses_x")
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					return err
				}
				plan.WriteString(line + "\n")
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plan.String(), index) {
			t.Errorf("%s plan:\n%s", action, plan.String())
		}
	}
}

// A lost or expired first invitation: the platform admin re-issues it
// (ADR-0042, amended) until the tenant has an owner.
func TestPlatformReinviteOwner(t *testing.T) {
	f := setup(t)
	admin := f.platformAdmin(t)
	as := f.session(t, admin, true)
	slug := "reinvite-" + strings.ToLower(ids.New("x")[2:10])
	r := f.do(t, "POST", Prefix+"/platform/tenants", fmt.Sprintf(`{"slug":%q,"name":"Reinvite Co","owner_email":"typo@reinvite.example"}`, slug), as)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	lost := r.body["invitation"].(map[string]any)["token"]
	p := Prefix + "/platform/tenants/" + slug + "/owner-invitation"
	again := f.do(t, "POST", p, `{"owner_email":"owner@reinvite.example"}`, as)
	inv, _ := again.body["invitation"].(map[string]any)
	if again.code != 201 || inv["email"] != "owner@reinvite.example" || inv["token"] == lost || again.body["tenant"].(map[string]any)["slug"] != slug {
		t.Fatalf("re-issue: %d %s", again.code, again.raw)
	}
	f.do(t, "POST", Prefix+"/invitations/accept", fmt.Sprintf(`{"token":%q}`, lost), f.session(t, f.newUser(t, "typo@reinvite.example"), true)).problem(t, 422, "validation_failed")
	hasMembers := func() any {
		for _, it := range f.do(t, "GET", Prefix+"/platform/tenants?limit=200", "", as).body["items"].([]any) {
			if m := it.(map[string]any); m["slug"] == slug {
				return m["has_members"]
			}
		}
		return nil
	}
	if again.body["tenant"].(map[string]any)["has_members"] != false || hasMembers() != false {
		t.Errorf("before acceptance: has_members %v", hasMembers())
	}
	owner := f.newUser(t, "owner@reinvite.example")
	if r := f.do(t, "POST", Prefix+"/invitations/accept", fmt.Sprintf(`{"token":%q}`, inv["token"]), f.session(t, owner, true)); r.code != 200 {
		t.Fatalf("accept: %d %s", r.code, r.raw)
	}
	if hasMembers() != true {
		t.Errorf("after acceptance: has_members %v", hasMembers())
	}
	if r := f.do(t, "POST", p, `{"owner_email":"x@reinvite.example"}`, as).problem(t, 409, "conflict"); !strings.Contains(fmt.Sprint(r["detail"]), "has an owner") {
		t.Errorf("with an owner: %v", r)
	}
	f.do(t, "POST", Prefix+"/platform/tenants/no-such-tenant/owner-invitation", `{"owner_email":"a@b.example"}`, as).problem(t, 404, "not_found")
	f.do(t, "POST", p, `{"owner_email":"x@reinvite.example"}`, f.session(t, owner, true)).problem(t, 403, "forbidden")
}
