package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
)

func (f *fixture) setPolicy(t *testing.T, tenantID string, p authz.Assurance) {
	t.Helper()
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		return tx.Tenant.UpdateOneID(tenantID).SetMfaPolicy(tenant.MfaPolicy(p)).Exec(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) mfaEvents(t *testing.T, tenantID string) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenantID, func(tx *ent.Tx) (err error) {
		es, err = tx.AuditEvent.Query().Where(auditevent.Action("session.mfa_required")).All(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return es
}

var levels = []authz.Assurance{authz.AssuranceNone, authz.AssuranceMFA, authz.AssurancePhishingResistant}

// Every tenant request checks the session against the tenant's policy,
// right after the membership check (ADR-0038).
func TestMFAEnforcement(t *testing.T) {
	f := setup(t)
	p := tokensPath(f.a.Slug)
	for i, policy := range levels {
		f.setPolicy(t, f.a.ID, policy)
		for j, session := range levels {
			r := f.do(t, "GET", p, "", f.sessionAt(t, f.viewerA, false, session))
			if j >= i {
				if r.code != 200 {
					t.Errorf("policy %s, session %s: %d %s", policy, session, r.code, r.raw)
				}
				continue
			}
			body := r.problem(t, http.StatusForbidden, "mfa_required")
			step, _ := url.Parse(body["step_up_url"].(string))
			if body["required_assurance"] != string(policy) || body["session_assurance"] != string(session) ||
				step.Path != "/auth/login" || step.Query().Get("assurance") != string(policy) || step.Query().Get("return") != "/t/"+f.a.Slug+"/" {
				t.Errorf("policy %s, session %s: %v", policy, session, body)
			}
		}
	}
	// Policy phishing_resistant from here on.
	// A non-member still gets 404: the policy isn't revealed.
	f.do(t, "GET", p, "", f.sessionAt(t, f.outsider, false, authz.AssuranceNone)).problem(t, http.StatusNotFound, "not_found")
	// API tokens are exempt at use.
	tok := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	if r := f.do(t, "GET", p, "", bearer(tok.Token)); r.code != 200 {
		t.Errorf("token: %d", r.code)
	}
	// Creating a token needs a session that meets the policy.
	create := `{"name":"ci","role":"sdk","all_products":true}`
	f.do(t, "POST", p, create, f.sessionAt(t, f.ownerA, true, authz.AssuranceMFA)).problem(t, http.StatusForbidden, "mfa_required")
	if r := f.do(t, "POST", p, create, f.sessionAt(t, f.ownerA, true, authz.AssurancePhishingResistant)); r.code != 201 {
		t.Errorf("create with a security key: %d %s", r.code, r.raw)
	}
	// User routes aren't tenant routes: no policy applies.
	if r := f.do(t, "GET", Prefix+"/me/tenants", "", f.sessionAt(t, f.viewerA, false, authz.AssuranceNone)); r.code != 200 {
		t.Errorf("/me/tenants: %d", r.code)
	}
	// A policy change applies to a live session at its next request.
	live := f.sessionAt(t, f.viewerA, false, authz.AssuranceMFA)
	f.do(t, "GET", p, "", live).problem(t, http.StatusForbidden, "mfa_required")
	f.setPolicy(t, f.a.ID, authz.AssuranceMFA)
	if r := f.do(t, "GET", p, "", live); r.code != 200 {
		t.Errorf("after lowering: %d", r.code)
	}
}

// A refusal is audited once per session and tenant; every one is counted.
func TestMFARefusalAuditedOnce(t *testing.T) {
	f := setup(t)
	f.setPolicy(t, f.a.ID, authz.AssuranceMFA)
	p := tokensPath(f.a.Slug)
	before := testutil.ToFloat64(metrics.MFARefusals.WithLabelValues("mfa"))
	s1, s2 := f.sessionAt(t, f.viewerA, false, authz.AssuranceNone), f.sessionAt(t, f.viewerA, false, authz.AssuranceNone)
	for range 3 {
		f.do(t, "GET", p, "", s1).problem(t, http.StatusForbidden, "mfa_required")
	}
	f.srv.mfaSeen = mfaAudited{} // another replica: the database check still finds the entry
	f.do(t, "GET", p, "", s1).problem(t, http.StatusForbidden, "mfa_required")
	f.do(t, "GET", p, "", s2).problem(t, http.StatusForbidden, "mfa_required")
	es := f.mfaEvents(t, f.a.ID)
	if len(es) != 2 || es[0].Outcome != auditevent.OutcomeDenied || *es[0].ActorID != f.viewerA || *es[0].ObjectID == *es[1].ObjectID {
		t.Fatalf("events %+v", es)
	}
	if got := testutil.ToFloat64(metrics.MFARefusals.WithLabelValues("mfa")) - before; got != 5 {
		t.Errorf("counted %v refusals", got)
	}
	if len(f.mfaEvents(t, f.b.ID)) != 0 {
		t.Error("tenant b's chain written")
	}
}

// /me/tenants lists every membership with its policy and whether this
// session meets it.
func TestMyTenantsAccessible(t *testing.T) {
	f := setup(t)
	f.setPolicy(t, f.a.ID, authz.AssurancePhishingResistant)
	r := f.do(t, "GET", Prefix+"/me/tenants", "", f.sessionAt(t, f.ownerA, false, authz.AssuranceMFA))
	items, _ := r.body["items"].([]any)
	if r.code != 200 || len(items) != 1 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	it := items[0].(map[string]any)
	if it["mfa_policy"] != "phishing_resistant" || it["accessible"] != false {
		t.Errorf("item %v", it)
	}
	r = f.do(t, "GET", Prefix+"/me/tenants", "", f.sessionAt(t, f.ownerA, false, authz.AssurancePhishingResistant))
	if it := r.body["items"].([]any)[0].(map[string]any); it["accessible"] != true {
		t.Errorf("item %v", it)
	}
}
