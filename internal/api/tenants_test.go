package api

import (
	"net/http"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
)

func TestUpdateTenantMFAPolicy(t *testing.T) {
	f := setup(t)
	p := Prefix + "/tenants/" + f.a.Slug
	patch := func(body string, o opt) resp {
		return f.do(t, "PATCH", p, body, o, header("Content-Type", "application/merge-patch+json"))
	}
	f.token(t, f.a.ID, f.ownerA, authz.SDK) // one active token, reported
	ownerNone := f.sessionAt(t, f.ownerA, true, authz.AssuranceNone)
	ownerMFA := f.sessionAt(t, f.ownerA, true, authz.AssuranceMFA)

	patch(`{"mfa_policy":"mfa"}`, ownerNone).problem(t, http.StatusConflict, "mfa_policy_unmet")
	r := patch(`{"mfa_policy":"mfa"}`, ownerMFA)
	if r.code != 200 || r.body["mfa_policy"] != "mfa" || r.body["id"] != f.a.ID || r.body["slug"] != f.a.Slug || r.body["active_api_tokens"] != float64(1) {
		t.Fatalf("raise: %d %s", r.code, r.raw)
	}
	patch(`{"mfa_policy":"phishing_resistant"}`, ownerMFA).problem(t, http.StatusConflict, "mfa_policy_unmet")
	if r := patch(`{}`, ownerMFA); r.code != 200 || r.body["mfa_policy"] != "mfa" {
		t.Errorf("empty patch: %d %s", r.code, r.raw)
	}
	// A password session can't reach the tenant once it requires MFA (403
	// mfa_required); lowering takes a session that meets the current policy.
	patch(`{"mfa_policy":"none"}`, ownerNone).problem(t, http.StatusForbidden, "mfa_required")
	if r := patch(`{"mfa_policy":"none"}`, ownerMFA); r.code != 200 || r.body["mfa_policy"] != "none" {
		t.Errorf("lower: %d %s", r.code, r.raw)
	}

	pr := f.sessionAt(t, f.adminA, true, authz.AssurancePhishingResistant)
	patch(`{"mfa_policy":"mfa"}`, pr).problem(t, http.StatusForbidden, "forbidden")
	owner := f.token(t, f.a.ID, f.ownerA, authz.Owner)
	patch(`{"mfa_policy":"none"}`, bearer(owner.Token)).problem(t, http.StatusForbidden, "forbidden")
	body := patch(`{"mfa_policy":"strong"}`, ownerMFA).problem(t, http.StatusUnprocessableEntity, "validation_failed")
	if errs, _ := body["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["field"] != "/mfa_policy" {
		t.Errorf("errors %v", body["errors"])
	}
	patch(`{"mfa_policy":null}`, ownerMFA).problem(t, http.StatusUnprocessableEntity, "validation_failed")
	patch(`{"mfa_policy":"mfa","name":"x"}`, ownerMFA).problem(t, http.StatusBadRequest, "invalid_request")
	patch(`{"mfa_policy":"mfa"}`, f.session(t, f.ownerA, false)).problem(t, http.StatusForbidden, "csrf_failed")
	// Another tenant's member: not found, whatever the policy.
	f.do(t, "PATCH", p, `{"mfa_policy":"mfa"}`, f.sessionAt(t, f.ownerB, true, authz.AssurancePhishingResistant),
		header("Content-Type", "application/merge-patch+json")).problem(t, http.StatusNotFound, "not_found")
}
