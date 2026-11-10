package api

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestPlanEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/plans"
	created := f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","slug":"pro","name":"Pro","duration_months":12,"max_activations":3}`, owner)
	if created.code != 201 || created.body["slug"] != "pro" || created.body["bind_type"] != "machine" || created.body["expiry_basis"] != "from_issue" ||
		created.body["lease_seconds"] != float64(604800) || created.body["duration_months"] != float64(12) || created.body["duration_seconds"] != nil {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	if v, ok := created.body["updates_months"]; !ok || v != nil {
		t.Errorf("updates_months absent is null: %s", created.raw)
	}
	id := created.body["id"].(string)
	// Maintenance (ADR-0045): a merge patch sets and clears it.
	if r := f.do(t, "PATCH", p+"/"+id, `{"updates_months":24}`, owner); r.code != 200 || r.body["updates_months"] != float64(24) {
		t.Errorf("set updates_months: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "PATCH", p+"/"+id, `{"updates_months":null}`, owner); r.code != 200 || r.body["updates_months"] != nil {
		t.Errorf("clear updates_months: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","slug":"pro","name":"Again"}`, owner).problem(t, 409, "conflict")
	for body, field := range map[string]string{
		`{"product_id":"` + ids.Product() + `","slug":"x","name":"X"}`:                                    "/product_id",
		`{"product_id":"` + f.prodA + `","slug":"x","name":"X","duration_months":1,"duration_seconds":1}`: "/duration_seconds",
		`{"product_id":"` + f.prodA + `","slug":"x","name":"X","bind_type":"none","max_activations":1}`:   "/max_activations",
		`{"product_id":"` + f.prodA + `","slug":"x","name":"X","bind_type":"user"}`:                       "/bind_type",
	} {
		if r := f.do(t, "POST", p, body, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), field) {
			t.Errorf("%s: %v", body, r)
		}
	}
	manager := f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA), true)
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","slug":"BAD","name":""}`, manager).problem(t, 403, "forbidden")
	// A product-scoped caller elsewhere: hidden product (422), plans not found (404), empty list.
	other := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/products", `{"slug":"cache","name":"Cache"}`, owner).body["id"].(string)
	elsewhere := f.session(t, f.join(t, f.a.ID, invitation.RoleAdmin, f.ownerA, other), true)
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","slug":"x","name":"X"}`, elsewhere).problem(t, 422, "validation_failed")
	if r := f.do(t, "GET", p, "", elsewhere); r.raw != `{"items":[]}`+"\n" {
		t.Errorf("scoped list: %s", r.raw)
	}
	missing := f.do(t, "GET", p+"/"+ids.Plan(), "", owner).problem(t, 404, "not_found")
	for name, c := range map[string]struct{ method, path string }{
		"hidden get":     {"GET", p + "/" + id},
		"hidden patch":   {"PATCH", p + "/" + id},
		"hidden archive": {"POST", p + "/" + id + "/archive"},
	} {
		if got := f.do(t, c.method, c.path, `{"name":"x"}`, elsewhere).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	if r := f.do(t, "GET", p+"?product_id="+f.prodA, "", owner); len(r.body["items"].([]any)) != 1 {
		t.Errorf("product filter: %s", r.raw)
	}
	// PATCH: null clears a nullable term; bind_type and slug never change; null name is 422.
	if r := f.do(t, "PATCH", p+"/"+id, `{"max_activations":null,"duration_months":null,"duration_seconds":86400}`, owner); r.code != 200 ||
		r.body["max_activations"] != nil || r.body["duration_months"] != nil || r.body["duration_seconds"] != float64(86400) {
		t.Errorf("patch: %d %s", r.code, r.raw)
	}
	f.do(t, "PATCH", p+"/"+id, `{"bind_type":"cluster"}`, owner).problem(t, 400, "invalid_request")
	f.do(t, "PATCH", p+"/"+id, `{"slug":"other"}`, owner).problem(t, 400, "invalid_request")
	for _, body := range []string{`{"name":null}`, `{"lease_seconds":null}`, `{"duration_months":12}`} {
		f.do(t, "PATCH", p+"/"+id, body, owner).problem(t, 422, "validation_failed")
	}
	// Archive once; no new license from an archived plan.
	if r := f.do(t, "POST", p+"/"+id+"/archive", "", owner); r.code != 200 || r.body["archived_at"] == nil {
		t.Errorf("archive: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p+"/"+id+"/archive", "", owner).problem(t, 409, "invalid_state")
	customer := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/customers", `{"name":"Contoso"}`, owner).body["id"].(string)
	if r := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/licenses", issueBody(f.prodA, id, customer), owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "/plan_id") {
		t.Errorf("license from an archived plan: %v", r)
	}
	// No new plan on an archived product.
	f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/products/"+other+"/archive", "", owner)
	if r := f.do(t, "POST", p, `{"product_id":"`+other+`","slug":"x","name":"X"}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "archived") {
		t.Errorf("archived product: %v", r)
	}
}

// The feature × plan matrix over HTTP (ADR-0015): a merge patch keyed by
// feature key; a license issued afterwards snapshots the grants (ADR-0013).
func TestPlanFeatureEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	tp := Prefix + "/tenants/" + f.a.Slug
	for _, b := range []string{`{"key":"sso","name":"SSO","type":"boolean"}`, `{"key":"max_users","name":"Users","type":"limit"}`} {
		if r := f.do(t, "POST", tp+"/features", `{"product_id":"`+f.prodA+`",`+b[1:], owner); r.code != 201 {
			t.Fatalf("feature: %s", r.raw)
		}
	}
	plan := f.do(t, "POST", tp+"/plans", `{"product_id":"`+f.prodA+`","slug":"pro","name":"Pro"}`, owner).body["id"].(string)
	fp := tp + "/plans/" + plan + "/features"
	if r := f.do(t, "GET", fp, "", owner); r.code != 200 || r.raw != "{}\n" {
		t.Errorf("empty: %d %s", r.code, r.raw)
	}
	r := f.do(t, "PATCH", fp, `{"sso":true,"max_users":9007199254740991}`, owner)
	if r.code != 200 || r.body["sso"] != true || r.body["max_users"] != float64(9007199254740991) {
		t.Fatalf("patch: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "PATCH", fp, `{"max_users":50}`, owner); r.code != 200 || r.raw != `{"max_users":50,"sso":true}`+"\n" {
		t.Errorf("patch 2: %d %s", r.code, r.raw)
	}
	for body, field := range map[string]string{
		`{"sso":5}`:                      "/sso",
		`{"max_users":9007199254740993}`: "/max_users",
		`{"nope":true}`:                  "/nope",
	} {
		if r := f.do(t, "PATCH", fp, body, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), field) {
			t.Errorf("%s: %v", body, r)
		}
	}
	f.do(t, "PATCH", fp, `[]`, owner).problem(t, 400, "invalid_request")
	// Hidden and missing alike; a viewer sees but can't change.
	other := f.do(t, "POST", tp+"/products", `{"slug":"cache","name":"Cache"}`, owner).body["id"].(string)
	elsewhere := f.session(t, f.join(t, f.a.ID, invitation.RoleAdmin, f.ownerA, other), true)
	missing := f.do(t, "GET", tp+"/plans/"+ids.Plan()+"/features", "", owner).problem(t, 404, "not_found")
	for _, m := range []string{"GET", "PATCH"} {
		if got := f.do(t, m, fp, `{"sso":null}`, elsewhere).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("hidden %s: %v", m, got)
		}
	}
	viewer := f.session(t, f.join(t, f.a.ID, invitation.RoleViewer, f.ownerA), true)
	if r := f.do(t, "GET", fp, "", viewer); r.code != 200 {
		t.Errorf("viewer read: %s", r.raw)
	}
	f.do(t, "PATCH", fp, `{"sso":null}`, viewer).problem(t, 403, "forbidden")
	// A license copies the grants; a later patch doesn't touch it.
	customer := f.do(t, "POST", tp+"/customers", `{"name":"Contoso"}`, owner).body["id"].(string)
	lic := f.do(t, "POST", tp+"/licenses", issueBody(f.prodA, plan, customer), owner)
	if lic.code != 201 || fmt.Sprint(lic.body["entitlements"]) != "map[features:[sso] limits:map[max_users:50]]" {
		t.Fatalf("issue: %d %s", lic.code, lic.raw)
	}
	f.do(t, "PATCH", fp, `{"sso":null,"max_users":-1}`, owner)
	if r := f.do(t, "GET", tp+"/licenses/"+lic.body["id"].(string), "", owner); fmt.Sprint(r.body["entitlements"]) != "map[features:[sso] limits:map[max_users:50]]" {
		t.Errorf("sold license changed: %s", r.raw)
	}
}
