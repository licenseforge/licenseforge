package api

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestFeatureEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/features"
	created := f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","key":"max_users","name":"Users","type":"limit","unit":"users"}`, owner)
	if created.code != 201 || created.body["key"] != "max_users" || created.body["type"] != "limit" || created.body["unit"] != "users" || created.body["archived_at"] != nil {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	id := created.body["id"].(string)
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","key":"max_users","name":"Again","type":"boolean"}`, owner).problem(t, 409, "conflict")
	for body, field := range map[string]string{
		`{"product_id":"` + ids.Product() + `","key":"sso","name":"SSO","type":"boolean"}`: "/product_id",
		`{"product_id":"` + f.prodA + `","key":"SSO","name":"SSO","type":"boolean"}`:       "/key",
		`{"product_id":"` + f.prodA + `","key":"sso","name":"SSO","type":"string"}`:        "/type",
	} {
		if r := f.do(t, "POST", p, body, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), field) {
			t.Errorf("%s: %v", body, r)
		}
	}
	manager := f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA), true)
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","key":"BAD","name":"","type":"x"}`, manager).problem(t, 403, "forbidden")
	// A product-scoped caller elsewhere: the product is hidden (422), the feature not found (404).
	other := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/products", `{"slug":"cache","name":"Cache"}`, owner).body["id"].(string)
	elsewhere := f.session(t, f.join(t, f.a.ID, invitation.RoleAdmin, f.ownerA, other), true)
	f.do(t, "POST", p, `{"product_id":"`+f.prodA+`","key":"sso","name":"SSO","type":"boolean"}`, elsewhere).problem(t, 422, "validation_failed")
	if r := f.do(t, "GET", p, "", elsewhere); r.raw != `{"items":[]}`+"\n" {
		t.Errorf("scoped list: %s", r.raw)
	}
	missing := f.do(t, "GET", p+"/"+ids.Feature(), "", owner).problem(t, 404, "not_found")
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
	f.do(t, "GET", p+"?product_id=x", "", owner).problem(t, 400, "invalid_request")
	// PATCH: unit null clears; key can't change; name null is 422.
	if r := f.do(t, "PATCH", p+"/"+id, `{"name":"Named users","unit":null}`, owner); r.code != 200 || r.body["unit"] != nil || r.body["name"] != "Named users" {
		t.Errorf("patch: %d %s", r.code, r.raw)
	}
	f.do(t, "PATCH", p+"/"+id, `{"key":"other"}`, owner).problem(t, 400, "invalid_request")
	f.do(t, "PATCH", p+"/"+id, `{"name":null}`, owner).problem(t, 422, "validation_failed")
	// Archive once.
	if r := f.do(t, "POST", p+"/"+id+"/archive", "", owner); r.code != 200 || r.body["archived_at"] == nil {
		t.Errorf("archive: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p+"/"+id+"/archive", "", owner).problem(t, 409, "invalid_state")
	// No new feature on an archived product.
	f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/products/"+other+"/archive", "", owner)
	if r := f.do(t, "POST", p, `{"product_id":"`+other+`","key":"sso","name":"SSO","type":"boolean"}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "archived") {
		t.Errorf("archived product: %v", r)
	}
}
