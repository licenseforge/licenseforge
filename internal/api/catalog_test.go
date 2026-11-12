package api

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestProductEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/products"
	created := f.do(t, "POST", p, `{"slug":"cache","name":"Cache"}`, owner)
	if created.code != 201 || created.body["slug"] != "cache" || created.body["name"] != "Cache" {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	id := created.body["id"].(string)
	if r := f.do(t, "POST", p, `{"slug":"cache","name":"Again"}`, owner).problem(t, 409, "conflict"); !strings.Contains(fmt.Sprint(r["errors"]), "/slug") {
		t.Errorf("slug taken: %v", r)
	}
	if r := f.do(t, "POST", p, `{"slug":"Cache!","name":"x"}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "/slug") {
		t.Errorf("bad slug: %v", r)
	}
	// Rights before values; creating is tenant-wide.
	f.do(t, "POST", p, `{"slug":"Bad!","name":""}`, f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	f.do(t, "POST", p, `{"slug":"x","name":"x"}`, f.session(t, f.scoped, true)).problem(t, 403, "forbidden")
	// List newest first; a product-scoped caller sees only its products.
	r := f.do(t, "GET", p+"?limit=1", "", owner)
	if items := r.body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != id || r.body["next_cursor"] == nil {
		t.Fatalf("list: %s", r.raw)
	}
	scoped := f.session(t, f.scoped, true) // admin of prodA only
	if r := f.do(t, "GET", p, "", scoped); len(r.body["items"].([]any)) != 1 || r.body["items"].([]any)[0].(map[string]any)["id"] != f.prodA {
		t.Errorf("scoped list: %s", r.raw)
	}
	// Hidden and missing alike.
	missing := f.do(t, "GET", p+"/"+ids.Product(), "", owner).problem(t, 404, "not_found")
	for name, c := range map[string]struct {
		method, path string
		o            opt
	}{
		"hidden get":       {"GET", p + "/" + id, scoped},
		"hidden patch":     {"PATCH", p + "/" + id, scoped},
		"another tenant's": {"GET", Prefix + "/tenants/" + f.b.Slug + "/products/" + id, f.session(t, f.ownerB, true)},
		"malformed":        {"GET", p + "/x", owner},
	} {
		if got := f.do(t, c.method, c.path, `{"name":"x"}`, c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// PATCH: rename; the slug can't change; null is invalid.
	if r := f.do(t, "PATCH", p+"/"+id, `{"name":"Cache 2"}`, owner, header("Content-Type", "application/merge-patch+json")); r.code != 200 || r.body["name"] != "Cache 2" || r.body["slug"] != "cache" {
		t.Errorf("patch: %d %s", r.code, r.raw)
	}
	f.do(t, "PATCH", p+"/"+id, `{"slug":"other"}`, owner).problem(t, 400, "invalid_request")
	if r := f.do(t, "PATCH", p+"/"+id, `{"name":null}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "/name") {
		t.Errorf("null name: %v", r)
	}
	f.do(t, "PATCH", p+"/"+id, `{"name":""}`, f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA), true)).problem(t, 403, "forbidden")
	if r := f.do(t, "PATCH", p+"/"+f.prodA, `{"name":"Mine"}`, scoped); r.code != 200 {
		t.Errorf("scoped admin renames its product: %d %s", r.code, r.raw)
	}
}

func TestCustomerEndpoints(t *testing.T) {
	f := setup(t)
	mgr := f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA), true)
	p := Prefix + "/tenants/" + f.a.Slug + "/customers"
	created := f.do(t, "POST", p, `{"name":"Contoso","email":"it@contoso.example","external_refs":{"stripe":"cus_1"}}`, mgr)
	if created.code != 201 || created.body["email"] != "it@contoso.example" || created.body["archived_at"] != nil {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	id := created.body["id"].(string)
	if r := f.do(t, "POST", p, `{"name":"x","email":"nope"}`, mgr).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), "/email") {
		t.Errorf("bad email: %v", r)
	}
	viewer := f.session(t, f.viewerA, true)
	f.do(t, "POST", p, `{"name":""}`, viewer).problem(t, 403, "forbidden")
	if r := f.do(t, "GET", p, "", viewer); r.code != 200 || len(r.body["items"].([]any)) != 1 {
		t.Errorf("viewer list: %s", r.raw)
	}
	// Tenant-wide: a product-scoped caller sees none, and gets the missing 404.
	scoped := f.session(t, f.scoped, true)
	if r := f.do(t, "GET", p, "", scoped); r.code != 200 || r.raw != `{"items":[]}`+"\n" {
		t.Errorf("scoped list: %s", r.raw)
	}
	missing := f.do(t, "GET", p+"/"+ids.Customer(), "", mgr).problem(t, 404, "not_found")
	for name, c := range map[string]struct {
		method, path string
		o            opt
	}{
		"scoped get":       {"GET", p + "/" + id, scoped},
		"scoped archive":   {"POST", p + "/" + id + "/archive", scoped},
		"another tenant's": {"GET", Prefix + "/tenants/" + f.b.Slug + "/customers/" + id, f.session(t, f.ownerB, true)},
	} {
		if got := f.do(t, c.method, c.path, "", c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// PATCH: email null clears it; name null is invalid; viewers can't.
	if r := f.do(t, "PATCH", p+"/"+id, `{"email":null,"external_refs":{"crm":"42"}}`, mgr); r.code != 200 || r.body["email"] != nil ||
		!reflect.DeepEqual(r.body["external_refs"], map[string]any{"stripe": "cus_1", "crm": "42"}) || r.body["name"] != "Contoso" {
		t.Errorf("patch: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "PATCH", p+"/"+id, `{"external_refs":{"stripe":null}}`, mgr); r.code != 200 || !reflect.DeepEqual(r.body["external_refs"], map[string]any{"crm": "42"}) {
		t.Errorf("remove a ref: %d %s", r.code, r.raw)
	}
	for body, field := range map[string]string{`{"name":null}`: "/name", `{"external_refs":null}`: "/external_refs", `{"external_refs":{"A":"1"}}`: "/external_refs"} {
		if r := f.do(t, "PATCH", p+"/"+id, body, mgr).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(r["errors"]), field) {
			t.Errorf("%s: %v", body, r)
		}
	}
	f.do(t, "PATCH", p+"/"+id, `{"name":null}`, viewer).problem(t, 403, "forbidden")
	// Archive once.
	f.do(t, "POST", p+"/"+id+"/archive", "", viewer).problem(t, 403, "forbidden")
	if r := f.do(t, "POST", p+"/"+id+"/archive", "", mgr); r.code != 200 || r.body["archived_at"] == nil {
		t.Errorf("archive: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p+"/"+id+"/archive", "", mgr).problem(t, 409, "invalid_state")
}

func TestProductArchiveEndpoint(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/products"
	other := f.do(t, "POST", p, `{"slug":"cache","name":"Cache"}`, owner).body["id"].(string)
	scoped := f.session(t, f.scoped, true) // admin of prodA only
	f.do(t, "POST", p+"/"+f.prodA+"/archive", "", f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA), true)).problem(t, 403, "forbidden")
	ids2 := struct{ Product func() string }{ids.Product}
	missing := f.do(t, "POST", p+"/"+ids.Product()+"/archive", "", owner).problem(t, 404, "not_found")
	if got := f.do(t, "POST", p+"/"+other+"/archive", "", scoped).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
		t.Errorf("hidden: %v, missing %v", got, missing)
	}
	if r := f.do(t, "POST", p+"/"+f.prodA+"/archive", "", scoped); r.code != 200 || r.body["archived_at"] == nil {
		t.Fatalf("archive: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p+"/"+f.prodA+"/archive", "", owner).problem(t, 409, "invalid_state")
	ids := func(q string) []any {
		var out []any
		for _, it := range f.do(t, "GET", p+q, "", owner).body["items"].([]any) {
			out = append(out, it.(map[string]any)["id"])
		}
		return out
	}
	if got := ids(""); !reflect.DeepEqual(got, []any{other, f.prodA}) {
		t.Errorf("all: %v", got)
	}
	if got := ids("?archived=false"); !reflect.DeepEqual(got, []any{other}) {
		t.Errorf("active: %v", got)
	}
	if got := ids("?archived=true"); !reflect.DeepEqual(got, []any{f.prodA}) {
		t.Errorf("archived: %v", got)
	}
	f.do(t, "GET", p+"?archived=maybe", "", owner).problem(t, 400, "invalid_request")
	// Restore (ADR-0015, amended): same rights; hidden is missing; once.
	missingRestore := f.do(t, "POST", p+"/"+ids2.Product()+"/restore", "", owner).problem(t, 404, "not_found")
	if got := f.do(t, "POST", p+"/"+other+"/restore", "", scoped).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missingRestore) {
		t.Errorf("hidden restore: %v, missing %v", got, missingRestore)
	}
	if r := f.do(t, "POST", p+"/"+f.prodA+"/restore", "", scoped); r.code != 200 || r.body["archived_at"] != nil {
		t.Fatalf("restore: %d %s", r.code, r.raw)
	}
	f.do(t, "POST", p+"/"+f.prodA+"/restore", "", owner).problem(t, 409, "invalid_state")
	if got := ids("?archived=true"); len(got) != 0 {
		t.Errorf("archived after restore: %v", got)
	}
}
