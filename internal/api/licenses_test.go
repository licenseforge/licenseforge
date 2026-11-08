package api

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
)

type testCatalog struct{ prodQ, planP, planQ, customer, bProduct, bPlan, bCustomer string }

// catalog adds a plan for prodA, a second product with a plan, a customer,
// and the same in tenant b.
func (f *fixture) catalog(t *testing.T) testCatalog {
	t.Helper()
	ctx := context.Background()
	var c testCatalog
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		mk := func(tenant, product string) (string, string, error) {
			if product == "" {
				p, err := tx.Product.Create().SetTenantID(tenant).SetSlug("p" + strings.ToLower(ids.New("x")[2:10])).SetName("P").Save(ctx)
				if err != nil {
					return "", "", err
				}
				product = p.ID
			}
			pl, err := tx.Plan.Create().SetTenantID(tenant).SetProductID(product).SetSlug("pro").SetName("Pro").SetDurationMonths(12).Save(ctx)
			if err != nil {
				return "", "", err
			}
			return product, pl.ID, nil
		}
		var err error
		if _, c.planP, err = mk(f.a.ID, f.prodA); err != nil {
			return err
		}
		if c.prodQ, c.planQ, err = mk(f.a.ID, ""); err != nil {
			return err
		}
		if c.bProduct, c.bPlan, err = mk(f.b.ID, ""); err != nil {
			return err
		}
		cu, err := tx.Customer.Create().SetTenantID(f.a.ID).SetName("Contoso").Save(ctx)
		if err != nil {
			return err
		}
		bc, err := tx.Customer.Create().SetTenantID(f.b.ID).SetName("Other").Save(ctx)
		c.customer, c.bCustomer = cu.ID, bc.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func issueBody(product, plan, customer string, extra ...string) string {
	return `{"product_id":"` + product + `","plan_id":"` + plan + `","customer_id":"` + customer + `"` + strings.Join(extra, "") + `}`
}

func TestLicenseEndpoints(t *testing.T) {
	f := setup(t)
	c := f.catalog(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/licenses"
	ok := issueBody(f.prodA, c.planP, c.customer)
	issued := f.do(t, "POST", p, issueBody(f.prodA, c.planP, c.customer, `,"type":"trial","overrides":{},"external_refs":{"order":"SO-1"}`), owner)
	key, _ := issued.body["key"].(string)
	if issued.code != 201 || key == "" || !strings.HasSuffix(key, issued.body["key_hint"].(string)) || issued.body["status"] != "active" ||
		issued.body["type"] != "trial" || issued.body["expires_at"] == nil {
		t.Fatalf("issue: %d %s", issued.code, issued.raw)
	}
	id := issued.body["id"].(string)
	// Get and list never show the key.
	got := f.do(t, "GET", p+"/"+id, "", owner)
	if got.code != 200 || got.body["id"] != id || strings.Contains(got.raw, key) || got.body["key"] != nil {
		t.Fatalf("get: %d %s", got.code, got.raw)
	}
	second := f.do(t, "POST", p, ok, owner)
	qLic := f.do(t, "POST", p, issueBody(c.prodQ, c.planQ, c.customer), owner)
	l := f.do(t, "GET", p+"?limit=2", "", owner)
	items, _ := l.body["items"].([]any)
	if l.code != 200 || len(items) != 2 || items[0].(map[string]any)["id"] != qLic.body["id"] || l.body["next_cursor"] == nil || strings.Contains(l.raw, key) {
		t.Fatalf("list: %s", l.raw)
	}
	listIDs := func(q string, o opt) []any {
		r := f.do(t, "GET", p+q, "", o)
		var out []any
		for _, it := range r.body["items"].([]any) {
			out = append(out, it.(map[string]any)["id"])
		}
		return out
	}
	if got := listIDs("?product_id="+f.prodA, owner); !reflect.DeepEqual(got, []any{second.body["id"], id}) {
		t.Errorf("product filter: %v", got)
	}
	// A product-scoped manager sees only its product's licenses; others are not found.
	scoped := f.session(t, f.join(t, f.a.ID, invitation.RoleManager, f.ownerA, c.prodQ), true)
	if got := listIDs("", scoped); !reflect.DeepEqual(got, []any{qLic.body["id"]}) {
		t.Errorf("scoped list: %v", got)
	}
	missing := f.do(t, "GET", p+"/"+ids.License(), "", owner).problem(t, 404, "not_found")
	for name, c := range map[string]struct {
		path string
		o    opt
	}{
		"hidden":           {p + "/" + id, scoped},
		"another tenant's": {Prefix + "/tenants/" + f.b.Slug + "/licenses/" + id, f.session(t, f.ownerB, true)},
		"malformed":        {p + "/x", owner},
		"hidden suspend":   {p + "/" + id + "/suspend", scoped},
	} {
		method := "GET"
		if strings.HasSuffix(c.path, "/suspend") {
			method = "POST"
		}
		if got := f.do(t, method, c.path, "", c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// Body references: 422 on the field; hidden is missing.
	refs := map[string]struct {
		body  string
		o     opt
		field string
	}{
		"unknown product":           {issueBody(ids.Product(), c.planP, c.customer), owner, "/product_id"},
		"hidden product":            {issueBody(f.prodA, c.planP, c.customer), scoped, "/product_id"},
		"another tenant's product":  {issueBody(c.bProduct, c.bPlan, c.bCustomer), owner, "/product_id"},
		"another product's plan":    {issueBody(f.prodA, c.planQ, c.customer), owner, "/plan_id"},
		"unknown customer":          {issueBody(f.prodA, c.planP, ids.Customer()), owner, "/customer_id"},
		"another tenant's customer": {issueBody(f.prodA, c.planP, c.bCustomer), owner, "/customer_id"},
		"unknown feature":           {issueBody(f.prodA, c.planP, c.customer, `,"overrides":{"a/b":{}}`), owner, "/overrides/a~1b"},
		"type":                      {issueBody(f.prodA, c.planP, c.customer, `,"type":"gold"`), owner, "/type"},
	}
	var unknownProduct map[string]any
	for name, r := range refs {
		got := f.do(t, "POST", p, r.body, r.o).problem(t, 422, "validation_failed")
		if errs, _ := got["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["field"] != r.field {
			t.Errorf("%s: %v", name, got)
		}
		if r.field == "/product_id" {
			if unknownProduct == nil {
				unknownProduct = got
			} else if !reflect.DeepEqual(got, unknownProduct) {
				t.Errorf("%s: %v differs from %v", name, got, unknownProduct)
			}
		}
	}
	// Rights before values.
	viewer := f.session(t, f.viewerA, true)
	f.do(t, "POST", p, issueBody(f.prodA, "x", "y"), viewer).problem(t, 403, "forbidden")
	f.do(t, "POST", p+"/"+id+"/suspend", "", viewer).problem(t, 403, "forbidden")
	// Transitions: 200 with the license; a status that doesn't allow it is 409.
	for _, step := range []struct{ verb, want string }{{"suspend", "suspended"}, {"reinstate", "active"}, {"suspend", "suspended"}, {"revoke", "revoked"}} {
		if r := f.do(t, "POST", p+"/"+id+"/"+step.verb, "", owner); r.code != 200 || r.body["status"] != step.want {
			t.Fatalf("%s: %d %s", step.verb, r.code, r.raw)
		}
	}
	f.do(t, "POST", p+"/"+id+"/reinstate", "", owner).problem(t, 409, "invalid_state")
	f.do(t, "POST", p+"/"+id+"/revoke", "", owner).problem(t, 409, "invalid_state")
	if got := listIDs("?status=revoked", owner); !reflect.DeepEqual(got, []any{id}) {
		t.Errorf("status filter: %v", got)
	}
	if got := listIDs("?created_after="+strings.ReplaceAll(second.body["created_at"].(string), "+", "%2B"), owner); !reflect.DeepEqual(got, []any{qLic.body["id"]}) {
		t.Errorf("created_after: %v", got)
	}
	for _, q := range []string{"?status=gone", "?product_id=x", "?customer_id=x", "?created_after=yesterday", "?plan_id=" + c.planP} {
		f.do(t, "GET", p+q, "", owner).problem(t, 400, "invalid_request")
	}
	if got := listIDs("?customer_id="+ids.Customer(), owner); len(got) != 0 {
		t.Errorf("unknown customer filter: %v", got)
	}
}

func TestIssueLicenseIdempotency(t *testing.T) {
	f := setup(t)
	c := f.catalog(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/licenses"
	body := issueBody(f.prodA, c.planP, c.customer)
	key := header("Idempotency-Key", "order-1")
	first := f.do(t, "POST", p, body, owner, key)
	if first.code != 201 || first.body["key"] == nil {
		t.Fatalf("first: %d %s", first.code, first.raw)
	}
	// A retry gets the same license and key; nothing new is issued.
	again := f.do(t, "POST", p, body, owner, key)
	if again.code != 201 || again.body["id"] != first.body["id"] || again.body["key"] != first.body["key"] {
		t.Fatalf("replay: %d %s", again.code, again.raw)
	}
	if e := f.lastEvent(t, f.a.ID); e.Action != "license.key_reveal" || *e.ObjectID != first.body["id"] || *e.ActorID != f.ownerA ||
		!strings.Contains(e.Details, `"product_id":"`+f.prodA+`"`) ||
		strings.Contains(e.Details, first.body["key"].(string)) {
		t.Errorf("replay audit = %+v", e)
	}
	if r := f.do(t, "GET", p, "", owner); len(r.body["items"].([]any)) != 1 {
		t.Errorf("issued twice: %s", r.raw)
	}
	// The same key with another body; another credential's key space.
	f.do(t, "POST", p, issueBody(f.prodA, c.planP, c.customer, `,"type":"trial"`), owner, key).problem(t, 422, "idempotency_key_reused")
	tok := f.token(t, f.a.ID, f.ownerA, authz.Admin)
	if r := f.do(t, "POST", p, body, bearer(tok.Token), key); r.code != 201 || r.body["id"] == first.body["id"] {
		t.Errorf("another credential: %d %s", r.code, r.raw)
	}
	// A refusal is stored and replayed as it was.
	bad := header("Idempotency-Key", "order-2")
	r1 := f.do(t, "POST", p, issueBody(f.prodA, c.planQ, c.customer), owner, bad).problem(t, 422, "validation_failed")
	r2 := f.do(t, "POST", p, issueBody(f.prodA, c.planQ, c.customer), owner, bad).problem(t, 422, "validation_failed")
	if !reflect.DeepEqual(r1["errors"], r2["errors"]) {
		t.Errorf("refusal replay: %v, %v", r1, r2)
	}
	// A replay re-checks the caller's rights: an admin demoted to viewer
	// gets 403, not the stored license and key.
	admin := f.session(t, f.adminA, true)
	k3 := header("Idempotency-Key", "order-3")
	if r := f.do(t, "POST", p, body, admin, k3); r.code != 201 {
		t.Fatalf("admin issue: %d %s", r.code, r.raw)
	}
	if err := f.db.WithTenant(context.Background(), f.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE memberships SET role = 'viewer' WHERE id = $1`, f.mem[f.adminA])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, "POST", p, body, admin, k3).problem(t, 403, "forbidden"); r["key"] != nil {
		t.Errorf("replay leaked: %v", r)
	}
	if e := f.lastEvent(t, f.a.ID); e.Action != "license.issue" || e.Outcome != "denied" || *e.ActorID != f.adminA || !strings.Contains(e.Details, `"replay":true`) {
		t.Errorf("refused replay audit = %+v", e)
	}
	// Malformed keys.
	for _, k := range []string{strings.Repeat("k", 256), "é", ""} {
		r := f.do(t, "POST", p, body, owner, header("Idempotency-Key", k))
		if k == "" {
			continue // an empty header is no header (Go's http.Header.Get)
		}
		if r.code != 400 || r.body["code"] != "invalid_request" {
			t.Errorf("key %q: %d %s", k, r.code, r.raw)
		}
	}
}

func (f *fixture) lastEvent(t *testing.T, tenant string) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		e, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).First(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// GET /summary: exact counts in the caller's scope and tenant; customers
// only for callers who see every product (absent, not zero, otherwise).
func TestSummary(t *testing.T) {
	f := setup(t)
	c := f.catalog(t)
	owner := f.session(t, f.ownerA, true)
	lic := Prefix + "/tenants/" + f.a.Slug + "/licenses"
	var onA []string
	for range 2 {
		r := f.do(t, "POST", lic, issueBody(f.prodA, c.planP, c.customer), owner)
		if r.code != 201 {
			t.Fatalf("issue: %d %s", r.code, r.raw)
		}
		onA = append(onA, r.body["id"].(string))
	}
	if r := f.do(t, "POST", lic, issueBody(c.prodQ, c.planQ, c.customer), owner); r.code != 201 {
		t.Fatalf("issue on Q: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "POST", lic+"/"+onA[0]+"/suspend", "", owner); r.code != 200 {
		t.Fatalf("suspend: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "POST", Prefix+"/tenants/"+f.b.Slug+"/licenses", issueBody(c.bProduct, c.bPlan, c.bCustomer), f.session(t, f.ownerB, true)); r.code != 201 {
		t.Fatalf("issue in b: %d %s", r.code, r.raw)
	}
	// Seen this month (ADR-0016): the customer with an activation refreshed
	// now; another customer last seen last month doesn't count.
	other := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/customers", `{"name":"Gone"}`, owner).body["id"].(string)
	old := f.do(t, "POST", lic, issueBody(f.prodA, c.planP, other), owner).body["id"].(string)
	// A machine deactivated after being seen now still counts; so does one
	// seen exactly at the month start (on product Q: the scoped counts stay).
	onQ := func(name string) string {
		cus := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/customers", `{"name":"`+name+`"}`, owner).body["id"].(string)
		return f.do(t, "POST", lic, issueBody(c.prodQ, c.planQ, cus), owner).body["id"].(string)
	}
	moved, edge := onQ("Moved"), onQ("Edge")
	ctx := context.Background()
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) error {
		monthStart := `date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
		for _, a := range []struct {
			license, seen, deactivated string
		}{
			{onA[1], `clock_timestamp()`, `NULL`},
			{onA[1], `clock_timestamp()`, `NULL`}, // a second machine: one customer
			{old, monthStart + ` - interval '1 microsecond'`, `NULL`},
			{moved, `clock_timestamp()`, `clock_timestamp()`},
			{edge, monthStart, `NULL`},
		} {
			id := ids.New("act") // inserted active, then deactivated (insert_active)
			if _, err := tx.ExecContext(ctx, `INSERT INTO activations (id, tenant_id, license_id, fingerprint, fp_source, binding, mode, first_seen_at, last_seen_at, created_at, updated_at)
				VALUES ($1, $2, $3, $4, 'machine-id', 'machine', 'online', `+a.seen+`, `+a.seen+`, now(), now())`, id, f.a.ID, a.license, newFP()); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE activations SET deactivated_at = `+a.deactivated+` WHERE id = $1`, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, "GET", Prefix+"/tenants/"+f.a.Slug+"/summary", "", owner); r.code != 200 {
		t.Fatalf("summary: %s", r.raw)
	} else {
		cs := r.body["customers"].(map[string]any)
		start, err := time.Parse(time.RFC3339, cs["month_start"].(string))
		now := time.Now().UTC()
		if err != nil || start.Day() != 1 || start.Hour()+start.Minute()+start.Second()+start.Nanosecond() != 0 || start.Location() != time.UTC ||
			start.After(now) || now.Sub(start) > 32*24*time.Hour {
			t.Errorf("month_start = %v (%v)", cs["month_start"], err)
		}
	}
	path := func(tn *ent.Tenant) string { return Prefix + "/tenants/" + tn.Slug + "/summary" }
	for name, tc := range map[string]struct {
		path string
		o    opt
		want string
	}{
		"owner":                   {path(f.a), owner, `{"customers":{"active":4,"seen_this_month":3},"licenses":{"active":5,"revoked":0,"suspended":1}}`},
		"viewer":                  {path(f.a), f.session(t, f.viewerA, false), `{"customers":{"active":4,"seen_this_month":3},"licenses":{"active":5,"revoked":0,"suspended":1}}`},
		"scoped to prodA":         {path(f.a), f.session(t, f.scoped, false), `{"licenses":{"active":2,"revoked":0,"suspended":1}}`},
		"other tenant":            {path(f.b), f.session(t, f.ownerB, false), `{"customers":{"active":1,"seen_this_month":0},"licenses":{"active":1,"revoked":0,"suspended":0}}`},
		"API token, all products": {path(f.a), bearer(f.token(t, f.a.ID, f.ownerA, authz.Viewer).Token), `{"customers":{"active":4,"seen_this_month":3},"licenses":{"active":5,"revoked":0,"suspended":1}}`},
	} {
		r := f.do(t, "GET", tc.path, "", tc.o)
		var got, want any
		_ = json.Unmarshal([]byte(r.raw), &got)
		if cs, ok := got.(map[string]any)["customers"].(map[string]any); ok {
			delete(cs, "month_start") // checked above
		}
		_ = json.Unmarshal([]byte(tc.want), &want)
		if r.code != 200 || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %d %s, want %s", name, r.code, r.raw, tc.want)
		}
	}
	f.do(t, "GET", path(f.a), "").problem(t, 401, "unauthenticated")
	f.do(t, "GET", path(f.a), "", f.session(t, f.outsider, false)).problem(t, 404, "not_found")
	f.do(t, "GET", path(f.a), "", bearer(f.token(t, f.a.ID, f.ownerA, authz.SDK).Token)).problem(t, 403, "forbidden")
	f.do(t, "GET", path(f.a)+"?status=active", "", owner).problem(t, 400, "invalid_request")
}
