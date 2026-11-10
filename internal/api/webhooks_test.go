package api

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func webhooksPath(tenant string) string { return Prefix + "/tenants/" + tenant + "/webhooks" }

func TestWebhookEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := webhooksPath(f.a.Slug)
	r := f.do(t, "POST", p, `{"url":"https://hooks.example.com/services/T0/B0/s3cr3t?key=k","events":["license.revoked","license.issued"]}`, owner)
	secret, _ := r.body["secret"].(string)
	id, _ := r.body["id"].(string)
	if r.code != 201 || !strings.HasPrefix(secret, "whsec_") || !ids.Valid("whe", id) || r.body["url"] != "https://hooks.example.com:443" ||
		r.body["enabled"] != true || r.body["disabled_reason"] != nil {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if d, _ := r.body["delivery"].(map[string]any); d["attempts"] != float64(0) || d["in_flight"] != false {
		t.Errorf("delivery state %v", d)
	}
	// Reads show the masked URL and never the secret, to viewers too.
	viewer := f.session(t, f.viewerA, false)
	for _, rr := range []resp{f.do(t, "GET", p, "", viewer), f.do(t, "GET", p+"/"+id, "", viewer)} {
		if rr.code != 200 || strings.Contains(rr.raw, "s3cr3t") || strings.Contains(rr.raw, "key=k") || strings.Contains(rr.raw, secret) {
			t.Errorf("read: %d %s", rr.code, rr.raw)
		}
	}
	// Viewers can't change; another tenant and a product-scoped admin see nothing.
	f.do(t, "POST", p, `{"url":"https://x.example/","events":["license.issued"]}`, f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	f.do(t, "GET", webhooksPath(f.b.Slug)+"/"+id, "", f.session(t, f.ownerB, false)).problem(t, 404, "not_found")
	scoped := f.session(t, f.scoped, true)
	if rr := f.do(t, "GET", p, "", scoped); rr.code != 200 || !strings.Contains(rr.raw, `"items":[]`) {
		t.Errorf("scoped list: %s", rr.raw)
	}
	f.do(t, "POST", p+"/"+id+"/disable", "", scoped).problem(t, 404, "not_found")
	// Validation: field and message, never the URL.
	for body, field := range map[string]string{
		`{"url":"http://hooks.example.com/x","events":["license.issued"]}`:                   "/url",
		`{"url":"https://u:p@hooks.example.com/x","events":["license.issued"]}`:              "/url",
		`{"url":"https://hooks.example.com/x","events":["license.issued","license.issued"]}`: "/events",
	} {
		pr := f.do(t, "POST", p, body, owner).problem(t, 422, "validation_failed")
		if fs, _ := pr["errors"].([]any); len(fs) != 1 || fs[0].(map[string]any)["field"] != field || strings.Contains(f.do(t, "POST", p, body, owner).raw, "u:p") {
			t.Errorf("%s: %v", body, pr)
		}
	}
	f.do(t, "POST", p, `{"url":"https://hooks.example.com/x","events":["bogus"]}`, owner).problem(t, 422, "validation_failed")
	// Update, rotate, disable/enable, skip, delete.
	if rr := f.do(t, "PATCH", p+"/"+id, `{"events":["activation.created"]}`, owner); rr.code != 200 || !strings.Contains(rr.raw, `"events":["activation.created"]`) {
		t.Errorf("update: %s", rr.raw)
	}
	f.do(t, "PATCH", p+"/"+id, `{}`, owner).problem(t, 422, "validation_failed")
	if rr := f.do(t, "POST", p+"/"+id+"/rotate-secret", "", owner); rr.code != 200 || rr.body["secret"] == secret || !strings.HasPrefix(rr.body["secret"].(string), "whsec_") {
		t.Errorf("rotate: %s", rr.raw)
	}
	if rr := f.do(t, "POST", p+"/"+id+"/disable", "", owner); rr.code != 200 || rr.body["enabled"] != false || rr.body["disabled_reason"] != "disabled by a user" {
		t.Errorf("disable: %s", rr.raw)
	}
	f.do(t, "POST", p+"/"+id+"/disable", "", owner).problem(t, 409, "invalid_state")
	if rr := f.do(t, "POST", p+"/"+id+"/enable", "", owner); rr.code != 200 || rr.body["enabled"] != true {
		t.Errorf("enable: %s", rr.raw)
	}
	f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":1}`, owner).problem(t, 409, "invalid_state")
	f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":0}`, owner).problem(t, 422, "validation_failed")
	if rr := f.do(t, "POST", p+"/"+id+"/skip-to-now", "", owner); rr.code != 200 {
		t.Errorf("skip to now: %s", rr.raw)
	}
	if rr := f.do(t, "GET", p+"/"+id+"/deliveries", "", viewer); rr.code != 200 || !strings.Contains(rr.raw, `"items":[]`) {
		t.Errorf("deliveries: %s", rr.raw)
	}
	f.do(t, "GET", p+"/"+id+"/deliveries?cursor=bad", "", viewer).problem(t, 400, "invalid_cursor")
	if rr := f.do(t, "DELETE", p+"/"+id, "", owner); rr.code != 204 {
		t.Errorf("delete: %d %s", rr.code, rr.raw)
	}
	f.do(t, "GET", p+"/"+id, "", owner).problem(t, 404, "not_found")
	// At most 10.
	for i := range 10 {
		if rr := f.do(t, "POST", p, `{"url":"https://hooks.example.com/`+strconv.Itoa(i)+`","events":["license.issued"]}`, owner); rr.code != 201 {
			t.Fatalf("create %d: %s", i, rr.raw)
		}
	}
	f.do(t, "POST", p, `{"url":"https://hooks.example.com/11","events":["license.issued"]}`, owner).problem(t, 409, "webhook_limit")
}

// The delivery log in the API's words: fixed error texts, newest first, paged.
func TestWebhookDeliveryLog(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := webhooksPath(f.a.Slug)
	r := f.do(t, "POST", p, `{"url":"https://hooks.example.com/x","events":["license.issued"]}`, owner)
	id := r.body["id"].(string)
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		for i, rec := range []struct {
			outcome, category string
			status            any
		}{{"failure", "connection", nil}, {"failure", "http", 500}, {"failure", "timeout", nil}, {"success", "http", 204}} {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome,
				category, status_code, duration_ms, attempted_at) VALUES ($1, $2, $3, 5, $4, 'license.issued', $5, $6, $7, $8, 12, now() - make_interval(secs => $9))`,
				ids.WebhookDelivery(), f.a.ID, id, ids.AuditEvent(), i+1, rec.outcome, rec.category, rec.status, 10-i); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r1 := f.do(t, "GET", p+"/"+id+"/deliveries?limit=2", "", owner)
	items, _ := r1.body["items"].([]any)
	next, _ := r1.body["next_cursor"].(string)
	if r1.code != 200 || len(items) != 2 || next == "" {
		t.Fatalf("page 1: %s", r1.raw)
	}
	first, second := items[0].(map[string]any), items[1].(map[string]any)
	if first["outcome"] != "success" || first["error"] != nil || first["status_code"] != float64(204) || second["error"] != "timeout" {
		t.Errorf("page 1 items %v %v", first, second)
	}
	r2 := f.do(t, "GET", p+"/"+id+"/deliveries?limit=2&cursor="+next, "", owner)
	items, _ = r2.body["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["error"] != "http 500" || items[1].(map[string]any)["error"] != "connection failed" {
		t.Errorf("page 2: %s", r2.raw)
	}
}
