package api

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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
	list := f.do(t, "GET", p, "", viewer)
	if items, _ := list.body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != id || items[0].(map[string]any)["url"] != "https://hooks.example.com:443" {
		t.Errorf("list: %s", list.raw)
	}
	for _, rr := range []resp{list, f.do(t, "GET", p+"/"+id, "", viewer)} {
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
	if pr := f.do(t, "POST", p, `{"url":"https://hooks.example.com/x","events":["bogus"]}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmtAny(pr["errors"]), "/events") {
		t.Errorf("unknown event: %v", pr)
	}
	// Update, rotate, disable/enable, skip, delete.
	mp := header("Content-Type", "application/merge-patch+json")
	if rr := f.do(t, "PATCH", p+"/"+id, `{"events":["activation.created"]}`, owner, mp); rr.code != 200 || !strings.Contains(rr.raw, `"events":["activation.created"]`) {
		t.Errorf("update: %s", rr.raw)
	}
	if rr := f.do(t, "PATCH", p+"/"+id, `{"url":"https://other.example.net:8443/new?token=t2"}`, owner, mp); rr.code != 200 || rr.body["url"] != "https://other.example.net:8443" || strings.Contains(rr.raw, "token=t2") {
		t.Errorf("update url: %s", rr.raw)
	}
	if pr := f.do(t, "PATCH", p+"/"+id, `{"url":null,"events":["license.issued"]}`, owner, mp).problem(t, 422, "validation_failed"); !strings.Contains(fmtAny(pr["errors"]), "/url") {
		t.Errorf("null url: %v", pr)
	}
	if rr := f.do(t, "PATCH", p+"/"+id, `{}`, owner, mp); rr.code != 200 {
		t.Errorf("empty patch: %s", rr.raw)
	}
	if rr := f.do(t, "POST", p+"/"+id+"/rotate-secret", "", owner); rr.code != 200 || rr.body["secret"] == secret || !strings.HasPrefix(rr.body["secret"].(string), "whsec_") {
		t.Errorf("rotate: %s", rr.raw)
	}
	if rr := f.do(t, "POST", p+"/"+id+"/disable", "", owner); rr.code != 200 || rr.body["enabled"] != false || rr.body["disabled_reason"] != "disabled by a user" {
		t.Errorf("disable: %s", rr.raw)
	}
	f.do(t, "POST", p+"/"+id+"/disable", "", owner).problem(t, 409, "invalid_state")
	if rr := f.do(t, "POST", p+"/"+id+"/enable", "", owner); rr.code != 200 || rr.body["enabled"] != true || rr.body["disabled_reason"] != nil {
		t.Errorf("enable: %s", rr.raw)
	}
	f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":1}`, owner).problem(t, 409, "invalid_state")
	f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":0}`, owner).problem(t, 422, "validation_failed")
	// seq is checked after not found and denied (ADR-0032).
	f.do(t, "POST", p+"/whe_aaaaaaaaaaaaaaaaaaaaaaaaaa/skip-event", `{"seq":0}`, owner).problem(t, 404, "not_found")
	f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":0}`, f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	// An event held back: next_seq names it, and skip-event passes it.
	held := f.recordEvent(t, f.a.ID, "activation.create")
	g := f.do(t, "GET", p+"/"+id, "", owner)
	if d, _ := g.body["delivery"].(map[string]any); d["next_seq"] != float64(held) {
		t.Fatalf("next_seq: %s (want %d)", g.raw, held)
	}
	if rr := f.do(t, "POST", p+"/"+id+"/skip-event", `{"seq":`+strconv.FormatInt(held, 10)+`}`, owner); rr.code != 200 || rr.body["delivery"].(map[string]any)["seq"] != float64(held) ||
		rr.body["delivery"].(map[string]any)["next_seq"] != nil {
		t.Errorf("skip-event: %s", rr.raw)
	}
	head := f.recordEvent(t, f.a.ID, "license.revoke")
	if rr := f.do(t, "POST", p+"/"+id+"/skip-to-now", "", owner); rr.code != 200 || rr.body["delivery"].(map[string]any)["seq"].(float64) < float64(head) {
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
	f.do(t, "POST", p, `{"url":"https://hooks.example.com/11","events":["license.issued"]}`, owner).problem(t, 409, "webhook_limit_reached")
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
		}{{"failure", "connection", nil}, {"failure", "http", 500}, {"failure", "timeout", nil}, {"success", "http", 204}, {"failure", "tls", nil}, {"failure", "redirect", nil}} {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome,
				category, status_code, duration_ms, attempted_at) VALUES ($1, $2, $3, 5, $4, 'license.issued', $5, $6, $7, $8, 12, now() - make_interval(secs => $9))`,
				ids.WebhookDelivery(), f.a.ID, id, ids.AuditEvent(), min(i+1, 8), rec.outcome, rec.category, rec.status, []int{10, 9, 8, 7, 20, 20}[i]); err != nil {
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
	if first["seq"] != float64(5) || first["duration_ms"] != float64(12) || !strings.HasPrefix(first["event_id"].(string), "aud_") || first["event_type"] != "license.issued" {
		t.Errorf("fields %v", first)
	}
	// Walk every page: newest first, ties (same attempted_at) by ID, none twice or missing.
	seen := map[string]bool{}
	var all []map[string]any
	cursor := ""
	for range 10 {
		q := "?limit=1" // a page boundary inside the tie
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		rr := f.do(t, "GET", p+"/"+id+"/deliveries"+q, "", owner)
		page, _ := rr.body["items"].([]any)
		for _, it := range page {
			m := it.(map[string]any)
			if seen[m["id"].(string)] {
				t.Fatalf("%s twice", m["id"])
			}
			seen[m["id"].(string)] = true
			all = append(all, m)
		}
		next, _ := rr.body["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	var texts []string
	for _, m := range all {
		e, _ := m["error"].(string)
		texts = append(texts, e)
	}
	if got := strings.Join(texts, ","); got != ",timeout,http 500,connection failed,tls,redirect" && got != ",timeout,http 500,connection failed,redirect,tls" {
		t.Errorf("all pages: %s", got)
	}
	for i := 1; i < len(all); i++ {
		a, b := all[i-1], all[i]
		if a["attempted_at"].(string) == b["attempted_at"].(string) && a["id"].(string) < b["id"].(string) {
			t.Errorf("tie not ordered by ID desc: %v then %v", a["id"], b["id"])
		}
	}
}

func fmtAny(v any) string { b, _ := json.Marshal(v); return string(b) }

// recordEvent writes a successful audit entry on tenant's chain and returns its seq.
func (f *fixture) recordEvent(t *testing.T, tenant, action string) int64 {
	t.Helper()
	var seq int64
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		e, err := audit.Record(context.Background(), tx, tenant, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: action,
			Outcome: auditevent.OutcomeSuccess, Details: map[string]any{"new_seat": true}})
		if err == nil {
			seq = e.Seq
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return seq
}
