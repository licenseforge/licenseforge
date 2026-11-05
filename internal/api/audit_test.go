package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

func auditPath(tenant string) string { return Prefix + "/tenants/" + tenant + "/audit-events" }

// record appends n entries to tenant's chain (the platform pool for the
// platform chain).
func (f *fixture) record(t *testing.T, tenant, action string, n int) {
	t.Helper()
	ctx := context.Background()
	write := func(tx *ent.Tx) error {
		for i := range n {
			if _, err := audit.Record(ctx, tx, tenant, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: action, Outcome: auditevent.OutcomeSuccess,
				Details: map[string]any{"i": i, "note": "<a&b>"}}); err != nil {
				return err
			}
		}
		return nil
	}
	var err error
	if tenant == audit.PlatformTenant {
		err = f.db.WithPlatform(ctx, write)
	} else {
		err = f.db.WithTenant(ctx, tenant, write)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) reads(t *testing.T, tenant string) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) (err error) {
		es, err = tx.AuditEvent.Query().Where(auditevent.Action("audit_event.read")).Order(ent.Asc(auditevent.FieldSeq)).All(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return es
}

type auditItem struct {
	ID, TenantID, Action, PrevHash, Hash string
	Seq                                  int64
	Details                              json.RawMessage
}

func readAuditPage(t *testing.T, r resp) ([]auditItem, string) {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.raw)
	}
	var page struct {
		Items []struct {
			ID         string          `json:"id"`
			TenantID   string          `json:"tenant_id"`
			Seq        int64           `json:"seq"`
			OccurredAt string          `json:"occurred_at"`
			ActorType  string          `json:"actor_type"`
			ActorID    *string         `json:"actor_id"`
			Action     string          `json:"action"`
			ObjectType *string         `json:"object_type"`
			ObjectID   *string         `json:"object_id"`
			Outcome    string          `json:"outcome"`
			SourceIP   *string         `json:"source_ip"`
			UserAgent  *string         `json:"user_agent"`
			Details    json.RawMessage `json:"details"`
			PrevHash   string          `json:"prev_hash"`
			Hash       string          `json:"hash"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(r.raw), &page); err != nil {
		t.Fatal(err)
	}
	var out []auditItem
	for _, it := range page.Items {
		// The hash as the spec documents it, from the response alone (not
		// audit.Hash): "lf-audit-v1" and the fields in order, each after its
		// length as 4 bytes big-endian; null as empty; occurred_at and
		// details as sent; prev_hash as its raw 32 bytes.
		s := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		prev, err := hex.DecodeString(it.PrevHash)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		for _, v := range []string{"lf-audit-v1", it.ID, it.TenantID, strconv.FormatInt(it.Seq, 10), it.OccurredAt, it.ActorType, s(it.ActorID),
			it.Action, s(it.ObjectType), s(it.ObjectID), it.Outcome, s(it.SourceIP), s(it.UserAgent), string(it.Details), string(prev)} {
			_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(v))))
			_, _ = h.Write([]byte(v))
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != it.Hash {
			t.Errorf("seq %d: hash from the response %s, sent %s", it.Seq, got, it.Hash)
		}
		out = append(out, auditItem{it.ID, it.TenantID, it.Action, it.PrevHash, it.Hash, it.Seq, it.Details})
	}
	return out, page.Next
}

func TestAuditEventEndpoints(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.record(t, f.a.ID, "test.thing", 4)
	f.record(t, f.b.ID, "test.other_tenant", 2)
	f.record(t, audit.PlatformTenant, "test.platform", 1)
	owner := f.session(t, f.ownerA, true)
	p := auditPath(f.a.Slug)

	// Newest first, paged by seq; only this tenant's chain.
	first, next := readAuditPage(t, f.do(t, "GET", p+"?limit=2", "", owner))
	if len(first) != 2 || next == "" || first[0].Seq <= first[1].Seq {
		t.Fatalf("first page: %+v %q", first, next)
	}
	var all []auditItem
	all = append(all, first...)
	for next != "" {
		var page []auditItem
		page, next = readAuditPage(t, f.do(t, "GET", p+"?limit=2&cursor="+next, "", owner))
		all = append(all, page...)
	}
	var stored []*ent.AuditEvent
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) (err error) {
		stored, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).All(ctx)
		return
	}); err != nil {
		t.Fatal(err)
	}
	// The fields are the spec's (auditEventView mirrors apigen.AuditEvent).
	var raw struct{ Items []map[string]any }
	_ = json.Unmarshal([]byte(f.do(t, "GET", p+"?limit=1", "", owner).raw), &raw)
	var want, got []string
	for _, fl := range reflect.VisibleFields(reflect.TypeFor[apigen.AuditEvent]()) {
		name, _, _ := strings.Cut(fl.Tag.Get("json"), ",")
		want = append(want, name)
	}
	for k := range raw.Items[0] {
		got = append(got, k)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("fields %v, spec %v", got, want)
	}
	// The read entry was written after the first page.
	if len(all) != len(stored)-1 {
		t.Fatalf("%d items, %d stored", len(all), len(stored))
	}
	for i, it := range all {
		e := stored[i+1]
		if it.TenantID != f.a.ID || strings.HasPrefix(it.Action, "test.other") || it.Action == "test.platform" {
			t.Errorf("foreign entry %+v", it)
		}
		// Enough to verify the chain: the hash recomputes from the entry
		// as stored, details byte for byte.
		if it.ID != e.ID || it.Seq != e.Seq || string(it.Details) != e.Details || it.Hash != hex.EncodeToString(audit.Hash(e)) ||
			it.PrevHash != hex.EncodeToString(e.PrevHash) {
			t.Errorf("item %d = %+v, stored %+v", i, it, e)
		}
		if i > 0 && all[i-1].PrevHash != it.Hash {
			t.Errorf("seq %d: chain link", it.Seq)
		}
	}
	// One read entry for the browsing session, cursor pages included.
	if rs := f.reads(t, f.a.ID); len(rs) != 1 || *rs[0].ActorID != f.ownerA || rs[0].ActorType != auditevent.ActorTypeUser || rs[0].Outcome != auditevent.OutcomeSuccess {
		t.Fatalf("read entries %+v", rs)
	}
	f.do(t, "GET", p, "", owner)

	// Export: oldest first from after_seq, continued by cursor.
	low := all[len(all)-1].Seq
	exp, next := readAuditPage(t, f.do(t, "GET", p+"?after_seq="+strconv.FormatInt(low, 10)+"&limit=3", "", owner))
	if len(exp) != 3 || exp[0].Seq != low+1 || exp[2].Seq != low+3 || next == "" {
		t.Fatalf("export: %+v %q", exp, next)
	}
	exp, _ = readAuditPage(t, f.do(t, "GET", p+"?limit=1&cursor="+next, "", owner))
	if len(exp) != 1 || exp[0].Seq != low+4 {
		t.Errorf("export page 2: %+v", exp)
	}
	if rs := f.reads(t, f.a.ID); len(rs) != 1 {
		t.Errorf("same reader within the window: %d read entries", len(rs))
	}

	// Another reader gets its own entry; tokens with audit:read may read.
	tok := f.token(t, f.a.ID, f.ownerA, authz.Admin)
	readAuditPage(t, f.do(t, "GET", p, "", f.session(t, f.adminA, true)))
	readAuditPage(t, f.do(t, "GET", p, "", bearer(tok.Token)))
	if rs := f.reads(t, f.a.ID); len(rs) != 3 || *rs[1].ActorID != f.adminA || rs[2].ActorType != auditevent.ActorTypeToken {
		t.Errorf("read entries %+v", rs)
	}

	// Roles without audit:read and product-scoped admins: 403, recorded as
	// denied. Non-members: 404.
	for name, o := range map[string]opt{"viewer": f.session(t, f.viewerA, true), "scoped admin": f.session(t, f.scoped, true),
		"manager token": bearer(f.token(t, f.a.ID, f.ownerA, authz.Manager).Token)} {
		if r := f.do(t, "GET", p, "", o).problem(t, 403, "forbidden"); r["items"] != nil {
			t.Errorf("%s: %v", name, r)
		}
		if e := f.lastEvent(t, f.a.ID); e.Action != "audit_event.read" || e.Outcome != auditevent.OutcomeDenied {
			t.Errorf("%s: refusal entry %+v", name, e)
		}
	}
	f.do(t, "GET", p, "", f.session(t, f.ownerB, true)).problem(t, 404, "not_found")
	// Tenant b's owner sees only b's chain.
	bItems, _ := readAuditPage(t, f.do(t, "GET", auditPath(f.b.Slug)+"?after_seq=0", "", f.session(t, f.ownerB, true)))
	if len(bItems) == 0 {
		t.Fatal("tenant b sees none of its own entries")
	}
	for _, it := range bItems {
		if it.TenantID != f.b.ID || strings.HasPrefix(it.Action, "test.thing") {
			t.Errorf("tenant b sees %+v", it)
		}
	}

	for _, q := range []string{"?cursor=x", "?cursor=" + next + "&after_seq=1", "?after_seq=-1", "?after_seq=x", "?action=license", "?limit=0"} {
		r := f.do(t, "GET", p+q, "", owner)
		if r.code != 400 || (r.body["code"] != "invalid_request" && r.body["code"] != "invalid_cursor") {
			t.Errorf("%s: %d %s", q, r.code, r.raw)
		}
	}
}
