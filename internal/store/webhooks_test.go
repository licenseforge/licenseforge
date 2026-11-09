package store

import (
	"context"
	"slices"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Exactly ADR-0044's grants, pinned in full (no TRUNCATE, no grant
// options, no extra columns): the tenant pool manages endpoints and recovers
// cursors but never touches the lease; the dispatcher (platform pool) leases
// and disables but can't create or delete cursors; nobody else gets anything.
func TestWebhookPrivileges(t *testing.T) {
	owner := sqlOpen(t, env.OwnerURL)
	grants := func(role string, table []string, cols map[string][]string) []string {
		var out []string
		for _, p := range table {
			out = append(out, role+" "+p+"  grantable=false")
		}
		for p, cs := range cols {
			for _, c := range cs {
				out = append(out, role+" "+p+" "+c+" grantable=false")
			}
		}
		return out
	}
	want := map[string][]string{
		"webhook_endpoints": append(
			grants(AppRole, []string{"SELECT", "INSERT", "DELETE"}, map[string][]string{"UPDATE": {"url_ciphertext", "url_display", "events",
				"secret_ciphertext", "previous_secret_ciphertext", "previous_secret_until", "enabled", "disabled_reason", "updated_at"}}),
			grants(PlatformRole, []string{"SELECT"}, map[string][]string{"UPDATE": {"enabled", "disabled_reason", "updated_at"}})...),
		"webhook_cursors": append(
			grants(AppRole, []string{"DELETE"}, map[string][]string{
				"SELECT": {"id", "tenant_id", "endpoint_id", "seq", "claimed_until", "attempts", "next_attempt_at"},
				"INSERT": {"id", "tenant_id", "endpoint_id", "seq"},
				"UPDATE": {"seq", "attempts", "next_attempt_at"}}),
			grants(PlatformRole, []string{"SELECT"}, map[string][]string{"UPDATE": {"seq", "claimed_by", "claimed_until", "attempts", "next_attempt_at"}})...),
		"webhook_deliveries": append(grants(AppRole, []string{"SELECT", "DELETE"}, nil),
			grants(PlatformRole, []string{"SELECT", "INSERT", "DELETE"}, nil)...),
	}
	for table, w := range want {
		slices.Sort(w)
		if got := tableACL(t, owner, table); !slices.Equal(got, w) {
			t.Errorf("privileges on %s:\n got %q\nwant %q", table, got, w)
		}
	}
}

// The cursor policies: created at or below the chain's end; seq only moves
// forward, to an entry that exists or to the anchor; the tenant pool only
// resets the retry count; endpoints are same-tenant.
func TestWebhookCursorPolicies(t *testing.T) {
	ctx := context.Background()
	f := newRetentionFixture(t) // tenant with entries 1..7; 1..5 old enough to prune
	platform := sqlOpen(t, env.PlatformURL)
	tenantExec := func(tenant, q string, args ...any) error {
		return f.d.WithTenant(ctx, tenant, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, q, args...)
			return err
		})
	}
	endpoint := func(tenant string) string {
		t.Helper()
		id := ids.WebhookEndpoint()
		if err := tenantExec(tenant, `INSERT INTO webhook_endpoints (id, tenant_id, created_at, updated_at, url_ciphertext, url_display, events, secret_ciphertext)
			VALUES ($1, $2, now(), now(), '\x01', 'https://example.com:443', '["license.issued"]', '\x01')`, id, tenant); err != nil {
			t.Fatal(err)
		}
		return id
	}
	newCursor := func(tenant, ep string, seq int64) (string, error) {
		id := ids.WebhookCursor()
		return id, tenantExec(tenant, `INSERT INTO webhook_cursors (id, tenant_id, endpoint_id, seq) VALUES ($1, $2, $3, $4)`, id, tenant, ep, seq)
	}
	a := f.tenant
	ep := endpoint(a)
	if _, err := newCursor(a, ep, 8); err == nil {
		t.Error("cursor created past the chain's end")
	}
	cur, err := newCursor(a, ep, 7)
	if err != nil {
		t.Fatalf("cursor at the end: %v", err)
	}
	for name, c := range map[string]struct {
		q    string
		args []any
		ok   bool
	}{
		"tenant: back":               {`UPDATE webhook_cursors SET seq = 5 WHERE id = $1`, nil, false},
		"tenant: to no entry":        {`UPDATE webhook_cursors SET seq = 9 WHERE id = $1`, nil, false},
		"tenant: attempts not reset": {`UPDATE webhook_cursors SET attempts = 3 WHERE id = $1`, nil, false},
		"tenant: reset":              {`UPDATE webhook_cursors SET attempts = 0, next_attempt_at = now() WHERE id = $1`, nil, true},
		"tenant: lease":              {`UPDATE webhook_cursors SET claimed_by = 'x', claimed_until = now() WHERE id = $1`, nil, false},
		"tenant: read the holder":    {`SELECT claimed_by FROM webhook_cursors WHERE id = $1`, nil, false},
	} {
		err := tenantExec(a, c.q, append([]any{cur}, c.args...)...)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The dispatcher: lease, retry state within bounds, forward only.
	for _, q := range []string{`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
		VALUES ($1, $2, 8, now(), 'system', 'test.entry', 'success', '{}', $3, $3)`} {
		if _, err := f.owner.Exec(q, ids.AuditEvent(), a, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		q  string
		ok bool
	}{
		"platform: lease":           {`UPDATE webhook_cursors SET claimed_by = 'pod-1', claimed_until = now() + interval '1 minute' WHERE id = $1`, true},
		"platform: count a failure": {`UPDATE webhook_cursors SET attempts = attempts + 1 WHERE id = $1`, true},
		"platform: past the bound":  {`UPDATE webhook_cursors SET attempts = 9 WHERE id = $1`, false},
		"platform: back":            {`UPDATE webhook_cursors SET seq = 6 WHERE id = $1`, false},
		"platform: forward":         {`UPDATE webhook_cursors SET seq = 8 WHERE id = $1`, true},
		"platform: create":          {`INSERT INTO webhook_cursors (id, tenant_id, endpoint_id, seq) SELECT 'whc_aaaaaaaaaaaaaaaaaaaaaaaaaa', tenant_id, endpoint_id, 8 FROM webhook_cursors WHERE id = $1`, false},
		"platform: delete":          {`DELETE FROM webhook_cursors WHERE id = $1`, false},
	} {
		if err := exec(platform, c.q, cur); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Pruned past the cursor: it may move to the anchor, not to a pruned seq.
	ep2 := endpoint(a)
	low, err := newCursor(a, ep2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.anchor(5, f.hashes[5]); err != nil {
		t.Fatal(err)
	}
	if n := f.prune(); n < 5 {
		t.Fatalf("pruned %d", n)
	}
	if err := exec(platform, `UPDATE webhook_cursors SET seq = 4 WHERE id = $1`, low); err == nil {
		t.Error("moved to a pruned entry that isn't the anchor")
	}
	if err := exec(platform, `UPDATE webhook_cursors SET seq = 5 WHERE id = $1`, low); err != nil {
		t.Errorf("to the anchor: %v", err)
	}
	// Another tenant can't hang a cursor or a record on this endpoint.
	b := createTenants(t, f.d, 1)[0].ID
	if _, err := newCursor(b, endpoint(a), 0); err == nil { // an endpoint without a cursor yet
		t.Error("cursor on another tenant's endpoint")
	}
	if _, err := platform.Exec(`INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
		VALUES ($1, $2, $3, 1, $4, 'license.issued', 1, 'success', 'http', 1, now())`, ids.WebhookDelivery(), b, ep, ids.AuditEvent()); err == nil {
		t.Error("delivery record on another tenant's endpoint")
	}
	// Deleting an endpoint takes its cursor and records along, in one transaction.
	if err := f.d.WithTenant(ctx, a, func(tx *ent.Tx) error {
		// The cursor first: it waits for a dispatcher holding it, whose pinned
		// write then matches nothing and records nothing.
		for _, q := range []string{`DELETE FROM webhook_cursors WHERE endpoint_id = $1`, `DELETE FROM webhook_deliveries WHERE endpoint_id = $1`, `DELETE FROM webhook_endpoints WHERE id = $1`} {
			if _, err := tx.ExecContext(ctx, q, ep); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Errorf("delete an endpoint: %v", err)
	}
}

// An update that waited for a concurrent advance doesn't move the cursor
// back (snapshot-matching USING), from either pool: e.g. a tenant's "skip to
// now" racing the dispatcher.
func TestWebhookCursorForwardUnderConcurrentCommits(t *testing.T) {
	f := newRetentionFixture(t) // entries 1..7
	for _, c := range []struct {
		name, url, tenant string
	}{{"platform", env.PlatformURL, ""}, {"tenant", env.TenantURL, f.tenant}} {
		ep, cur := ids.WebhookEndpoint(), ids.WebhookCursor()
		if _, err := f.owner.Exec(`INSERT INTO webhook_endpoints (id, tenant_id, created_at, updated_at, url_ciphertext, url_display, events, secret_ciphertext)
			VALUES ($1, $2, now(), now(), '\x01', 'https://example.com:443', '["license.issued"]', '\x01')`, ep, f.tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(`INSERT INTO webhook_cursors (id, tenant_id, endpoint_id, seq) VALUES ($1, $2, $3, 3)`, cur, f.tenant, ep); err != nil {
			t.Fatal(err)
		}
		n, err := raced(t, c.url, c.tenant, `UPDATE webhook_cursors SET seq = 7 WHERE id = $1`, `UPDATE webhook_cursors SET seq = 5, attempts = 0 WHERE id = $1`, cur)
		var seq int
		if err := f.owner.QueryRow(`SELECT seq FROM webhook_cursors WHERE id = $1`, cur).Scan(&seq); err != nil {
			t.Fatal(err)
		}
		if seq != 7 {
			t.Errorf("%s: cursor moved back past a concurrent advance: %d rows, %v, seq %d", c.name, n, err, seq)
		}
	}
}

// The CHECKs keep endpoint and delivery rows to ADR-0044's vocabulary: known
// events only, a disabled reason exactly when disabled, delivery categories
// that are fixed words (never an address), success only on a 2xx.
func TestWebhookChecks(t *testing.T) {
	f := newRetentionFixture(t)
	ep := ids.WebhookEndpoint()
	insertEndpoint := func(id, events string, enabled bool, reason any) error {
		_, err := f.owner.Exec(`INSERT INTO webhook_endpoints (id, tenant_id, created_at, updated_at, url_ciphertext, url_display, events, secret_ciphertext, enabled, disabled_reason)
			VALUES ($1, $2, now(), now(), '\x01', 'https://example.com:443', $3, '\x01', $4, $5)`, id, f.tenant, events, enabled, reason)
		return err
	}
	if err := insertEndpoint(ep, `["license.issued", "activation.created"]`, true, nil); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		events  string
		enabled bool
		reason  any
	}{
		"no events":               {`[]`, true, nil},
		"unknown event":           {`["license.issued", "bogus"]`, true, nil},
		"not a string":            {`["license.issued", 5]`, true, nil},
		"not an array":            {`{"license.issued": true}`, true, nil},
		"disabled without reason": {`["license.issued"]`, false, nil},
		"blank reason":            {`["license.issued"]`, false, " "},
		"enabled with a reason":   {`["license.issued"]`, true, "gone"},
	} {
		if err := insertEndpoint(ids.WebhookEndpoint(), c.events, c.enabled, c.reason); err == nil {
			t.Errorf("endpoint accepted: %s", name)
		}
	}
	recordAt := func(seq int, eventID string, attempt int, eventType, outcome, category string, status any) error {
		_, err := f.owner.Exec(`INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, status_code, duration_ms, attempted_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 10, now())`, ids.WebhookDelivery(), f.tenant, ep, seq, eventID, eventType, attempt, outcome, category, status)
		return err
	}
	record := func(eventType, outcome, category string, status any) error {
		return recordAt(1, ids.AuditEvent(), 1, eventType, outcome, category, status)
	}
	for name, err := range map[string]error{
		"seq 0":            recordAt(0, ids.AuditEvent(), 1, "license.issued", "failure", "timeout", nil),
		"not an audit ID":  recordAt(1, "whatever", 1, "license.issued", "failure", "timeout", nil),
		"attempt 9":        recordAt(1, ids.AuditEvent(), 9, "license.issued", "failure", "timeout", nil),
		"success on a 3xx": recordAt(1, ids.AuditEvent(), 1, "license.issued", "success", "http", 302),
	} {
		if err == nil {
			t.Errorf("record accepted: %s", name)
		}
	}
	if err := record("license.issued", "success", "http", 204); err != nil {
		t.Errorf("a 204: %v", err)
	}
	if err := record("license.issued", "failure", "timeout", nil); err != nil {
		t.Errorf("a timeout: %v", err)
	}
	for name, c := range map[string]struct {
		event, outcome, category string
		status                   any
	}{
		"address as category": {"license.issued", "failure", "dial tcp 10.0.0.5:443", nil},
		"unknown event":       {"license.bogus", "failure", "timeout", nil},
		"http without status": {"license.issued", "failure", "http", nil},
		"status without http": {"license.issued", "failure", "timeout", 500},
		"success on a 500":    {"license.issued", "success", "http", 500},
	} {
		if err := record(c.event, c.outcome, c.category, c.status); err == nil {
			t.Errorf("record accepted: %s", name)
		}
	}
}
