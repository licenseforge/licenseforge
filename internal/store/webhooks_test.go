package store

import (
	"context"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Exactly ADR-0044's grants: the tenant pool manages endpoints and recovers
// cursors but never touches the lease; the dispatcher (platform pool) leases
// and disables but can't create or delete cursors; nobody else gets anything.
func TestWebhookPrivileges(t *testing.T) {
	owner := sqlOpen(t, env.OwnerURL)
	for _, c := range []struct {
		role, table, column, priv string
		want                      bool
	}{
		{AppRole, "webhook_endpoints", "", "SELECT", true},
		{AppRole, "webhook_endpoints", "", "INSERT", true},
		{AppRole, "webhook_endpoints", "", "DELETE", true},
		{AppRole, "webhook_endpoints", "url_ciphertext", "UPDATE", true},
		{AppRole, "webhook_endpoints", "enabled", "UPDATE", true},
		{AppRole, "webhook_endpoints", "tenant_id", "UPDATE", false},
		{AppRole, "webhook_endpoints", "id", "UPDATE", false},
		{AppRole, "webhook_endpoints", "created_at", "UPDATE", false},
		{PlatformRole, "webhook_endpoints", "", "SELECT", true},
		{PlatformRole, "webhook_endpoints", "", "INSERT", false},
		{PlatformRole, "webhook_endpoints", "", "DELETE", false},
		{PlatformRole, "webhook_endpoints", "enabled", "UPDATE", true},
		{PlatformRole, "webhook_endpoints", "disabled_reason", "UPDATE", true},
		{PlatformRole, "webhook_endpoints", "url_ciphertext", "UPDATE", false},
		{PlatformRole, "webhook_endpoints", "secret_ciphertext", "UPDATE", false},
		{PlatformRole, "webhook_endpoints", "events", "UPDATE", false},

		{AppRole, "webhook_cursors", "seq", "SELECT", true},
		{AppRole, "webhook_cursors", "claimed_until", "SELECT", true},
		{AppRole, "webhook_cursors", "claimed_by", "SELECT", false},
		{AppRole, "webhook_cursors", "seq", "INSERT", true},
		{AppRole, "webhook_cursors", "claimed_by", "INSERT", false},
		{AppRole, "webhook_cursors", "attempts", "INSERT", false},
		{AppRole, "webhook_cursors", "", "DELETE", true},
		{AppRole, "webhook_cursors", "seq", "UPDATE", true},
		{AppRole, "webhook_cursors", "attempts", "UPDATE", true},
		{AppRole, "webhook_cursors", "next_attempt_at", "UPDATE", true},
		{AppRole, "webhook_cursors", "claimed_by", "UPDATE", false},
		{AppRole, "webhook_cursors", "claimed_until", "UPDATE", false},
		{AppRole, "webhook_cursors", "endpoint_id", "UPDATE", false},
		{PlatformRole, "webhook_cursors", "", "SELECT", true},
		{PlatformRole, "webhook_cursors", "", "INSERT", false},
		{PlatformRole, "webhook_cursors", "", "DELETE", false},
		{PlatformRole, "webhook_cursors", "seq", "UPDATE", true},
		{PlatformRole, "webhook_cursors", "claimed_by", "UPDATE", true},
		{PlatformRole, "webhook_cursors", "claimed_until", "UPDATE", true},
		{PlatformRole, "webhook_cursors", "attempts", "UPDATE", true},
		{PlatformRole, "webhook_cursors", "endpoint_id", "UPDATE", false},
		{PlatformRole, "webhook_cursors", "tenant_id", "UPDATE", false},

		{AppRole, "webhook_deliveries", "", "SELECT", true},
		{AppRole, "webhook_deliveries", "", "DELETE", true},
		{AppRole, "webhook_deliveries", "", "INSERT", false},
		{PlatformRole, "webhook_deliveries", "", "SELECT", true},
		{PlatformRole, "webhook_deliveries", "", "INSERT", true},
		{PlatformRole, "webhook_deliveries", "", "DELETE", true},
	} {
		var got bool
		q, args := `SELECT has_table_privilege($1, $2, $3)`, []any{c.role, c.table, c.priv}
		if c.column != "" {
			q, args = `SELECT has_column_privilege($1, $2, $3, $4)`, []any{c.role, c.table, c.column, c.priv}
		}
		if err := owner.QueryRow(q, args...).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s %s %s.%s = %v, want %v", c.role, c.priv, c.table, c.column, got, c.want)
		}
	}
	for _, role := range []string{IdentityRole, RetentionRole} {
		for _, table := range []string{"webhook_endpoints", "webhook_cursors", "webhook_deliveries"} {
			var any bool
			if err := owner.QueryRow(`SELECT has_table_privilege($1, $2, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
				OR has_any_column_privilege($1, $2, 'SELECT,INSERT,UPDATE,REFERENCES')`, role, table).Scan(&any); err != nil {
				t.Fatal(err)
			}
			if any {
				t.Errorf("%s has privileges on %s", role, table)
			}
		}
	}
	// No UPDATE on delivery records for anyone serving.
	for _, role := range []string{AppRole, PlatformRole} {
		var upd bool
		if err := owner.QueryRow(`SELECT has_table_privilege($1, 'webhook_deliveries', 'UPDATE') OR has_any_column_privilege($1, 'webhook_deliveries', 'UPDATE')`, role).Scan(&upd); err != nil || upd {
			t.Errorf("%s can update delivery records: %v %v", role, upd, err)
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
		for _, q := range []string{`DELETE FROM webhook_deliveries WHERE endpoint_id = $1`, `DELETE FROM webhook_cursors WHERE endpoint_id = $1`, `DELETE FROM webhook_endpoints WHERE id = $1`} {
			if _, err := tx.ExecContext(ctx, q, ep); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Errorf("delete an endpoint: %v", err)
	}
}
