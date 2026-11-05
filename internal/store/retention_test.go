package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// retentionFixture: a tenant whose chain has entries 1..5 older than a year
// and 6..7 from last week (inserted by the owner; hashes are distinct
// placeholders, these tests are about the policies, not the chain).
type retentionFixture struct {
	d      *DB
	r      *Retention
	owner  *sql.DB
	tenant string
	hashes map[int64][]byte
	ret    *sql.DB // the retention login, raw
}

func newRetentionFixture(t *testing.T) retentionFixture {
	t.Helper()
	ctx := context.Background()
	f := retentionFixture{d: openDB(t), hashes: map[int64][]byte{}}
	var err error
	if f.r, err = OpenRetention(ctx, env.RetentionURL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.r.Close() })
	f.owner = sqlOpen(t, env.OwnerURL)
	f.ret = sqlOpen(t, env.RetentionURL)
	f.tenant = createTenants(t, f.d, 1)[0].ID
	for seq := int64(1); seq <= 7; seq++ {
		age := "400 days"
		if seq > 5 {
			age = "7 days"
		}
		h := make([]byte, 32)
		h[0], h[1] = byte(seq), 0xab
		f.hashes[seq] = h
		if _, err := f.owner.Exec(fmt.Sprintf(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, $3, now() - interval '%s', 'system', 'test.entry', 'success', '{}', $4, $5)`, age),
			ids.AuditEvent(), f.tenant, seq, make([]byte, 32), h); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func sqlOpen(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (f retentionFixture) seqs(t *testing.T) []int64 {
	t.Helper()
	rows, err := f.owner.Query(`SELECT seq FROM audit_events WHERE tenant_id = $1 ORDER BY seq`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (f retentionFixture) anchor(seq int64, hash []byte) error {
	_, err := f.ret.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, $3, $4, now())`, ids.AuditAnchor(), f.tenant, seq, hash)
	return err
}

func (f retentionFixture) prune() int64 {
	res, err := f.ret.Exec(`DELETE FROM audit_events WHERE tenant_id = $1`, f.tenant)
	if err != nil {
		return -1
	}
	n, _ := res.RowsAffected()
	return n
}

func TestRetentionLogin(t *testing.T) {
	ctx := context.Background()
	if r, err := OpenRetention(ctx, env.RetentionURL); err != nil {
		t.Errorf("retention login refused: %v", err)
	} else {
		_ = r.Close()
	}
	for name, url := range map[string]string{"platform": env.PlatformURL, "tenant": env.TenantURL, "owner": env.OwnerURL} {
		if r, err := OpenRetention(ctx, url); err == nil {
			_ = r.Close()
			t.Errorf("OpenRetention accepted the %s login", name)
		}
	}
	l := testLogins()
	l.Platform = env.RetentionURL
	if d, err := Open(ctx, l); err == nil {
		_ = d.Close()
		t.Error("Open accepted the retention login as the platform pool")
	}
}

// The database's own limits on pruning (ADR-0036), whatever the job does.
func TestRetentionFloorAndAnchors(t *testing.T) {
	f := newRetentionFixture(t)
	if n := f.prune(); n != 0 {
		t.Fatalf("pruned %d entries without an anchor", n)
	}
	// Entry 2 out of time order (a clock step): the age floor still keeps it.
	if _, err := f.owner.Exec(`UPDATE audit_events SET occurred_at = now() - interval '7 days' WHERE tenant_id = $1 AND seq = 2`, f.tenant); err != nil {
		t.Fatal(err)
	}
	// Anchors name a real, aged entry that isn't the last, and move forward.
	// The other tenant has its own old entries 1..5 (other hashes): only the
	// chain clause can refuse an anchor that names this chain's entry 3 there.
	other := createTenants(t, f.d, 1)[0].ID
	for seq := int64(1); seq <= 5; seq++ {
		h := make([]byte, 32)
		h[0], h[1] = byte(seq), 0xcd
		if _, err := f.owner.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, $3, now() - interval '400 days', 'system', 'test.entry', 'success', '{}', $4, $5)`, ids.AuditEvent(), other, seq, make([]byte, 32), h); err != nil {
			t.Fatal(err)
		}
	}
	for name, err := range map[string]error{
		"wrong hash":       f.anchor(3, f.hashes[4]),
		"no such entry":    f.anchor(9, f.hashes[3]),
		"a young entry":    f.anchor(6, f.hashes[6]),
		"the chain's head": f.anchor(7, f.hashes[7]),
		"another tenant's chain": func() error {
			_, err := f.ret.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 3, $3, now())`, ids.AuditAnchor(), other, f.hashes[3])
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("anchor on %s accepted", name)
		}
	}
	if err := f.anchor(3, f.hashes[3]); err != nil {
		t.Fatalf("anchor at 3: %v", err)
	}
	for name, err := range map[string]error{"backwards": f.anchor(1, f.hashes[1]), "the same seq": f.anchor(3, f.hashes[3])} {
		if err == nil {
			t.Errorf("anchor %s accepted", name)
		}
	}
	// Deletes reach at most the anchor, and never an entry younger than 365 days.
	if n := f.prune(); n != 2 || fmt.Sprint(f.seqs(t)) != "[2 4 5 6 7]" {
		t.Fatalf("pruned %d, left %v; want 1 and 3 gone, the young 2 kept", n, f.seqs(t))
	}
	if err := f.anchor(5, f.hashes[5]); err != nil {
		t.Fatal(err)
	}
	if n := f.prune(); n != 2 || fmt.Sprint(f.seqs(t)) != "[2 6 7]" {
		t.Errorf("pruned %d, left %v; want 4..5 gone", n, f.seqs(t))
	}
}

// Anchors and deletes are per chain: another tenant's anchors neither allow
// deletes in a chain without one nor hold its anchors back.
func TestRetentionIsPerChain(t *testing.T) {
	f := newRetentionFixture(t)
	if err := f.anchor(5, f.hashes[5]); err != nil {
		t.Fatal(err)
	}
	g := f
	g.tenant = createTenants(t, f.d, 1)[0].ID
	for seq := int64(1); seq <= 3; seq++ {
		if _, err := f.owner.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, $3, now() - interval '400 days', 'system', 'test.entry', 'success', '{}', $4, $5)`,
			ids.AuditEvent(), g.tenant, seq, make([]byte, 32), f.hashes[seq]); err != nil {
			t.Fatal(err)
		}
	}
	if n := g.prune(); n != 0 {
		t.Errorf("deleted %d entries of a chain without an anchor", n)
	}
	// An old entry that is this chain's last can't be an anchor, even though
	// another chain has later entries.
	if err := g.anchor(3, f.hashes[3]); err == nil {
		t.Error("anchor on the chain's last entry accepted")
	}
	if err := g.anchor(2, f.hashes[2]); err != nil { // below the other chain's anchor (5): still forward for this chain
		t.Errorf("anchor at 2 refused because of another chain's anchor: %v", err)
	}
}

func TestRetentionLoginLimits(t *testing.T) {
	f := newRetentionFixture(t)
	ctx := context.Background()
	if err := f.anchor(3, f.hashes[3]); err != nil {
		t.Fatal(err)
	}
	record := func(action, actor string) error {
		_, err := f.ret.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, 8, now(), $3, $4, 'success', '{}', $5, $5)`, ids.AuditEvent(), f.tenant, actor, action, f.hashes[7])
		return err
	}
	for name, err := range map[string]error{
		"another action":           record("api_token.create", "system"),
		"another actor":            record("audit.retention", "user"),
		"update an entry":          exec(f.ret, `UPDATE audit_events SET action = 'x.y' WHERE tenant_id = $1`, f.tenant),
		"update an anchor":         exec(f.ret, `UPDATE audit_anchors SET seq = 1 WHERE tenant_id = $1`, f.tenant),
		"delete an anchor":         exec(f.ret, `DELETE FROM audit_anchors WHERE tenant_id = $1`, f.tenant),
		"write a cursor":           exec(f.ret, `UPDATE audit_export_cursors SET seq = 0`),
		"read licenses":            exec(f.ret, `SELECT 1 FROM licenses`),
		"read users":               exec(f.ret, `SELECT 1 FROM users`),
		"read tenants' API tokens": exec(f.ret, `SELECT 1 FROM api_tokens`),
	} {
		if err == nil {
			t.Errorf("retention login could %s", name)
		}
	}
	if _, err := f.ret.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
		VALUES ($1, $2, 8, now() - interval '1 day', 'system', 'audit.retention', 'success', '{}', $3, $3)`, ids.AuditEvent(), f.tenant, f.hashes[7]); err == nil {
		t.Error("retention login wrote a backdated entry")
	}
	if _, err := f.ret.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
		VALUES ($1, $2, 8, now() + interval '1 day', 'system', 'audit.retention', 'success', '{}', $3, $3)`, ids.AuditEvent(), f.tenant, f.hashes[7]); err == nil {
		t.Error("retention login wrote a future-dated entry")
	}
	if err := record("audit.retention", "system"); err != nil {
		t.Errorf("retention login can't record its own entry: %v", err)
	}
	for _, q := range []string{`SELECT 1 FROM audit_export_sinks`, `SELECT 1 FROM audit_export_cursors`, `SELECT 1 FROM audit_anchors`} {
		if err := exec(f.ret, q); err != nil {
			t.Errorf("retention login: %s: %v", q, err)
		}
	}
	// Serving logins never delete entries, and only read anchors (tenants their own).
	for pool, with := range map[string]func(func(*ent.Tx) error) error{
		"tenant":   func(fn func(*ent.Tx) error) error { return f.d.WithTenant(ctx, f.tenant, fn) },
		"platform": func(fn func(*ent.Tx) error) error { return f.d.WithPlatform(ctx, fn) },
	} {
		if err := with(func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE tenant_id = $1`, f.tenant)
			return err
		}); err == nil {
			t.Errorf("%s pool deleted audit entries", pool)
		}
		if err := with(func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 4, $3, now())`, ids.AuditAnchor(), f.tenant, f.hashes[4])
			return err
		}); err == nil {
			t.Errorf("%s pool inserted an anchor", pool)
		}
		var n int
		if err := with(func(tx *ent.Tx) error {
			var err error
			n, err = tx.AuditAnchor.Query().Count(ctx)
			return err
		}); err != nil || n == 0 {
			t.Errorf("%s pool reads %d anchors, %v", pool, n, err)
		}
	}
	other := createTenants(t, f.d, 1)[0].ID
	if err := f.d.WithTenant(ctx, other, func(tx *ent.Tx) error {
		n, err := tx.AuditAnchor.Query().Count(ctx)
		if err == nil && n != 0 {
			err = errors.New("sees another tenant's anchors")
		}
		return err
	}); err != nil {
		t.Error(err)
	}
}

func exec(db *sql.DB, q string, args ...any) error {
	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	return errors.Join(rows.Err(), rows.Close())
}

// Exactly ADR-0036's grants for the retention login, and read-only anchors
// for the serving logins.
func TestRetentionPrivileges(t *testing.T) {
	owner := sqlOpen(t, env.OwnerURL)
	for _, c := range []struct {
		role, table, priv string
		want              bool
	}{
		{RetentionRole, "audit_events", "SELECT", true}, {RetentionRole, "audit_events", "INSERT", true},
		{RetentionRole, "audit_events", "DELETE", true}, {RetentionRole, "audit_events", "UPDATE", false},
		{RetentionRole, "audit_events", "TRUNCATE", false},
		{RetentionRole, "audit_anchors", "SELECT", true}, {RetentionRole, "audit_anchors", "INSERT", true},
		{RetentionRole, "audit_anchors", "UPDATE", false}, {RetentionRole, "audit_anchors", "DELETE", false},
		{RetentionRole, "audit_export_cursors", "SELECT", true}, {RetentionRole, "audit_export_cursors", "UPDATE", false},
		{RetentionRole, "audit_export_cursors", "INSERT", false}, {RetentionRole, "audit_export_cursors", "DELETE", false},
		{RetentionRole, "audit_export_sinks", "SELECT", true}, {RetentionRole, "audit_export_sinks", "INSERT", false},
		{RetentionRole, "audit_export_sinks", "DELETE", false},
		{AppRole, "audit_anchors", "SELECT", true}, {AppRole, "audit_anchors", "INSERT", false},
		{PlatformRole, "audit_anchors", "SELECT", true}, {PlatformRole, "audit_anchors", "INSERT", false},
		{PlatformRole, "audit_anchors", "DELETE", false}, {PlatformRole, "audit_events", "DELETE", false},
		{AppRole, "audit_events", "DELETE", false}, {IdentityRole, "audit_events", "DELETE", false},
		{IdentityRole, "audit_anchors", "SELECT", false},
	} {
		var got bool
		if err := owner.QueryRow(`SELECT has_table_privilege($1, $2, $3)`, c.role, c.table, c.priv).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s %s on %s = %v, want %v", c.role, c.priv, c.table, got, c.want)
		}
	}
	// On tenants: the two columns it needs, read-only.
	for col, want := range map[string]bool{"id": true, "audit_retention_days": true, "name": false, "slug": false} {
		var got bool
		if err := owner.QueryRow(`SELECT has_column_privilege($1, 'tenants', $2, 'SELECT')`, RetentionRole, col).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("retention SELECT tenants.%s = %v, want %v", col, got, want)
		}
	}
	var tw bool
	if err := owner.QueryRow(`SELECT has_any_column_privilege($1, 'tenants', 'INSERT,UPDATE') OR has_table_privilege($1, 'tenants', 'DELETE,TRUNCATE')`, RetentionRole).Scan(&tw); err != nil || tw {
		t.Errorf("retention login may write tenants (%v)", err)
	}
	// The tenant pool may change only its retention setting (and updated_at).
	for col, want := range map[string]bool{"audit_retention_days": true, "updated_at": true, "name": false, "slug": false, "id": false} {
		var got bool
		if err := owner.QueryRow(`SELECT has_column_privilege($1, 'tenants', $2, 'UPDATE')`, AppRole, col).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("tenant pool UPDATE tenants.%s = %v, want %v", col, got, want)
		}
	}
	// Nothing else: the retention login touches only the audit tables.
	var others []string
	rows, err := owner.Query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'
		  AND c.relname NOT IN ('audit_events', 'audit_anchors', 'audit_export_cursors', 'audit_export_sinks', 'tenants')
		  AND (has_table_privilege($1, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
		    OR has_any_column_privilege($1, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))`, RetentionRole)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		others = append(others, n)
	}
	if len(others) != 0 {
		t.Errorf("retention login has privileges on %v", others)
	}
}
