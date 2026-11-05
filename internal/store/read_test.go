package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// ReadTenant and ReadPlatform (audit.Verify's runners) are read-only, take a
// snapshot only when asked, and ReadTenant stays scoped to its tenant.
func TestReadRunners(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	ts := createTenants(t, d, 2)
	a, b := ts[0].ID, ts[1].ID
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
		VALUES ($1, $2, 1, clock_timestamp(), 'system', 'test.entry', 'success', '{}', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'))`, ids.AuditEvent(), b); err != nil {
		t.Fatal(err)
	}
	runners := map[string]func(bool, func(*ent.Tx) error) error{
		"ReadTenant":   func(snap bool, fn func(*ent.Tx) error) error { return d.ReadTenant(ctx, a, snap, fn) },
		"ReadPlatform": func(snap bool, fn func(*ent.Tx) error) error { return d.ReadPlatform(ctx, snap, fn) },
	}
	for name, run := range runners {
		for snap, want := range map[bool]string{true: "repeatable read", false: "read committed"} {
			var iso string
			if err := run(snap, func(tx *ent.Tx) error {
				rows, err := tx.QueryContext(ctx, `SHOW transaction_isolation`)
				if err != nil {
					return err
				}
				if rows.Next() {
					err = rows.Scan(&iso)
				}
				return errors.Join(err, rows.Err(), rows.Close())
			}); err != nil || iso != want {
				t.Errorf("%s(snapshot=%v): isolation %q, %v; want %s", name, snap, iso, err, want)
			}
			err := run(snap, func(tx *ent.Tx) error {
				_, err := tx.ExecContext(ctx, `UPDATE tenants SET name = name WHERE id = $1`, a)
				return err
			})
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "25006" { // read_only_sql_transaction
				t.Errorf("%s(snapshot=%v): write = %v, want 25006", name, snap, err)
			}
		}
	}
	var n int
	if err := d.ReadTenant(ctx, a, true, func(tx *ent.Tx) error {
		var err error
		n, err = tx.AuditEvent.Query().Count(ctx)
		return err
	}); err != nil || n != 0 {
		t.Errorf("ReadTenant(A) sees %d audit entries (B has one), %v", n, err)
	}
	if err := d.ReadTenant(ctx, "", false, func(*ent.Tx) error { return nil }); err == nil {
		t.Error("ReadTenant without a tenant")
	}
}
