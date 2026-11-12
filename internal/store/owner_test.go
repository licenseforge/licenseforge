package store

import (
	"context"
	"errors"
	"slices"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// The way out when no platform admin can sign in (ADR-0031): the owner login
// empties the admin set, in one audited transaction, and bootstrap opens again.
func TestOwnerResetPlatformAdmins(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	emptyAdmins(t, f)
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, noAudit); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if err := f.d.GrantPlatformAdmin(ctx, f.ownerB, f.ownerA, noAudit); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwner(ctx, env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	// A failed audit write changes nothing.
	if _, err := o.ResetPlatformAdmins(ctx, func(*ent.Tx, []string) error { return context.Canceled }); err == nil || f.admins(t) != 2 {
		t.Fatalf("reset with a failed record: %v, %d admins", err, f.admins(t))
	}
	var recorded []string
	removed, err := o.ResetPlatformAdmins(ctx, func(_ *ent.Tx, r []string) error { recorded = r; return nil })
	slices.Sort(removed)
	want := []string{f.ownerA, f.ownerB}
	slices.Sort(want)
	if err != nil || !slices.Equal(removed, want) || !slices.Equal(recorded, removed) || f.admins(t) != 0 {
		t.Fatalf("reset = %v %v (recorded %v), %d admins left", removed, err, recorded, f.admins(t))
	}
	// Bootstrap is open again, for the configured bootstrap user only once.
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerB, noAudit); !ok || err != nil {
		t.Errorf("bootstrap after reset: %v %v", ok, err)
	}
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, noAudit); ok || err != nil {
		t.Errorf("second bootstrap: %v %v", ok, err)
	}
}

// A sink no longer exported stops holding retention back once removed; an
// unknown name changes nothing.
func TestOwnerRemoveExportSink(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	f.owner(t, `INSERT INTO audit_export_sinks (id, created_at) VALUES ('old-siem', now()), ('kept-siem', now())`)
	t.Cleanup(func() {
		f.owner(t, `DELETE FROM audit_export_cursors WHERE sink_id IN ('old-siem', 'kept-siem')`)
		f.owner(t, `DELETE FROM audit_export_sinks WHERE id IN ('old-siem', 'kept-siem')`)
	})
	f.owner(t, `INSERT INTO audit_export_cursors (id, sink_id, tenant_id, seq) VALUES ($3, 'old-siem', $1, 0), ($4, 'old-siem', $2, 0), ($5, 'kept-siem', $1, 0)`,
		f.a, f.b, ids.New("aec"), ids.New("aec"), ids.New("aec"))
	o, err := OpenOwner(ctx, env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	called := false
	if err := o.RemoveExportSink(ctx, "no-such", func(*ent.Tx, int) error { called = true; return nil }); !errors.Is(err, ErrNoSuchSink) || called {
		t.Errorf("unknown sink: %v, recorded %v", err, called)
	}
	if err := o.RemoveExportSink(ctx, "old-siem", func(*ent.Tx, int) error { return context.Canceled }); err == nil {
		t.Error("a failed record must roll back")
	}
	dropped := -1
	if err := o.RemoveExportSink(ctx, "old-siem", func(_ *ent.Tx, n int) error { dropped = n; return nil }); err != nil || dropped != 2 {
		t.Fatalf("remove = %v, %d cursors", err, dropped)
	}
	var sinks, cursors int
	if err := o.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM audit_export_sinks WHERE id IN ('old-siem', 'kept-siem')),
		(SELECT count(*) FROM audit_export_cursors WHERE sink_id IN ('old-siem', 'kept-siem'))`).Scan(&sinks, &cursors); err != nil || sinks != 1 || cursors != 1 {
		t.Errorf("left: %d sinks, %d cursors, %v", sinks, cursors, err)
	}
}
