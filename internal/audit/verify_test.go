package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// smallPages makes Verify page every n entries for the test.
func smallPages(t *testing.T, n int) {
	old := pageSize
	pageSize = n
	t.Cleanup(func() { pageSize = old })
}

// chain records n entries in a new tenant's chain and returns them.
func chain(t *testing.T, d *store.DB, n int) (string, []*ent.AuditEvent) {
	t.Helper()
	tn := newTenant(t, d)
	var es []*ent.AuditEvent
	for range n {
		es = append(es, record(t, d, tn, Event{ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess}))
	}
	return tn, es
}

type txLog struct{ snapshots, plain int }

// counting wraps run and counts its transactions.
func counting(run Runner, l *txLog) Runner {
	return func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
		if snap {
			l.snapshots++
		} else {
			l.plain++
		}
		return run(ctx, snap, fn)
	}
}

func headOf(e *ent.AuditEvent) Head { return Head{Seq: e.Seq, Hash: e.Hash} }

func TestVerifyPages(t *testing.T) {
	smallPages(t, 7)
	d := openDB(t)
	tn, es := chain(t, d, 30)
	var l txLog
	h, err := Verify(context.Background(), counting(tenantRunner(d, tn), &l), tn, Head{})
	if err != nil || h.Seq != 30 || !bytes.Equal(h.Hash, es[29].Hash) {
		t.Fatalf("Verify = %+v, %v", h, err)
	}
	// Pages 1-7 (with the anchor, one snapshot), 8-14, 15-21, 22-28, 29-30.
	if l.snapshots != 1 || l.plain != 4 {
		t.Errorf("transactions: %+v, want 1 snapshot and 4 pages", l)
	}
	// An exact multiple of the page size ends with one empty page.
	smallPages(t, 10)
	if h, err := Verify(context.Background(), tenantRunner(d, tn), tn, Head{}); err != nil || h.Seq != 30 {
		t.Errorf("Verify with 3 full pages = %+v, %v", h, err)
	}
}

func TestVerifyResumes(t *testing.T) {
	smallPages(t, 7)
	d := openDB(t)
	tn, es := chain(t, d, 30)
	run := tenantRunner(d, tn)
	var l txLog
	h, err := Verify(context.Background(), counting(run, &l), tn, headOf(es[19]))
	if err != nil || h.Seq != 30 || !bytes.Equal(h.Hash, es[29].Hash) {
		t.Fatalf("resume from 20 = %+v, %v", h, err)
	}
	if l.snapshots+l.plain != 2 { // 21-27, 28-30: only the new entries
		t.Errorf("resume read %+v transactions, want 2", l)
	}
	// Up to date: the head comes back unchanged.
	if h, err := Verify(context.Background(), run, tn, headOf(es[29])); err != nil || h.Seq != 30 {
		t.Errorf("resume from the head = %+v, %v", h, err)
	}
	// A head that isn't the chain's (wrong hash), or whose entry was changed since, fails.
	bad := headOf(es[19])
	bad.Hash = es[18].Hash
	if _, err := Verify(context.Background(), run, tn, bad); !errors.Is(err, ErrBroken) {
		t.Errorf("resume from a wrong hash: %v", err)
	}
	bad = headOf(es[29]) // at the chain's head no next entry's link would catch it
	bad.Hash = es[28].Hash
	if _, err := Verify(context.Background(), run, tn, bad); !errors.Is(err, ErrBroken) {
		t.Errorf("resume from a wrong hash at the head: %v", err)
	}
	owner := sqlDB(t, env.OwnerURL)
	if _, err := owner.Exec(`UPDATE audit_events SET details = '{"x":1}' WHERE tenant_id = $1 AND seq = 20`, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), run, tn, headOf(es[19])); err == nil || !strings.Contains(err.Error(), "resume head seq 20 was modified") {
		t.Errorf("resume from a modified head: %v", err)
	}
}

// Tampering is found on any page, including a removed entry at a page boundary.
func TestVerifyDetectsTamperingOnLaterPages(t *testing.T) {
	smallPages(t, 7)
	d := openDB(t)
	owner := sqlDB(t, env.OwnerURL)
	for _, c := range []struct{ stmt, want string }{
		{`UPDATE audit_events SET action = 'test.other' WHERE tenant_id = $1 AND seq = 25`, "seq 25 was modified"},
		{`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 15`, "seq 16 doesn't follow seq 14"}, // first of page 3
		{`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 18`, "seq 19 doesn't follow seq 17"}, // inside page 3
	} {
		tn, _ := chain(t, d, 30)
		if _, err := owner.Exec(c.stmt, tn); err != nil {
			t.Fatal(err)
		}
		before := testutil.ToFloat64(metrics.AuditVerifyFailures)
		_, err := Verify(context.Background(), tenantRunner(d, tn), tn, Head{})
		if !errors.Is(err, ErrBroken) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.stmt, err, c.want)
		}
		if got := testutil.ToFloat64(metrics.AuditVerifyFailures); got != before+1 {
			t.Errorf("verify failures %v→%v", before, got)
		}
	}
}

// A prune between pages (simulated: the prefix deleted and the anchor moved)
// breaks the next page's start; Verify re-reads the anchor and restarts from it.
func TestVerifyRestartsAfterAPrune(t *testing.T) {
	smallPages(t, 7)
	d := openDB(t)
	tn, es := chain(t, d, 30)
	owner := sqlDB(t, env.OwnerURL)
	old := readAnchor
	t.Cleanup(func() { readAnchor = old })
	for _, moved := range []bool{true, false} {
		var anchor Head
		readAnchor = func(context.Context, *ent.Tx, string) (Head, error) { return anchor, nil }
		tn, es := tn, es
		if !moved {
			tn, es = chain(t, d, 30)
		}
		calls := 0
		run := func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
			if calls++; calls == 2 { // after the first page: prune through seq 10
				if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= 10`, tn); err != nil {
					t.Fatal(err)
				}
				if moved {
					anchor = headOf(es[9])
				}
			}
			return tenantRunner(d, tn)(ctx, snap, fn)
		}
		h, err := Verify(context.Background(), run, tn, Head{})
		if moved && (err != nil || h.Seq != 30) {
			t.Errorf("after a prune that moved the anchor: %+v, %v", h, err)
		}
		if !moved && !errors.Is(err, ErrBroken) {
			t.Errorf("entries gone without an anchor: %v", err)
		}
	}
	// Entries at or below the anchor must not remain.
	tn2, es2 := chain(t, d, 12)
	anchor := headOf(es2[4])
	readAnchor = func(context.Context, *ent.Tx, string) (Head, error) { return anchor, nil }
	if _, err := Verify(context.Background(), tenantRunner(d, tn2), tn2, Head{}); err == nil || !strings.Contains(err.Error(), "at or below the anchor") {
		t.Errorf("entries below the anchor: %v", err)
	}
	// With them gone, the chain verifies from the anchor.
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= 5`, tn2); err != nil {
		t.Fatal(err)
	}
	if h, err := Verify(context.Background(), tenantRunner(d, tn2), tn2, Head{}); err != nil || h.Seq != 12 {
		t.Errorf("from the anchor: %+v, %v", h, err)
	}
}

func TestWriteFailuresAreCounted(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	tenant, platform := metrics.AuditWriteFailures.WithLabelValues("tenant"), metrics.AuditWriteFailures.WithLabelValues("platform")
	bt, bp := testutil.ToFloat64(tenant), testutil.ToFloat64(platform)
	bad := Event{ActorType: auditevent.ActorTypeUser, Action: "x.y", Outcome: auditevent.OutcomeSuccess, SourceIP: "nope"}
	if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error { _, err := Record(context.Background(), tx, tn, bad); return err }); err == nil {
		t.Fatal("invalid entry recorded")
	}
	ok := Event{ActorType: auditevent.ActorTypeUser, Action: "x.y", Outcome: auditevent.OutcomeSuccess}
	if err := d.WithTenant(context.Background(), PlatformTenant, func(tx *ent.Tx) error {
		_, err := Record(context.Background(), tx, PlatformTenant, ok) // the tenant pool can't write the platform chain
		return err
	}); err == nil {
		t.Fatal("tenant pool wrote the platform chain")
	}
	record(t, d, tn, ok) // a success counts nothing
	if gt, gp := testutil.ToFloat64(tenant), testutil.ToFloat64(platform); gt != bt+1 || gp != bp+1 {
		t.Errorf("write failures: tenant %v→%v, platform %v→%v", bt, gt, bp, gp)
	}
}

// A resume head that was deleted is reported; one older than an anchor that
// moved during the run restarts from the anchor.
func TestVerifyResumeHeadGoneOrPruned(t *testing.T) {
	smallPages(t, 7)
	d := openDB(t)
	owner := sqlDB(t, env.OwnerURL)
	tn, es := chain(t, d, 30)
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq >= 25`, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), tenantRunner(d, tn), tn, headOf(es[29])); err == nil || !strings.Contains(err.Error(), "resume head seq 30 is gone") {
		t.Errorf("resume from a deleted head: %v", err)
	}

	old := readAnchor
	t.Cleanup(func() { readAnchor = old })
	tn, es = chain(t, d, 30)
	var anchor Head
	readAnchor = func(context.Context, *ent.Tx, string) (Head, error) { return anchor, nil }
	calls := 0
	run := func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
		if calls++; calls == 2 { // after the first page from head 10: prune through 20
			if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= 20`, tn); err != nil {
				t.Fatal(err)
			}
			anchor = headOf(es[19])
		}
		return tenantRunner(d, tn)(ctx, snap, fn)
	}
	if h, err := Verify(context.Background(), run, tn, headOf(es[9])); err != nil || h.Seq != 30 {
		t.Errorf("resume with the anchor moving past the head: %+v, %v", h, err)
	}
	// Resuming exactly at the anchor needs the anchor's hash.
	if h, err := Verify(context.Background(), tenantRunner(d, tn), tn, headOf(es[19])); err != nil || h.Seq != 30 {
		t.Errorf("resume at the anchor: %+v, %v", h, err)
	}
	bad := headOf(es[19])
	bad.Hash = es[18].Hash
	if _, err := Verify(context.Background(), tenantRunner(d, tn), tn, bad); err == nil || !strings.Contains(err.Error(), "doesn't match the anchor") {
		t.Errorf("resume at the anchor with another hash: %v", err)
	}
}

// Only broken chains count as verify failures, not errors such as a
// cancelled context or a failing runner; a write that fails because the
// caller went away is no audit write failure either.
func TestPlainErrorsAreNotAuditFailures(t *testing.T) {
	d := openDB(t)
	tn, _ := chain(t, d, 3)
	before := testutil.ToFloat64(metrics.AuditVerifyFailures)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, tenantRunner(d, tn), tn, Head{}); err == nil || errors.Is(err, ErrBroken) {
		t.Errorf("cancelled: %v", err)
	}
	failing := func(context.Context, bool, func(*ent.Tx) error) error { return errors.New("pool closed") }
	if _, err := Verify(context.Background(), failing, tn, Head{}); err == nil || errors.Is(err, ErrBroken) {
		t.Errorf("failing runner: %v", err)
	}
	if got := testutil.ToFloat64(metrics.AuditVerifyFailures); got != before {
		t.Errorf("verify failures %v→%v", before, got)
	}

	writes := metrics.AuditWriteFailures.WithLabelValues("tenant")
	wb := testutil.ToFloat64(writes)
	if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Record(ctx, tx, tn, Event{ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess})
		return err
	}); err == nil {
		t.Fatal("Record with a cancelled context succeeded")
	}
	if got := testutil.ToFloat64(writes); got != wb {
		t.Errorf("write failures %v→%v after a client went away", wb, got)
	}
}

// Verify starts at the chain's real anchor (audit_anchors), on the tenant
// and the platform pool.
func TestVerifyFromStoredAnchor(t *testing.T) {
	d := openDB(t)
	tn, es := chain(t, d, 10)
	owner := sqlDB(t, env.OwnerURL)
	// As the retention job would: anchor at 4, then the prefix removed (the
	// owner here, as the entries are too young for the retention login).
	if _, err := owner.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 4, $3, now())`,
		ids.AuditAnchor(), tn, es[3].Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), tenantRunner(d, tn), tn, Head{}); err == nil || !strings.Contains(err.Error(), "at or below the anchor") {
		t.Errorf("entries below the stored anchor: %v", err)
	}
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= 4`, tn); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]Runner{"tenant": tenantRunner(d, tn), "platform": d.ReadPlatform} {
		if h, err := Verify(context.Background(), run, tn, Head{}); err != nil || h.Seq != 10 {
			t.Errorf("%s pool from the stored anchor: %+v, %v", name, h, err)
		}
	}
	// A later anchor wins; one with a wrong hash breaks the first link.
	if _, err := owner.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 6, $3, now())`,
		ids.AuditAnchor(), tn, es[4].Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= 6`, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), tenantRunner(d, tn), tn, Head{}); !errors.Is(err, ErrBroken) {
		t.Errorf("anchor with the wrong hash: %v", err)
	}
}
