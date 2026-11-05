package retention

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	d     *store.DB
	r     *store.Retention
	owner *sql.DB
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	r, err := store.OpenRetention(ctx, env.RetentionURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return fixture{d: d, r: r, owner: owner}
}

func (f fixture) tenant(t *testing.T, days *int) string {
	t.Helper()
	var id string
	if err := f.d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		c := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T")
		if days != nil {
			c.SetAuditRetentionDays(*days)
		}
		x, err := c.Save(context.Background())
		if err == nil {
			id = x.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// chain appends entries with the given ages (oldest first), hash-chained like
// audit.Record, written as the owner so they can be backdated.
func (f fixture) chain(t *testing.T, tn string, ages ...time.Duration) {
	t.Helper()
	var prev []byte
	var seq int64
	_ = f.owner.QueryRow(`SELECT COALESCE(max(seq), 0) FROM audit_events WHERE tenant_id = $1`, tn).Scan(&seq)
	if seq > 0 {
		_ = f.owner.QueryRow(`SELECT hash FROM audit_events WHERE tenant_id = $1 AND seq = $2`, tn, seq).Scan(&prev)
	} else {
		prev = make([]byte, 32)
	}
	for _, age := range ages {
		seq++
		e := &ent.AuditEvent{ID: ids.AuditEvent(), TenantID: tn, Seq: seq, OccurredAt: time.Now().Add(-age).UTC().Truncate(time.Microsecond),
			ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess, Details: "{}", PrevHash: prev}
		e.Hash = audit.Hash(e)
		if _, err := f.owner.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, $3, $4, 'system', 'test.entry', 'success', '{}', $5, $6)`, e.ID, tn, seq, e.OccurredAt, prev, e.Hash); err != nil {
			t.Fatal(err)
		}
		prev = e.Hash
	}
}

func ages(n int, d time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

const (
	old   = 400 * 24 * time.Hour
	young = 10 * 24 * time.Hour
)

func days(n int) *int { return &n }

func (f fixture) seqs(t *testing.T, tn string) (first, last int64, n int) {
	t.Helper()
	if err := f.owner.QueryRow(`SELECT COALESCE(min(seq),0), COALESCE(max(seq),0), count(*) FROM audit_events WHERE tenant_id = $1`, tn).Scan(&first, &last, &n); err != nil {
		t.Fatal(err)
	}
	return
}

func (f fixture) verify(t *testing.T, tn string) audit.Head {
	t.Helper()
	h, err := audit.Verify(context.Background(), f.d.ReadPlatform, tn, audit.Head{})
	if err != nil {
		t.Fatalf("Verify after the prune: %v", err)
	}
	return h
}

func cutsOf(cuts []Cut, tn string) []string {
	var out []string
	for _, c := range cuts {
		if c.TenantID == tn {
			out = append(out, fmt.Sprintf("%d:%d", c.Through, c.Deleted))
		}
	}
	return out
}

func TestPruneCutsTheOldPrefix(t *testing.T) {
	f := setup(t)
	tn := f.tenant(t, days(365))
	f.chain(t, tn, append(ages(10, old), ages(3, young)...)...)
	empty := f.tenant(t, days(365)) // a chain without entries: nothing to do
	keep := f.tenant(t, nil)        // no retention: kept whole
	f.chain(t, keep, ages(4, old)...)
	cuts, err := Prune(context.Background(), f.r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(cutsOf(cuts, tn)); got != "[10:10]" {
		t.Errorf("cuts %s, want one through 10", got)
	}
	if first, last, n := f.seqs(t, tn); first != 11 || last != 14 || n != 4 {
		t.Errorf("chain now %d..%d (%d), want 11..13 plus the retention entry 14", first, last, n)
	}
	if h := f.verify(t, tn); h.Seq != 14 {
		t.Errorf("head %d", h.Seq)
	}
	var action, details string
	if err := f.owner.QueryRow(`SELECT action, details FROM audit_events WHERE tenant_id = $1 AND seq = 14`, tn).Scan(&action, &details); err != nil {
		t.Fatal(err)
	}
	var h10 []byte
	_ = f.owner.QueryRow(`SELECT hash FROM audit_anchors WHERE tenant_id = $1 AND seq = 10`, tn).Scan(&h10)
	want := fmt.Sprintf(`{"deleted":10,"retention_days":365,"through_hash":"%s","through_seq":10}`, hex.EncodeToString(h10))
	if action != "audit.retention" || details != want || len(h10) != 32 {
		t.Errorf("retention entry %s %s, want %s", action, details, want)
	}
	if len(cutsOf(cuts, empty)) != 0 {
		t.Errorf("cut an empty chain: %v", cutsOf(cuts, empty))
	}
	if _, _, n := f.seqs(t, keep); n != 4 {
		t.Errorf("a tenant without retention lost entries: %d left", n)
	}
	// A second run finds nothing more to cut.
	if cuts, err := Prune(context.Background(), f.r, 0); err != nil || len(cutsOf(cuts, tn)) != 0 {
		t.Errorf("second run: %v %v", cuts, err)
	}
}

// The chain's last entry stays, so the retention entry links to a survivor.
func TestPruneKeepsTheLastEntry(t *testing.T) {
	f := setup(t)
	tn := f.tenant(t, days(365))
	f.chain(t, tn, ages(5, old)...)
	cuts, err := Prune(context.Background(), f.r, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The first cut stops before the last entry (5). Its retention entry (6)
	// is then the last, so a second batch may cut 5 and links entry 7 to 6.
	if got := fmt.Sprint(cutsOf(cuts, tn)); got != "[4:4 5:1]" {
		t.Errorf("cuts %s", got)
	}
	if first, last, _ := f.seqs(t, tn); first != 6 || last != 7 {
		t.Errorf("chain now %d..%d, want the retention entries 6 and 7", first, last)
	}
	f.verify(t, tn)
}

func TestPruneInBatches(t *testing.T) {
	old := batch
	batch = 3
	t.Cleanup(func() { batch = old })
	f := setup(t)
	tn := f.tenant(t, days(365))
	f.chain(t, tn, append(ages(10, 400*24*time.Hour), young)...)
	cuts, err := Prune(context.Background(), f.r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(cutsOf(cuts, tn)); got != "[3:3 6:3 9:3 10:1]" {
		t.Errorf("cuts %s", got)
	}
	if h := f.verify(t, tn); h.Seq != 15 { // 11 entries + 4 retention entries
		t.Errorf("head %d", h.Seq)
	}
}

// Nothing a registered sink hasn't delivered is cut; a sink without a cursor
// for the chain holds it at 0.
func TestPruneStopsAtTheExportGate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tn := f.tenant(t, days(365))
	f.chain(t, tn, ages(10, old)...)
	sink := "test-" + storetest.Suffix()
	if _, err := f.owner.Exec(`INSERT INTO audit_export_sinks (id, created_at) VALUES ($1, now())`, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM audit_export_sinks WHERE id = $1`, sink) })
	if cuts, err := Prune(ctx, f.r, 0); err != nil || len(cutsOf(cuts, tn)) != 0 {
		t.Fatalf("with a sink that has no cursor: %v %v", cutsOf(cuts, tn), err)
	}
	if _, err := f.owner.Exec(`INSERT INTO audit_export_cursors (id, tenant_id, sink_id, seq) VALUES ($1, $2, $3, 4)`, ids.AuditExportCursor(), tn, sink); err != nil {
		t.Fatal(err)
	}
	cuts, err := Prune(ctx, f.r, 0)
	if err != nil || fmt.Sprint(cutsOf(cuts, tn)) != "[4:4]" {
		t.Errorf("with the cursor at 4: %v %v", cutsOf(cuts, tn), err)
	}
}

// A prefix that isn't what the cut expects (an entry missing) rolls the batch
// back: no anchor, nothing deleted.
func TestPruneCountCheck(t *testing.T) {
	f := setup(t)
	tn := f.tenant(t, days(365))
	f.chain(t, tn, ages(10, old)...)
	if _, err := f.owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 5`, tn); err != nil {
		t.Fatal(err)
	}
	other := f.tenant(t, days(365)) // a healthy chain is still pruned
	f.chain(t, other, ages(3, old)...)
	t.Cleanup(func() { _, _ = f.owner.Exec(`UPDATE tenants SET audit_retention_days = NULL WHERE id = $1`, tn) })
	cuts, err := Prune(context.Background(), f.r, 0)
	if !errors.Is(err, ErrCountMismatch) {
		t.Errorf("Prune = %v, want ErrCountMismatch", err)
	}
	if len(cutsOf(cuts, other)) == 0 {
		t.Error("one broken chain stopped the others")
	}
	var anchors int
	_ = f.owner.QueryRow(`SELECT count(*) FROM audit_anchors WHERE tenant_id = $1`, tn).Scan(&anchors)
	if _, _, n := f.seqs(t, tn); n != 9 || anchors != 0 {
		t.Errorf("after a mismatch: %d entries, %d anchors; want 9, 0", n, anchors)
	}
}

func TestPrunePlatformChain(t *testing.T) {
	f := setup(t)
	f.chain(t, audit.PlatformTenant, append(ages(3, 800*24*time.Hour), ages(2, old)...)...)
	if _, err := Prune(context.Background(), f.r, 100); !errors.Is(err, ErrInvalid) {
		t.Errorf("platform retention below 365: %v", err)
	}
	if cuts, err := Prune(context.Background(), f.r, 0); err != nil || len(cutsOf(cuts, audit.PlatformTenant)) != 0 {
		t.Errorf("platform retention unset: %v %v", cutsOf(cuts, audit.PlatformTenant), err)
	}
	cuts, err := Prune(context.Background(), f.r, 500) // the 800-day entries go, the 400-day ones stay
	if err != nil {
		t.Fatal(err)
	}
	if got := cutsOf(cuts, audit.PlatformTenant); len(got) != 1 || got[0][len(got[0])-2:] != ":3" {
		t.Errorf("platform cuts %v", got)
	}
	f.verify(t, audit.PlatformTenant)
}

func TestSetTenantRetention(t *testing.T) {
	f := setup(t)
	tn := f.tenant(t, nil)
	as := func(role authz.Role) context.Context {
		return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: ids.User(), TenantID: tn, Role: role, Scope: authz.Scope{All: true}})
	}
	get := func() (d sql.NullInt64) {
		_ = f.owner.QueryRow(`SELECT audit_retention_days FROM tenants WHERE id = $1`, tn).Scan(&d)
		return d
	}
	if err := SetTenantRetention(as(authz.Admin), f.d, days(400)); !errors.Is(err, authz.ErrDenied) || get().Valid {
		t.Errorf("admin: %v, %v", err, get())
	}
	if err := SetTenantRetention(as(authz.Owner), f.d, days(100)); !errors.Is(err, ErrInvalid) || get().Valid {
		t.Errorf("100 days: %v, %v", err, get())
	}
	if err := SetTenantRetention(as(authz.Owner), f.d, days(400)); err != nil || get().Int64 != 400 {
		t.Errorf("owner, 400 days: %v, %v", err, get())
	}
	if err := SetTenantRetention(as(authz.Owner), f.d, nil); err != nil || get().Valid {
		t.Errorf("owner, keep everything: %v, %v", err, get())
	}
	var outcomes string
	if err := f.owner.QueryRow(`SELECT string_agg(outcome || ':' || (details::jsonb->>'days'), ',' ORDER BY seq) FROM audit_events
		WHERE tenant_id = $1 AND action = 'tenant.audit_retention.update'`, tn).Scan(&outcomes); err != nil {
		t.Fatal(err)
	}
	if outcomes != "denied:400,success:400" && outcomes != "denied:400,success:400,success:" {
		t.Errorf("audited %q", outcomes)
	}
	// The database refuses short periods and other columns too.
	if err := f.d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
		return tx.Tenant.UpdateOneID(tn).SetAuditRetentionDays(30).Exec(context.Background())
	}); err == nil {
		t.Error("tenant pool stored 30 days")
	}
	if err := f.d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
		return tx.Tenant.UpdateOneID(tn).SetName("renamed").Exec(context.Background())
	}); err == nil {
		t.Error("tenant pool renamed itself")
	}
}
