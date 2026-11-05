package auditverify

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

func setup(t *testing.T) (*store.DB, *Job, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	owner, err := sql.Open("pgx", env.OwnerURL) // a database attacker's view
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return d, New(d, slog.New(slog.NewTextHandler(io.Discard, nil))), owner
}

// chain creates a tenant with n entries and returns it and its head.
func chain(t *testing.T, d *store.DB, n int) string {
	t.Helper()
	ctx := context.Background()
	var tn string
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		x, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
		if err == nil {
			tn = x.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	add(t, d, tn, n)
	return tn
}

func add(t *testing.T, d *store.DB, tn string, n int) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	for range n {
		if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
			var err error
			e, err = audit.Record(context.Background(), tx, tn, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

type checkpoint struct {
	Mode    string   `json:"mode"`
	Batch   int      `json:"batch"`
	Batches int      `json:"batches"`
	Heads   []head   `json:"heads"`
	Broken  []string `json:"broken"`
}

// checkpoints returns the platform chain's checkpoint entries after seq.
func checkpoints(t *testing.T, d *store.DB, after int64) ([]*ent.AuditEvent, []checkpoint) {
	t.Helper()
	var es []*ent.AuditEvent
	if err := d.ReadPlatform(context.Background(), false, func(tx *ent.Tx) error {
		var err error
		es, err = tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.Action("audit.checkpoint"),
			auditevent.SeqGT(after)).Order(ent.Asc(auditevent.FieldSeq)).All(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var cs []checkpoint
	for _, e := range es {
		var c checkpoint
		if err := json.Unmarshal([]byte(e.Details), &c); err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	return es, cs
}

func platformHead(t *testing.T, d *store.DB) int64 {
	t.Helper()
	h, err := audit.Verify(context.Background(), d.ReadPlatform, audit.PlatformTenant, audit.Head{})
	if err != nil {
		t.Fatal(err)
	}
	return h.Seq
}

func headFor(cs []checkpoint, tn string) (head, bool) {
	for _, c := range cs {
		for _, h := range c.Heads {
			if h.TenantID == tn {
				return h, true
			}
		}
	}
	return head{}, false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// tamper runs do as the owner and undo when the test ends, so other tests
// on the shared database see an intact chain.
func tamper(t *testing.T, owner *sql.DB, do, undo, tn string) {
	t.Helper()
	if _, err := owner.Exec(do, tn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(undo, tn); err != nil {
			t.Error(err)
		}
	})
}

func TestCheckpointWritten(t *testing.T) {
	d, j, _ := setup(t)
	a, b := chain(t, d, 3), chain(t, d, 1)
	last := add(t, d, a, 1)
	if err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error { // so the platform chain isn't empty
		_, err := audit.Record(context.Background(), tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "test.entry", Outcome: auditevent.OutcomeSuccess})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := platformHead(t, d)
	r, err := j.Once(context.Background())
	if err != nil || !r.Ran || !r.Full || contains(r.Broken, a) || contains(r.Broken, b) || r.Verified < 2 {
		t.Fatalf("Once = %+v, %v", r, err)
	}
	es, cs := checkpoints(t, d, before)
	if len(cs) != 1 || cs[0].Mode != "full" || cs[0].Batch != 1 || cs[0].Batches != 1 || es[0].Outcome != auditevent.OutcomeSuccess ||
		es[0].ActorType != auditevent.ActorTypeSystem {
		t.Fatalf("checkpoints %+v", cs)
	}
	if h, ok := headFor(cs, a); !ok || h.Seq != 4 || h.Hash != hex.EncodeToString(last.Hash) {
		t.Errorf("head of a: %+v %v, want seq 4 %x", h, ok, last.Hash)
	}
	if h, ok := headFor(cs, b); !ok || h.Seq != 1 {
		t.Errorf("head of b: %+v %v", h, ok)
	}
	if h, ok := headFor(cs, audit.PlatformTenant); before > 0 && (!ok || h.Seq != before) {
		t.Errorf("the platform chain's own head: %+v %v, want seq %d", h, ok, before)
	}
	// The checkpoint is a chained platform entry like any other.
	if platformHead(t, d) != es[len(es)-1].Seq {
		t.Error("checkpoint isn't the platform chain's head")
	}
}

// After a first run, the job resumes from the heads it verified: an entry
// changed below a verified head isn't re-read, until the weekly full run.
func TestResumesFromVerifiedHeads(t *testing.T) {
	d, j, owner := setup(t)
	ck := time.Now()
	j.now = func() time.Time { return ck }
	a := chain(t, d, 3)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := add(t, d, a, 2)
	tamper(t, owner, `UPDATE audit_events SET action = 'test.tampered' WHERE tenant_id = $1 AND seq = 1`,
		`UPDATE audit_events SET action = 'test.entry' WHERE tenant_id = $1 AND seq = 1`, a)
	before := platformHead(t, d)
	r, err := j.Once(context.Background())
	if err != nil || r.Full || contains(r.Broken, a) {
		t.Fatalf("incremental run = %+v, %v (only entries after the verified head are read)", r, err)
	}
	_, cs := checkpoints(t, d, before)
	if h, _ := headFor(cs, a); len(cs) != 1 || cs[0].Mode != "incremental" || h.Seq != 5 || h.Hash != hex.EncodeToString(last.Hash) {
		t.Errorf("incremental checkpoint %+v", cs)
	}
	ck = ck.Add(j.FullInterval) // the full run is due
	r, err = j.Once(context.Background())
	if err != nil || !r.Full || !contains(r.Broken, a) {
		t.Errorf("full run = %+v, %v; want a broken", r, err)
	}
}

// A tampered entry after the verified head breaks the chain: the metric
// counts it, the checkpoint records it, and the next run checks again.
func TestTamperedEntryFiresTheMetric(t *testing.T) {
	d, j, owner := setup(t)
	a := chain(t, d, 2)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	good := j.heads[a]
	add(t, d, a, 2)
	tamper(t, owner, `UPDATE audit_events SET details = '{"x":1}' WHERE tenant_id = $1 AND seq = 4`,
		`UPDATE audit_events SET details = '{}' WHERE tenant_id = $1 AND seq = 4`, a)
	failures := testutil.ToFloat64(metrics.AuditVerifyFailures)
	before := platformHead(t, d)
	r, err := j.Once(context.Background())
	if err != nil || !contains(r.Broken, a) {
		t.Fatalf("Once = %+v, %v", r, err)
	}
	if got := testutil.ToFloat64(metrics.AuditVerifyFailures); got != failures+float64(len(r.Broken)) {
		t.Errorf("verify failures %v, want %v", got, failures+float64(len(r.Broken)))
	}
	es, cs := checkpoints(t, d, before)
	if len(cs) != 1 || es[0].Outcome != auditevent.OutcomeFailure || !contains(cs[0].Broken, a) {
		t.Errorf("checkpoint %+v outcome %s", cs, es[0].Outcome)
	}
	if _, ok := headFor(cs, a); ok || j.heads[a].Seq != good.Seq {
		t.Errorf("broken chain's head moved: %+v", j.heads[a])
	}
	failures = testutil.ToFloat64(metrics.AuditVerifyFailures)
	if r, err := j.Once(context.Background()); err != nil || !contains(r.Broken, a) || testutil.ToFloat64(metrics.AuditVerifyFailures) < failures+1 {
		t.Errorf("the next run must count it again: %+v %v", r, err)
	}
}

// While one replica holds the lock, another doesn't run or write.
func TestOneReplicaAtATime(t *testing.T) {
	d, j, _ := setup(t)
	chain(t, d, 1)
	unlock, ok, err := d.TryPlatformLock(context.Background(), lockKey) // the other replica
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	before := platformHead(t, d)
	if r, err := j.Once(context.Background()); err != nil || r.Ran {
		t.Errorf("ran while another replica held the lock: %+v %v", r, err)
	}
	if es, _ := checkpoints(t, d, before); len(es) != 0 {
		t.Error("checkpoint written without the lock")
	}
	if _, ok, err := d.TryPlatformLock(context.Background(), lockKey); err != nil || ok {
		t.Errorf("second lock taken: %v %v", ok, err)
	}
	unlock()
	if r, err := j.Once(context.Background()); err != nil || !r.Ran {
		t.Errorf("after release: %+v %v", r, err)
	}
	// The run released the lock again.
	unlock, ok, err = d.TryPlatformLock(context.Background(), lockKey)
	if err != nil || !ok {
		t.Fatalf("lock after a run: %v %v", ok, err)
	}
	unlock()
}

func TestCheckpointBatches(t *testing.T) {
	d, j, _ := setup(t)
	old := HeadsPerEntry
	HeadsPerEntry = 2
	t.Cleanup(func() { HeadsPerEntry = old })
	for range 3 {
		chain(t, d, 1)
	}
	before := platformHead(t, d)
	r, err := j.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, cs := checkpoints(t, d, before)
	want := (r.Verified + 1) / 2
	if len(cs) != want {
		t.Fatalf("%d entries for %d heads, want %d", len(cs), r.Verified, want)
	}
	n := 0
	for i, c := range cs {
		if c.Batch != i+1 || c.Batches != want || len(c.Heads) > 2 {
			t.Errorf("entry %d: %+v", i, c)
		}
		n += len(c.Heads)
	}
	if n != r.Verified {
		t.Errorf("%d heads, want %d", n, r.Verified)
	}
}

func TestRunRefusesBadSchedule(t *testing.T) {
	_, j, _ := setup(t)
	j.Interval = 0
	if err := j.Run(context.Background()); err == nil {
		t.Error("interval 0 accepted")
	}
}
