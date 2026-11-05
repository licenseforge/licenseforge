package auditverify

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
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
	j := New(d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(j.Close) // before the pool closes: the next test's job may lead
	return d, j, owner
}

// admin is a superuser connection, for pg_locks and pg_terminate_backend.
func admin(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// lockHolders lists the sessions holding the job's lock in this database.
func lockHolders(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.Query(`SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND ((classid::bigint << 32) | objid::bigint) = $1
		AND database = (SELECT oid FROM pg_database WHERE datname = $2)`, int64(lockKey), env.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var pids []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, pid)
	}
	return pids
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
	if _, ok := headFor(cs, a); ok {
		t.Errorf("broken chain listed as verified: %+v", cs)
	}
	if h := j.heads[a]; h.Seq != 2 || !j.broken[a] {
		t.Errorf("broken chain: head %+v, broken %v; want the last good head (seq 2) kept and the chain marked broken", h, j.broken[a])
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
	other, ok, err := d.TryPlatformLock(context.Background(), lockKey) // the other replica
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
	other.Release()
	if r, err := j.Once(context.Background()); err != nil || !r.Ran {
		t.Errorf("after release: %+v %v", r, err)
	}
	// The leader keeps the lock between runs: nobody else gets it.
	if _, ok, err := d.TryPlatformLock(context.Background(), lockKey); err != nil || ok {
		t.Errorf("lock free after a run: %v %v", ok, err)
	}
	j.Close()
	l, ok, err := d.TryPlatformLock(context.Background(), lockKey)
	if err != nil || !ok {
		t.Fatalf("lock after Close: %v %v", ok, err)
	}
	l.Release()
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

// The reviewer's probe: a break below a verified head, found by a full
// run, must keep being reported by the following incremental runs (the
// chain is re-verified from its anchor), not cleared after one report.
func TestBrokenBelowHeadKeepsCounting(t *testing.T) {
	d, j, owner := setup(t)
	ck := time.Now()
	j.now = func() time.Time { return ck }
	a := chain(t, d, 3)
	if _, err := j.Once(context.Background()); err != nil { // full: head at 3
		t.Fatal(err)
	}
	add(t, d, a, 2)
	if _, err := j.Once(context.Background()); err != nil { // incremental: head at 5
		t.Fatal(err)
	}
	tamper(t, owner, `UPDATE audit_events SET action = 'test.tampered' WHERE tenant_id = $1 AND seq = 2`,
		`UPDATE audit_events SET action = 'test.entry' WHERE tenant_id = $1 AND seq = 2`, a)
	ck = ck.Add(j.FullInterval)
	if r, err := j.Once(context.Background()); err != nil || !r.Full || !contains(r.Broken, a) {
		t.Fatalf("full run = %+v, %v", r, err)
	}
	for range 2 { // incremental schedule from here on
		failures := testutil.ToFloat64(metrics.AuditVerifyFailures)
		r, err := j.Once(context.Background())
		if err != nil || r.Full || !contains(r.Broken, a) || testutil.ToFloat64(metrics.AuditVerifyFailures) < failures+1 {
			t.Fatalf("incremental run after the break = %+v, %v: the break below the head must keep counting", r, err)
		}
	}
}

// Incremental runs list only chains whose head moved (and broken ones);
// full runs list every chain. Each head carries its chain's anchor.
func TestCheckpointListsMovedHeads(t *testing.T) {
	d, j, _ := setup(t)
	ck := time.Now()
	j.now = func() time.Time { return ck }
	a, b := chain(t, d, 2), chain(t, d, 2)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	add(t, d, a, 1)
	before := platformHead(t, d)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, cs := checkpoints(t, d, before)
	if h, ok := headFor(cs, a); !ok || h.Seq != 3 {
		t.Errorf("moved chain a: %+v %v", h, ok)
	}
	if _, ok := headFor(cs, b); ok {
		t.Errorf("unchanged chain b listed in an incremental checkpoint: %+v", cs)
	}
	ck = ck.Add(j.FullInterval)
	before = platformHead(t, d)
	if r, err := j.Once(context.Background()); err != nil || !r.Full {
		t.Fatalf("full run = %+v, %v", r, err)
	}
	_, cs = checkpoints(t, d, before)
	if h, ok := headFor(cs, b); !ok || h.Seq != 2 || h.Anchor.Seq != 0 || h.Anchor.Hash != "" {
		t.Errorf("full checkpoint, chain b: %+v %v", h, ok)
	}
}

func TestHeadsCarryTheAnchor(t *testing.T) {
	d, j, owner := setup(t)
	a := chain(t, d, 3)
	var first []byte
	if err := owner.QueryRow(`SELECT hash FROM audit_events WHERE tenant_id = $1 AND seq = 1`, a).Scan(&first); err != nil {
		t.Fatal(err)
	}
	// What a prune leaves: the anchor names seq 1, which is gone.
	if _, err := owner.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 1, $3, now())`, ids.AuditAnchor(), a, first); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 1`, a); err != nil {
		t.Fatal(err)
	}
	before := platformHead(t, d)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, cs := checkpoints(t, d, before)
	if h, ok := headFor(cs, a); !ok || h.Seq != 3 || h.Anchor.Seq != 1 || h.Anchor.Hash != hex.EncodeToString(first) {
		t.Errorf("head with anchor: %+v %v, want anchor 1 %x", h, ok, first)
	}
}

// The leader keeps its lock (and connection) between runs; if its
// connection drops, the lock is free and another replica takes over, and
// the old leader re-acquires once that one is gone.
func TestLeaderElection(t *testing.T) {
	d, leader, _ := setup(t)
	follower := New(d, leader.Log)
	t.Cleanup(follower.Close)
	chain(t, d, 1)
	adm := admin(t)
	if r, err := leader.Once(context.Background()); err != nil || !r.Ran {
		t.Fatalf("leader: %+v %v", r, err)
	}
	for range 2 {
		if r, err := follower.Once(context.Background()); err != nil || r.Ran {
			t.Fatalf("follower ran while the leader lives: %+v %v", r, err)
		}
		if r, err := leader.Once(context.Background()); err != nil || !r.Ran {
			t.Fatalf("leader lost the lead: %+v %v", r, err)
		}
	}
	pids := lockHolders(t, adm)
	if len(pids) != 1 {
		t.Fatalf("lock holders %v", pids)
	}
	if _, err := adm.Exec(`SELECT pg_terminate_backend($1)`, pids[0]); err != nil { // the leader's connection drops
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(lockHolders(t, adm)) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r, err := follower.Once(context.Background()); err != nil || !r.Ran {
		t.Fatalf("follower didn't take over: %+v %v", r, err)
	}
	if r, err := leader.Once(context.Background()); err != nil || r.Ran {
		t.Errorf("old leader ran beside the new one: %+v %v", r, err)
	}
	follower.Close()
	if r, err := leader.Once(context.Background()); err != nil || !r.Ran {
		t.Errorf("old leader didn't re-acquire: %+v %v", r, err)
	}
}

// Release frees the lock (seen from another session), also when the lock's
// connection is already dead, and the pool stays usable.
func TestReleaseFreesTheLock(t *testing.T) {
	d, _, _ := setup(t)
	adm := admin(t)
	l, ok, err := d.TryPlatformLock(context.Background(), lockKey)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if err := l.Alive(context.Background()); err != nil {
		t.Fatalf("Alive: %v", err)
	}
	l.Release()
	if pids := lockHolders(t, adm); len(pids) != 0 {
		t.Errorf("lock still held after Release by %v", pids)
	}
	l, ok, err = d.TryPlatformLock(context.Background(), lockKey)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	pids := lockHolders(t, adm)
	if _, err := adm.Exec(`SELECT pg_terminate_backend($1)`, pids[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := l.Alive(context.Background()); err == nil {
		t.Error("Alive on a dead connection")
	}
	l.Release() // the unlock fails: the connection is discarded, not pooled
	for range 5 {
		if err := d.ReadPlatform(context.Background(), false, func(*ent.Tx) error { return nil }); err != nil {
			t.Fatalf("pool after releasing a dead lock: %v", err)
		}
	}
}

// An incremental run that takes longer than the interval is cut off; only
// verified chains move the gauge the stall alert watches.
func TestStuckRunTimesOutAndSuccessIsTimed(t *testing.T) {
	d, j, _ := setup(t)
	chain(t, d, 1)
	if _, err := j.Once(context.Background()); err != nil { // the full pass, so the next run is incremental
		t.Fatal(err)
	}
	j.Interval = 200 * time.Millisecond
	j.verify = func(ctx context.Context, _ audit.Runner, _ string, _ audit.Head) (audit.Head, audit.Head, error) {
		<-ctx.Done() // a hung query
		return audit.Head{}, audit.Head{}, ctx.Err()
	}
	metrics.AuditVerifyLastSuccess.Set(0) // a failed run must leave it there
	before := testutil.ToFloat64(metrics.AuditVerifyLastSuccess)
	start := time.Now()
	if _, err := j.Once(context.Background()); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("stuck run: %v after %v", err, time.Since(start))
	}
	if testutil.ToFloat64(metrics.AuditVerifyLastSuccess) != before {
		t.Error("a stuck run moved the last-success gauge")
	}
	j.verify = audit.VerifyAnchored
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.AuditVerifyLastSuccess); got < float64(start.Unix()) {
		t.Errorf("last success %v, want at least %v", got, start.Unix())
	}
}

// An error on one chain that isn't a broken chain (the database) is
// reported, isn't counted as a verify failure, and a full run it spoiled is
// retried on the next run.
func TestFailedFullRunIsRetried(t *testing.T) {
	d, j, _ := setup(t)
	a := chain(t, d, 1)
	boom := errors.New("connection reset")
	j.verify = func(ctx context.Context, run audit.Runner, c string, from audit.Head) (audit.Head, audit.Head, error) {
		if c == a {
			return audit.Head{}, audit.Head{}, boom
		}
		return audit.VerifyAnchored(ctx, run, c, from)
	}
	failures := testutil.ToFloat64(metrics.AuditVerifyFailures)
	r, err := j.Once(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), a) || !r.Full || contains(r.Broken, a) {
		t.Fatalf("run with a chain error = %+v, %v", r, err)
	}
	if got := testutil.ToFloat64(metrics.AuditVerifyFailures); got != failures+float64(len(r.Broken)) {
		t.Errorf("verify failures %v, want %v (an outage is no broken chain)", got, failures+float64(len(r.Broken)))
	}
	j.verify = audit.VerifyAnchored
	if r, err := j.Once(context.Background()); err != nil || !r.Full {
		t.Errorf("the spoiled full run must be retried: %+v %v", r, err)
	}
	if r, err := j.Once(context.Background()); err != nil || r.Full {
		t.Errorf("after a successful full run: %+v %v", r, err)
	}
}

// deleteTail removes a chain's entries from seq on, as someone with the
// owner login could (truncation can't be seen from the table alone).
func deleteTail(t *testing.T, owner *sql.DB, tn string, from int) {
	t.Helper()
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq >= $2`, tn, from); err != nil {
		t.Fatal(err)
	}
}

// The reviewer's first scenario: entries removed below the verified head
// are reported on every run, not once.
func TestTruncationBelowHeadKeepsCounting(t *testing.T) {
	d, j, owner := setup(t)
	a := chain(t, d, 5)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	deleteTail(t, owner, a, 4) // the chain now ends at 3, below the verified head 5
	for i := range 3 {
		failures := testutil.ToFloat64(metrics.AuditVerifyFailures)
		r, err := j.Once(context.Background())
		if err != nil || !contains(r.Broken, a) || testutil.ToFloat64(metrics.AuditVerifyFailures) < failures+1 {
			t.Fatalf("run %d after the truncation = %+v, %v: must be reported every run", i, r, err)
		}
		if h := j.heads[a]; h.Seq != 5 {
			t.Fatalf("run %d: the last good head moved to %+v", i, h)
		}
	}
}

// The reviewer's second scenario: a truncation just before the weekly full
// run. The surviving chain verifies from the anchor on its own, so the full
// run must also check the head it verified before.
func TestTruncationBeforeFullRunIsReported(t *testing.T) {
	d, j, owner := setup(t)
	ck := time.Now()
	j.now = func() time.Time { return ck }
	a := chain(t, d, 5)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	deleteTail(t, owner, a, 4)
	ck = ck.Add(j.FullInterval)
	r, err := j.Once(context.Background())
	if err != nil || !r.Full || !contains(r.Broken, a) {
		t.Fatalf("full run after a truncation = %+v, %v: want a broken", r, err)
	}
}

// A full run gets more time than an incremental one.
func TestFullRunGetsALongerLimit(t *testing.T) {
	d, j, _ := setup(t)
	chain(t, d, 1)
	j.Interval = 100 * time.Millisecond
	j.FullTimeout = 10 * time.Second
	j.verify = func(ctx context.Context, run audit.Runner, c string, from audit.Head) (audit.Head, audit.Head, error) {
		if c == audit.PlatformTenant { // one slow chain is enough
			select {
			case <-time.After(150 * time.Millisecond):
			case <-ctx.Done():
				return audit.Head{}, audit.Head{}, ctx.Err()
			}
		}
		return audit.VerifyAnchored(ctx, run, c, from)
	}
	if r, err := j.Once(context.Background()); err != nil || !r.Full {
		t.Fatalf("full run beyond the interval: %+v, %v (needs the full run's limit)", r, err)
	}
	if _, err := j.Once(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("incremental run beyond the interval: %v, want it cut off", err)
	}
}

// A full run that runs out of time keeps what it verified: the next run
// continues the full pass with the remaining chains only (the others resume
// from their new heads), and records progress meanwhile.
func TestTimedOutFullRunResumes(t *testing.T) {
	d, j, _ := setup(t)
	x := chain(t, d, 1)
	j.FullTimeout = 300 * time.Millisecond
	stuck := true
	froms := map[string]audit.Head{}
	j.verify = func(ctx context.Context, run audit.Runner, c string, from audit.Head) (audit.Head, audit.Head, error) {
		if _, seen := froms[c]; !seen { // where the chain's verification starts (a second call checks the old head)
			froms[c] = from
		}
		if c == x && stuck {
			<-ctx.Done()
			return audit.Head{}, audit.Head{}, ctx.Err()
		}
		return audit.VerifyAnchored(ctx, run, c, from)
	}
	metrics.AuditVerifyLastSuccess.Set(0)
	before := platformHead(t, d)
	r, err := j.Once(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || !r.Full || r.Verified == 0 {
		t.Fatalf("first full run = %+v, %v", r, err)
	}
	if testutil.ToFloat64(metrics.AuditVerifyLastSuccess) == 0 {
		t.Error("no progress recorded by the partial run")
	}
	if es, _ := checkpoints(t, d, before); len(es) == 0 {
		t.Error("the partial run wrote no checkpoint")
	}
	done := map[string]bool{}
	for c := range j.heads {
		if c != x {
			done[c] = true
		}
	}
	stuck, froms = false, map[string]audit.Head{}
	r, err = j.Once(context.Background())
	if err != nil || !r.Full {
		t.Fatalf("second run = %+v, %v: the full pass must continue", r, err)
	}
	if froms[x].Seq != 0 {
		t.Errorf("the unfinished chain resumed from %+v, want its anchor", froms[x])
	}
	for c := range done {
		if froms[c].Seq == 0 && j.heads[c].Seq > 0 {
			t.Errorf("chain %s was verified from the anchor again", c)
		}
	}
	if r, err := j.Once(context.Background()); err != nil || r.Full {
		t.Errorf("after the full pass completed: %+v, %v", r, err)
	}
}

// Incremental checkpoints also list a chain whose anchor moved (retention
// cut it) even though its head didn't.
func TestIncrementalListsAnchorChange(t *testing.T) {
	d, j, owner := setup(t)
	a := chain(t, d, 3)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	var first []byte
	if err := owner.QueryRow(`SELECT hash FROM audit_events WHERE tenant_id = $1 AND seq = 1`, a).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, 1, $3, now())`, ids.AuditAnchor(), a, first); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 1`, a); err != nil {
		t.Fatal(err)
	}
	before := platformHead(t, d)
	if r, err := j.Once(context.Background()); err != nil || r.Full {
		t.Fatalf("incremental run = %+v, %v", r, err)
	}
	_, cs := checkpoints(t, d, before)
	if h, ok := headFor(cs, a); !ok || h.Seq != 3 || h.Anchor.Seq != 1 {
		t.Errorf("chain with a moved anchor: %+v %v", h, ok)
	}
}

// Run gives up the lead when it stops (shutdown).
func TestRunReleasesTheLockOnShutdown(t *testing.T) {
	_, j, _ := setup(t)
	adm := admin(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- j.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(lockHolders(t, adm)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run never took the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if pids := lockHolders(t, adm); len(pids) != 0 {
		t.Errorf("lock still held after Run returned: %v", pids)
	}
}

// Once a broken chain is repaired, it is no longer flagged and resumes from
// its head again (no anchor walk on every run).
func TestRepairedChainResumesFromItsHead(t *testing.T) {
	d, j, owner := setup(t)
	a := chain(t, d, 3)
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	add(t, d, a, 1)
	if _, err := owner.Exec(`UPDATE audit_events SET action = 'test.tampered' WHERE tenant_id = $1 AND seq = 4`, a); err != nil {
		t.Fatal(err)
	}
	if r, err := j.Once(context.Background()); err != nil || !contains(r.Broken, a) {
		t.Fatalf("tampered run = %+v, %v", r, err)
	}
	if _, err := owner.Exec(`UPDATE audit_events SET action = 'test.entry' WHERE tenant_id = $1 AND seq = 4`, a); err != nil { // repaired
		t.Fatal(err)
	}
	if r, err := j.Once(context.Background()); err != nil || contains(r.Broken, a) || j.broken[a] {
		t.Fatalf("after the repair = %+v, %v, flagged %v", r, err, j.broken[a])
	}
	var from audit.Head
	j.verify = func(ctx context.Context, run audit.Runner, c string, f audit.Head) (audit.Head, audit.Head, error) {
		if c == a {
			from = f
		}
		return audit.VerifyAnchored(ctx, run, c, f)
	}
	if _, err := j.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if from.Seq != 4 {
		t.Errorf("repaired chain verified from %+v, want its head (seq 4)", from)
	}
}
