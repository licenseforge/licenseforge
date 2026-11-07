package auditexport

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
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

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func openDB(t *testing.T) *store.DB {
	t.Helper()
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// chain creates a tenant with n audit entries.
func chain(t *testing.T, d *store.DB, n int) (string, []*ent.AuditEvent) {
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
	return tn, appendN(t, d, tn, n)
}

func appendN(t *testing.T, d *store.DB, tn string, n int) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	for range n {
		if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
			e, err := audit.Record(context.Background(), tx, tn, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: "usr_x",
				Action: "test.entry", Outcome: auditevent.OutcomeSuccess, SourceIP: "10.0.0.1", Details: map[string]any{"k": "v"}})
			es = append(es, e)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return es
}

// recorder is a Sink that keeps what it got, in delivery order.
type recorder struct {
	mu   sync.Mutex
	got  []Entry
	fail error
}

func (r *recorder) Send(_ context.Context, b []Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.got = append(r.got, b...)
	return nil
}

// seqs is the delivered seqs of tenant tn, in delivery order.
func (r *recorder) seqs(tn string) []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []int64
	for _, e := range r.got {
		if e.TenantID == tn {
			out = append(out, e.Seq)
		}
	}
	return out
}

func exporter(t *testing.T, d *store.DB, name string, s Sink) *Exporter {
	t.Helper()
	x := New(d, name, s, quiet)
	if err := Register(context.Background(), d, name); err != nil {
		t.Fatal(err)
	}
	if err := x.ensureCursors(context.Background()); err != nil {
		t.Fatal(err)
	}
	return x
}

// drain runs Once until nothing is pending.
func drain(t *testing.T, x *Exporter) {
	t.Helper()
	for range 10000 {
		n, err := x.Once(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("export never drained")
}

func sinkName() string { return "test-" + storetest.Suffix() }

func cursorSeq(t *testing.T, name, tn string) (seq int64, claimed bool) {
	t.Helper()
	db, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.QueryRow(`SELECT seq, claimed_by IS NOT NULL FROM audit_export_cursors WHERE sink_id = $1 AND tenant_id = $2`, name, tn).Scan(&seq, &claimed); err != nil {
		t.Fatal(err)
	}
	return seq, claimed
}

func want(n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(i + 1)
	}
	return out
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDeliversEveryEntryInOrder(t *testing.T) {
	d := openDB(t)
	tn, es := chain(t, d, 7)
	r := &recorder{}
	name := sinkName()
	x := exporter(t, d, name, r)
	x.Batch = 3
	drain(t, x)
	if got := r.seqs(tn); !equal(got, want(7)) {
		t.Fatalf("delivered %v", got)
	}
	var e Entry
	for _, g := range r.got {
		if g.TenantID == tn && g.Seq == 1 {
			e = g
		}
	}
	src := es[0]
	if e.ID != src.ID || e.Action != "test.entry" || e.ActorType != "user" || e.ActorID != "usr_x" || e.Outcome != "success" ||
		e.SourceIP != "10.0.0.1" || string(e.Details) != `{"k":"v"}` || e.Hash != hex.EncodeToString(src.Hash) ||
		e.PrevHash != hex.EncodeToString(src.PrevHash) || !e.OccurredAt.Equal(src.OccurredAt) {
		t.Errorf("entry %+v, from %+v", e, src)
	}
	if seq, claimed := cursorSeq(t, name, tn); seq != 7 || claimed {
		t.Errorf("cursor %d claimed=%v", seq, claimed)
	}
	// New entries follow, and nothing is sent twice.
	appendN(t, d, tn, 2)
	drain(t, x)
	if got := r.seqs(tn); !equal(got, want(9)) {
		t.Errorf("after two more: %v", got)
	}
	if lag, err := x.lag(context.Background()); err != nil || lag != 0 {
		t.Errorf("lag after draining = %v, %v", lag, err)
	}
	// The platform chain (no tenant row visible to the platform pool) has a cursor too.
	if err := x.ensureCursors(context.Background()); err != nil {
		t.Fatal(err)
	}
	cursorSeq(t, name, audit.PlatformTenant)
}

// A replica that dies between send and advance: once its lease runs out,
// another one sends the batch again (at-least-once) and advances; the dead
// one's late advance is refused.
func TestAtLeastOnceAfterACrash(t *testing.T) {
	d := openDB(t)
	tn, _ := chain(t, d, 4)
	name := sinkName()
	a, b := &recorder{}, &recorder{}
	xa, xb := exporter(t, d, name, a), exporter(t, d, name, b)
	xa.Lease = time.Second
	ctx := context.Background()
	var c cursor
	for { // claim this test's chain (other tests' chains may come first)
		got, ok, err := xa.claim(ctx)
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
		if got.tenantID == tn {
			c = got
			break
		}
		if err := xa.release(ctx, got); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := xa.read(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// ... and A dies here. While its lease holds, B leaves the chain alone.
	drain(t, xb)
	if got := b.seqs(tn); len(got) != 0 {
		t.Fatalf("B took a leased chain: %v", got)
	}
	time.Sleep(1200 * time.Millisecond)
	drain(t, xb)
	if got := b.seqs(tn); !equal(got, want(4)) || !equal(a.seqs(tn), want(4)) {
		t.Fatalf("A sent %v, B sent %v; want both 1..4", a.seqs(tn), b.seqs(tn))
	}
	if err := xa.advance(ctx, c, 4); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("late advance after a takeover: %v", err)
	}
	if seq, claimed := cursorSeq(t, name, tn); seq != 4 || claimed {
		t.Errorf("cursor %d claimed=%v", seq, claimed)
	}
}

// A failed send keeps the cursor, frees the lease and is retried.
func TestFailedSendIsRetried(t *testing.T) {
	d := openDB(t)
	tn, _ := chain(t, d, 3)
	name := sinkName()
	r := &recorder{fail: errors.New("siem down")}
	x := exporter(t, d, name, r)
	for range 100 { // every pending chain fails, this one included
		if n, err := x.Once(context.Background()); n != 0 || err == nil {
			t.Fatalf("Once with a failing sink = %d, %v", n, err)
		}
		if seq, claimed := cursorSeq(t, name, tn); seq != 0 || claimed {
			t.Fatalf("after a failed send: cursor %d claimed=%v", seq, claimed)
		}
	}
	r.mu.Lock()
	r.fail = nil
	r.mu.Unlock()
	drain(t, x)
	if got := r.seqs(tn); !equal(got, want(3)) {
		t.Errorf("after recovery: %v", got)
	}
}

// Replicas exporting at once deliver each chain gap-free, in order, once.
func TestConcurrentReplicasDeliverInOrder(t *testing.T) {
	d := openDB(t)
	tn, _ := chain(t, d, 40)
	tn2, _ := chain(t, d, 25)
	name := sinkName()
	r := &recorder{} // shared: one SIEM, three replicas
	var xs []*Exporter
	for range 3 {
		x := exporter(t, d, name, r)
		x.Batch = 4
		xs = append(xs, x)
	}
	var wg sync.WaitGroup
	errc := make(chan error, len(xs))
	for _, x := range xs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10000 {
				n, err := x.Once(context.Background())
				if err != nil {
					errc <- err
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	if got := r.seqs(tn); !equal(got, want(40)) {
		t.Errorf("chain 1: %v", got)
	}
	if got := r.seqs(tn2); !equal(got, want(25)) {
		t.Errorf("chain 2: %v", got)
	}
}

// blocking is a Sink that waits until its context is done.
type blocking struct{}

func (blocking) Send(ctx context.Context, _ []Entry) error { <-ctx.Done(); return ctx.Err() }

// A send gets half the lease, so it gives up before another replica may take over.
func TestSendCantOutliveTheLease(t *testing.T) {
	d := openDB(t)
	chain(t, d, 1)
	x := exporter(t, d, sinkName(), blocking{})
	x.Lease = 400 * time.Millisecond
	start := time.Now()
	if _, err := x.Once(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Once = %v, want the send's deadline", err)
	}
	if took := time.Since(start); took > 350*time.Millisecond {
		t.Errorf("send ran %v of a 400ms lease", took)
	}
}

func TestInvalidSettings(t *testing.T) {
	d := openDB(t)
	for name, set := range map[string]func(*Exporter){
		"lease": func(x *Exporter) { x.Lease = 0 }, "batch": func(x *Exporter) { x.Batch = 0 },
		"interval": func(x *Exporter) { x.Interval = -time.Second },
	} {
		x := New(d, sinkName(), &recorder{}, quiet)
		set(x)
		if _, err := x.Once(context.Background()); err == nil {
			t.Errorf("Once with bad %s", name)
		}
		if err := x.Run(context.Background()); err == nil {
			t.Errorf("Run with bad %s", name)
		}
	}
}

func TestLagAndFailureMetrics(t *testing.T) {
	d := openDB(t)
	chain(t, d, 1)
	name := sinkName()
	r := &recorder{fail: errors.New("siem down")}
	x := exporter(t, d, name, r)
	x.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- x.Run(ctx) }()
	// Until the first round has failed and set the lag, however slow the
	// database is (a fixed run time made this flaky).
	failures := func() float64 { return testutil.ToFloat64(metrics.AuditExportFailures.WithLabelValues(name)) }
	lag := func() float64 { return testutil.ToFloat64(metrics.AuditExportLag.WithLabelValues(name)) }
	for deadline := time.Now().Add(10 * time.Second); failures() < 1 || lag() <= 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("failures = %v, lag = %v; want >= 1 and > 0 while undelivered", failures(), lag())
		}
	}
	cancel()
	if err := <-ran; err != nil {
		t.Fatal(err)
	}
}

// The database keeps cursors honest and away from the other logins.
func TestCursorRules(t *testing.T) {
	d := openDB(t)
	tn, _ := chain(t, d, 3)
	name := sinkName()
	exporter(t, d, name, &recorder{})
	ctx := context.Background()
	exec := func(q string, args ...any) error {
		return d.WithPlatform(ctx, func(tx *ent.Tx) error {
			res, err := tx.ExecContext(ctx, q, args...)
			if err == nil {
				if n, _ := res.RowsAffected(); n == 0 {
					return errors.New("no rows")
				}
			}
			return err
		})
	}
	if err := exec(`UPDATE audit_export_cursors SET seq = 2 WHERE sink_id = $1 AND tenant_id = $2`, name, tn); err != nil {
		t.Fatalf("forward to an entry: %v", err)
	}
	for q, why := range map[string]string{
		`UPDATE audit_export_cursors SET seq = 1 WHERE sink_id = $1 AND tenant_id = $2`:  "backwards",
		`UPDATE audit_export_cursors SET seq = 99 WHERE sink_id = $1 AND tenant_id = $2`: "past the head",
		`DELETE FROM audit_export_cursors WHERE sink_id = $1 AND tenant_id = $2`:         "delete",
	} {
		if err := exec(q, name, tn); err == nil {
			t.Errorf("platform pool moved a cursor %s", why)
		}
	}
	// A cursor whose entry was pruned can still be claimed, released and advanced.
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 2`, tn); err != nil {
		t.Fatal(err)
	}
	for q, why := range map[string]string{
		`UPDATE audit_export_cursors SET claimed_by = 'r', claimed_until = clock_timestamp() WHERE sink_id = $1 AND tenant_id = $2`: "claim",
		`UPDATE audit_export_cursors SET claimed_by = NULL, claimed_until = NULL WHERE sink_id = $1 AND tenant_id = $2`:             "release",
		`UPDATE audit_export_cursors SET seq = 3 WHERE sink_id = $1 AND tenant_id = $2`:                                             "advance",
	} {
		if err := exec(q, name, tn); err != nil {
			t.Errorf("%s of a cursor whose entry is gone: %v", why, err)
		}
	}
	// A new chain's cursor starts at 0, never further on.
	late, _ := chain(t, d, 3)
	if err := exec(`INSERT INTO audit_export_cursors (id, tenant_id, sink_id, seq) VALUES ($3, $2, $1, 2)`, name, late, ids.AuditExportCursor()); err == nil {
		t.Error("platform pool inserted a cursor past the start")
	}
	if err := exec(`INSERT INTO audit_export_cursors (id, tenant_id, sink_id, seq) VALUES ($3, $2, $1, 0)`, name, late, ids.AuditExportCursor()); err != nil {
		t.Errorf("cursor at the start: %v", err)
	}
	for pool, with := range map[string]func(func(*ent.Tx) error) error{
		"tenant":   func(fn func(*ent.Tx) error) error { return d.WithTenant(ctx, tn, fn) },
		"identity": func(fn func(*ent.Tx) error) error { return d.WithIdentity(ctx, tn, fn) },
	} {
		for _, q := range []string{`SELECT 1 FROM audit_export_cursors`, `SELECT 1 FROM audit_export_sinks`} {
			if err := with(func(tx *ent.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err == nil {
				t.Errorf("%s pool: %s allowed", pool, q)
			}
		}
	}
}
