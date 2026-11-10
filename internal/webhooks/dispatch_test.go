package webhooks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// receiver is a webhook receiver for tests: it answers with status (or
// what answer returns) and keeps what it got.
type receiver struct {
	mu     sync.Mutex
	got    []*http.Request
	bodies [][]byte
	status int
	hold   chan struct{} // if set, requests wait for it
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.got, r.bodies = append(r.got, req), append(r.bodies, b)
	status, hold := r.status, r.hold
	r.mu.Unlock()
	if hold != nil {
		<-hold
	}
	w.WriteHeader(status)
}

func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.got) }

type dispatchFixture struct {
	fixture
	ctx  context.Context
	d    *Dispatcher
	srv  *httptest.Server
	recv *receiver
}

func setupDispatch(t *testing.T) dispatchFixture {
	t.Helper()
	f := setup(t)
	recv := &receiver{status: http.StatusNoContent}
	srv := httptest.NewTLSServer(recv)
	t.Cleanup(srv.Close)
	d := NewDispatcher(f.db, f.s.Keys, testClient(srv, 5*time.Second), slog.New(slog.DiscardHandler))
	return dispatchFixture{fixture: f, ctx: f.as(f.a, f.ownerA, authz.Owner), d: d, srv: srv, recv: recv}
}

func (f dispatchFixture) endpoint(t *testing.T, events ...string) Created {
	t.Helper()
	c, err := f.s.Create(f.ctx, f.srv.URL+"/hook?token=t", events)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// cursor reads an endpoint's delivery state (platform pool, lease included).
func (f dispatchFixture) cursor(t *testing.T, id string) (seq int64, attempts int, next *time.Time, holder *string) {
	t.Helper()
	if err := f.db.WithPlatform(f.ctx, func(tx *ent.Tx) error {
		_, err := scan(f.ctx, tx, `SELECT seq, attempts, next_attempt_at, claimed_by FROM webhook_cursors WHERE endpoint_id = $1`, []any{id}, &seq, &attempts, &next, &holder)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return
}

func (f dispatchFixture) platformExec(t *testing.T, q string, args ...any) {
	t.Helper()
	if err := f.db.WithPlatform(f.ctx, func(tx *ent.Tx) error { _, err := tx.ExecContext(f.ctx, q, args...); return err }); err != nil {
		t.Fatal(err)
	}
}

func (f dispatchFixture) deliveries(t *testing.T, id string) []string {
	t.Helper()
	var out []string
	if err := f.db.WithTenant(f.ctx, f.a, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(f.ctx, `SELECT outcome || ' ' || category || ' ' || COALESCE(status_code::text, '-') || ' #' || attempt
			FROM webhook_deliveries WHERE endpoint_id = $1 ORDER BY attempted_at, attempt`, id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f dispatchFixture) once(t *testing.T) bool {
	t.Helper()
	worked, err := f.d.Once(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return worked
}

var issueDetails = map[string]any{"product_id": "prd_x", "customer_id": "cus_x", "plan_slug": "pro", "expires_at": nil}

func TestDeliver(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, nil) // not subscribed
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	if !f.once(t) || f.recv.count() != 1 {
		t.Fatalf("%d requests", f.recv.count())
	}
	req, body := f.recv.got[0], f.recv.bodies[0]
	// Signed as Standard Webhooks says; a receiver library would accept it.
	ts, _ := strconv.ParseInt(req.Header.Get("webhook-timestamp"), 10, 64)
	want, _ := Signature(req.Header.Get("webhook-id"), ts, body, c.Secret)
	if req.Header.Get("webhook-signature") != want || !strings.HasPrefix(req.Header.Get("webhook-id"), "aud_") || req.URL.RawQuery != "token=t" {
		t.Errorf("request %v %s", req.Header, req.URL)
	}
	var p struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Type != "license.issued" || p.Data["status"] != "active" || p.Data["customer_id"] != "cus_x" || p.Data["plan"] != "pro" {
		t.Errorf("payload %s, %v", body, err)
	}
	if s, a, next, holder := f.cursor(t, c.ID); s != seq || a != 0 || next != nil || holder != nil {
		t.Errorf("cursor %d/%d/%v/%v, want %d", s, a, next, holder, seq)
	}
	if d := f.deliveries(t, c.ID); len(d) != 1 || d[0] != "success http 204 #1" {
		t.Errorf("deliveries %v", d)
	}
	// Nothing more: nothing claimed, nothing sent.
	if f.once(t) || f.recv.count() != 1 {
		t.Error("delivered again")
	}
	// Entries it doesn't subscribe to are passed without a request.
	head := f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, nil)
	if !f.once(t) || f.recv.count() != 1 {
		t.Error("an unsubscribed entry was sent")
	}
	if s, _, _, _ := f.cursor(t, c.ID); s != head {
		t.Errorf("cursor %d after unsubscribed entries, head %d", s, head)
	}
}

func TestRetryAndDisable(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.recv.status = http.StatusInternalServerError
	f.once(t)
	s, a, next, holder := f.cursor(t, c.ID)
	if s != seq-1 || a != 1 || next == nil || time.Until(*next) < 3*time.Second || time.Until(*next) > 7*time.Second || holder != nil {
		t.Fatalf("after a failure: %d/%d/%v/%v", s, a, next, holder)
	}
	if f.once(t) || f.recv.count() != 1 { // not due yet
		t.Error("retried before its time")
	}
	f.platformExec(t, `UPDATE webhook_cursors SET next_attempt_at = now() WHERE endpoint_id = $1`, c.ID)
	f.recv.status = http.StatusOK
	f.once(t)
	if s, a, _, _ := f.cursor(t, c.ID); s != seq || a != 0 {
		t.Errorf("after the retry: %d/%d", s, a)
	}
	if d := f.deliveries(t, c.ID); strings.Join(d, ",") != "failure http 500 #1,success http 200 #2" {
		t.Errorf("deliveries %v", d)
	}
	// The last failure disables (audited); a 410 disables at once.
	seq2 := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.platformExec(t, `UPDATE webhook_cursors SET attempts = 7 WHERE endpoint_id = $1`, c.ID)
	f.recv.status = http.StatusBadGateway
	f.once(t)
	if e, _ := f.s.Get(f.ctx, c.ID); e.Enabled || e.DisabledReason != ReasonFailing || e.Seq != seq2-1 || e.Attempts != 8 {
		t.Errorf("after the last failure: %+v", e)
	}
	if ev := f.events(t, f.a, "webhook.disable"); len(ev) != 1 || ev[0].ActorType != auditevent.ActorTypeSystem {
		t.Errorf("disable audited as %v", ev)
	}
	if f.once(t) { // a disabled endpoint isn't claimed
		t.Error("claimed a disabled endpoint")
	}
	g := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.recv.status = http.StatusGone
	f.once(t)
	if e, _ := f.s.Get(f.ctx, g.ID); e.Enabled || e.DisabledReason != ReasonGone {
		t.Errorf("after a 410: %+v", e)
	}
}

// A tenant's skip while the event is being sent: the send's result matches
// nothing (pinned to the claimed seq and attempts) and isn't recorded.
func TestResultOvertaken(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	hold := make(chan struct{})
	f.recv.status, f.recv.hold = http.StatusInternalServerError, hold
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(f.ctx); done <- err }()
	for f.recv.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	skipped, err := f.s.SkipToNow(f.ctx, c.ID)
	close(hold)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s, a, _, _ := f.cursor(t, c.ID); s != skipped.Seq || a != 0 || len(f.deliveries(t, c.ID)) != 0 {
		t.Errorf("an overtaken result was written: %d/%d %v", s, a, f.deliveries(t, c.ID))
	}
}

// At most 2 leases per tenant; disabled endpoints aren't claimed; a user's
// disable isn't overwritten.
func TestClaimLimits(t *testing.T) {
	f := setupDispatch(t)
	var eps []Created
	for range 3 {
		eps = append(eps, f.endpoint(t, "license.issued"))
	}
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	for _, e := range eps[:2] {
		f.platformExec(t, `UPDATE webhook_cursors SET claimed_by = 'other', claimed_until = now() + interval '1 minute' WHERE endpoint_id = $1`, e.ID)
	}
	if f.once(t) || f.recv.count() != 0 {
		t.Error("a third lease for one tenant")
	}
	f.platformExec(t, `UPDATE webhook_cursors SET claimed_by = NULL, claimed_until = NULL WHERE tenant_id = $1`, f.a)
	for _, e := range eps {
		if _, err := f.s.Disable(f.ctx, e.ID); err != nil {
			t.Fatal(err)
		}
	}
	if f.once(t) || f.recv.count() != 0 {
		t.Error("claimed a disabled endpoint")
	}
}

// During a rotation both secrets sign.
func TestDeliverRotated(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	_, next, err := f.s.RotateSecret(f.ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.once(t)
	req, body := f.recv.got[0], f.recv.bodies[0]
	ts, _ := strconv.ParseInt(req.Header.Get("webhook-timestamp"), 10, 64)
	want, _ := Signature(req.Header.Get("webhook-id"), ts, body, next, c.Secret)
	if req.Header.Get("webhook-signature") != want {
		t.Errorf("signature %q, want %q", req.Header.Get("webhook-signature"), want)
	}
}

func TestPayload(t *testing.T) {
	obj := "act_1"
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e := &ent.AuditEvent{Action: "activation.offline", ObjectID: &obj, OccurredAt: at,
		Details: `{"license_id":"lic_1","product_id":"prd_1","customer_id":"cus_1","fingerprint":"sha256:ab","binding":"machine","mode":"offline","new_seat":true,"request_sha256":"x"}`}
	b, err := Payload("activation.created", e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"activation_id":"act_1","binding":"machine","customer_id":"cus_1","fingerprint":"sha256:ab","license_id":"lic_1","mode":"offline","product_id":"prd_1"},"timestamp":"2026-11-10T12:00:00Z","type":"activation.created"}`
	if string(b) != want {
		t.Errorf("payload\n got %s\nwant %s", b, want)
	}
	l := &ent.AuditEvent{Action: "license.suspend", ObjectID: &obj, OccurredAt: at, Details: `{"from":"active","to":"suspended","product_id":"p","customer_id":"c","plan_slug":"pro","plan_id":"pln","expires_at":null}`}
	if b, _ := Payload("license.suspended", l); !strings.Contains(string(b), `"status":"suspended"`) || strings.Contains(string(b), "from") {
		t.Errorf("license payload %s", b)
	}
	if _, err := Payload("bogus", l); err == nil {
		t.Error("unknown event type")
	}
}

// Re-enabled while a send was in flight (same seq, attempts reset): the
// send's result is pinned to the attempts it claimed and misses.
func TestResultAfterReenable(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.platformExec(t, `UPDATE webhook_cursors SET attempts = 3 WHERE endpoint_id = $1`, c.ID)
	hold := make(chan struct{})
	f.recv.status, f.recv.hold = http.StatusInternalServerError, hold
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(f.ctx); done <- err }()
	for f.recv.count() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := f.s.Disable(f.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Enable(f.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, a, _, _ := f.cursor(t, c.ID); a != 0 || len(f.deliveries(t, c.ID)) != 0 {
		t.Errorf("a result from before the re-enable was written: attempts %d, %v", a, f.deliveries(t, c.ID))
	}
}

// A tenant at its lease cap isn't picked: another tenant's due endpoint is
// served (every time, not by chance).
func TestCappedTenantNotPicked(t *testing.T) {
	f := setupDispatch(t)
	var capped []Created
	for range 3 {
		capped = append(capped, f.endpoint(t, "license.issued"))
	}
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	ctxB := f.as(f.b, f.ownerB, authz.Owner)
	other, err := f.s.Create(ctxB, f.srv.URL+"/b", []string{"license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range capped[:2] {
		f.platformExec(t, `UPDATE webhook_cursors SET claimed_by = 'other', claimed_until = now() + interval '1 minute' WHERE endpoint_id = $1`, e.ID)
	}
	for i := range 8 {
		f.record(t, f.b, "license.issue", auditevent.OutcomeSuccess, issueDetails)
		before := f.recv.count()
		if !f.once(t) || f.recv.count() != before+1 || !strings.HasSuffix(f.recv.got[len(f.recv.got)-1].URL.Path, "/b") {
			t.Fatalf("round %d: the other tenant wasn't served", i)
		}
	}
	_ = other
}

// Replicas claiming for one tenant at once take turns on the tenant's lock
// before counting leases: never more than 2 in flight.
func TestConcurrentClaimsCapped(t *testing.T) {
	f := setupDispatch(t)
	for range 4 {
		f.endpoint(t, "license.issued")
	}
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	hold := make(chan struct{})
	f.recv.hold = hold
	var wg sync.WaitGroup
	for range 4 {
		d := NewDispatcher(f.db, f.s.Keys, f.d.Client, f.d.Log)
		wg.Go(func() { _, _ = d.Once(f.ctx) })
	}
	time.Sleep(time.Second) // every claim has run or is in its send
	got := f.recv.count()
	close(hold)
	wg.Wait()
	if got != 2 {
		t.Errorf("%d sends in flight for one tenant, want 2", got)
	}
}
