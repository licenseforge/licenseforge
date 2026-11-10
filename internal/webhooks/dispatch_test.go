package webhooks

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
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
	d := NewDispatcher(f.db, f.s.Keys, testClient(srv, 15*time.Second), slog.New(slog.DiscardHandler))
	df := dispatchFixture{fixture: f, ctx: f.as(f.a, f.ownerA, authz.Owner), d: d, srv: srv, recv: recv}
	// The dispatcher claims any tenant's due endpoint: other tests' endpoints
	// (same database) are taken out of its way, before and after.
	isolate := func() {
		df.platformExec(t, `UPDATE webhook_endpoints SET enabled = false, disabled_reason = 'test isolation', updated_at = now() WHERE enabled`)
	}
	isolate()
	t.Cleanup(isolate)
	return df
}

// waitFor polls cond for up to 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 1000 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
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
	waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
	skipped, err := f.s.SkipToNow(f.ctx, c.ID)
	close(hold)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s, a, _, holder := f.cursor(t, c.ID); s != skipped.Seq || a != 0 || len(f.deliveries(t, c.ID)) != 0 || holder != nil {
		t.Errorf("an overtaken result was written, or its lease kept: %d/%d %v %v", s, a, f.deliveries(t, c.ID), holder)
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
	if b, _ := Payload("license.suspended", l); string(b) != `{"data":{"customer_id":"c","expires_at":null,"license_id":"act_1","plan":"pro","product_id":"p","status":"suspended"},"timestamp":"2026-11-10T12:00:00Z","type":"license.suspended"}` {
		t.Errorf("license payload %s", b)
	}
	// An entry without a field (recorded before it was added) leaves it out:
	// a missing expires_at mustn't read as "never expires".
	bare := &ent.AuditEvent{Action: "license.revoke", ObjectID: &obj, OccurredAt: at, Details: `{"to":"revoked","product_id":"p"}`}
	if b, _ := Payload("license.revoked", bare); strings.Contains(string(b), "expires_at") || strings.Contains(string(b), "customer_id") {
		t.Errorf("absent fields included: %s", b)
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
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	// Retrying this event already (the claim won't move the cursor).
	f.platformExec(t, `UPDATE webhook_cursors SET seq = $2, attempts = 3 WHERE endpoint_id = $1`, c.ID, seq-1)
	hold := make(chan struct{})
	f.recv.status, f.recv.hold = http.StatusInternalServerError, hold
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(f.ctx); done <- err }()
	waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
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
	var mu sync.Mutex
	returned := 0
	for range 4 {
		d := NewDispatcher(f.db, f.s.Keys, f.d.Client, f.d.Log)
		wg.Go(func() {
			_, _ = d.Once(f.ctx)
			mu.Lock()
			returned++
			mu.Unlock()
		})
	}
	// Two send and wait; the other two find the cap and return.
	waitFor(t, "two sends and two refused claims", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return f.recv.count() == 2 && returned == 2
	})
	got := f.recv.count()
	close(hold)
	wg.Wait()
	if got != 2 {
		t.Errorf("%d sends in flight for one tenant, want 2", got)
	}
}

// A receiver slower than the write's own deadline still gets its result
// recorded (the write's deadline starts after the send).
func TestSlowReceiver(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	hold := make(chan struct{})
	f.recv.hold = hold
	go func() { time.Sleep(11 * time.Second); close(hold) }()
	f.once(t)
	if s, a, _, holder := f.cursor(t, c.ID); s != seq || a != 0 || holder != nil {
		t.Errorf("after a slow success: %d/%d/%v", s, a, holder)
	}
}

// An event committing between the head read and the scan isn't passed.
func TestEventDuringClaim(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, nil) // makes it due; not an event for it
	var seq int64
	testHookClaim = func() { seq = f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails) }
	t.Cleanup(func() { testHookClaim = nil })
	f.once(t)
	testHookClaim = nil
	if f.recv.count() == 0 {
		f.once(t) // not seen this round: the next one sends it
	}
	if s, _, _, _ := f.cursor(t, c.ID); f.recv.count() != 1 || s != seq {
		t.Errorf("an event committed during the claim: %d sends, cursor %d, event %d", f.recv.count(), s, seq)
	}
}

// A lease taken over by another replica (this one stalled past it): the
// stale send's result isn't written.
func TestStaleHolder(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	hold := make(chan struct{})
	f.recv.status, f.recv.hold = http.StatusInternalServerError, hold
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(f.ctx); done <- err }()
	waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
	f.platformExec(t, `UPDATE webhook_cursors SET claimed_by = 'other/replica', claimed_until = now() + interval '1 minute' WHERE endpoint_id = $1`, c.ID)
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, a, _, holder := f.cursor(t, c.ID); a != 0 || holder == nil || *holder != "other/replica" || len(f.deliveries(t, c.ID)) != 0 {
		t.Errorf("a stale holder wrote: attempts %d, holder %v, %v", a, holder, f.deliveries(t, c.ID))
	}
}

// Unreadable URL or secret: an invalid ciphertext disables; a key this
// replica lacks backs off without disabling; a malformed secret disables.
func TestUnreadable(t *testing.T) {
	f := setupDispatch(t)
	wrongRow, err := f.s.Keys.Encrypt([]byte("https://x.example/"), secretsBinding(f.a, "whe_aaaaaaaaaaaaaaaaaaaaaaaaaa", "webhook_url"))
	if err != nil {
		t.Fatal(err)
	}
	c := f.endpoint(t, "license.issued")
	f.platformExecOwner(t, `UPDATE webhook_endpoints SET url_ciphertext = $2 WHERE id = $1`, c.ID, []byte(wrongRow))
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.once(t)
	if e, _ := f.s.Get(f.ctx, c.ID); e.Enabled || e.DisabledReason != ReasonURL {
		t.Errorf("invalid URL ciphertext: %+v", e)
	}
	// Another replica's key (a rolling keyring change): back off, stay enabled.
	other := otherKeyring(t)
	g := f.endpoint(t, "license.issued")
	lost, _ := other.Encrypt([]byte("whsec_x"), secretsBinding(f.a, g.ID, "webhook_secret"))
	f.platformExecOwner(t, `UPDATE webhook_endpoints SET secret_ciphertext = $2 WHERE id = $1`, g.ID, []byte(lost))
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	if _, err := f.d.Once(f.ctx); err == nil {
		t.Error("an unknown key wasn't reported")
	}
	e, _ := f.s.Get(f.ctx, g.ID)
	if !e.Enabled || e.NextAttemptAt == nil || time.Until(*e.NextAttemptAt) < 4*time.Minute || f.recv.count() != 0 {
		t.Errorf("unknown key: %+v, %d sends", e, f.recv.count())
	}
	if _, _, _, holder := f.cursor(t, g.ID); holder != nil {
		t.Error("lease kept after backing off")
	}
	// A secret that decrypts but isn't a Standard Webhooks secret.
	h := f.endpoint(t, "license.issued")
	bad, _ := f.s.Keys.Encrypt([]byte("not-a-secret"), secretsBinding(f.a, h.ID, "webhook_secret"))
	f.platformExecOwner(t, `UPDATE webhook_endpoints SET secret_ciphertext = $2 WHERE id = $1`, h.ID, []byte(bad))
	f.platformExec(t, `UPDATE webhook_endpoints SET enabled = false, disabled_reason = 'x' WHERE id = $1`, g.ID)
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.once(t)
	if e, _ := f.s.Get(f.ctx, h.ID); e.Enabled || e.DisabledReason != ReasonSecret {
		t.Errorf("malformed secret: %+v", e)
	}
}

// A verdict from a send doesn't overwrite what changed meanwhile: a user's
// disable, or a new URL.
func TestVerdictPinnedToEndpoint(t *testing.T) {
	f := setupDispatch(t)
	for name, change := range map[string]func(id string){
		"user disable": func(id string) {
			if _, err := f.s.Disable(f.ctx, id); err != nil {
				t.Fatal(err)
			}
		},
		"new URL": func(id string) {
			u := f.srv.URL + "/new"
			if _, err := f.s.Update(f.ctx, id, &u, nil); err != nil {
				t.Fatal(err)
			}
		},
	} {
		c := f.endpoint(t, "license.issued")
		f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
		hold := make(chan struct{})
		f.recv.mu.Lock()
		f.recv.status, f.recv.hold, f.recv.got = http.StatusGone, hold, nil
		f.recv.mu.Unlock()
		done := make(chan error, 1)
		go func() { _, err := f.d.Once(f.ctx); done <- err }()
		waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
		change(c.ID)
		close(hold)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		e, _ := f.s.Get(f.ctx, c.ID)
		if e.DisabledReason == ReasonGone {
			t.Errorf("%s: overwritten by the send's 410: %+v", name, e)
		}
		f.platformExec(t, `UPDATE webhook_endpoints SET enabled = false, disabled_reason = 'done', updated_at = now() WHERE id = $1`, c.ID)
	}
}

// A cancelled send (shutting down) frees the lease without an attempt; an
// expired previous secret doesn't sign.
func TestCancelAndExpiredPrevious(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	if _, _, err := f.s.RotateSecret(f.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	f.platformExecOwner(t, `UPDATE webhook_endpoints SET previous_secret_until = now() - interval '1 minute' WHERE id = $1`, c.ID)
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	hold := make(chan struct{})
	f.recv.hold = hold
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(ctx); done <- err }()
	waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
	if sig := f.recv.got[0].Header.Get("webhook-signature"); strings.Count(sig, "v1,") != 1 {
		t.Errorf("an expired previous secret signed: %q", sig)
	}
	cancel()
	close(hold)
	if err := <-done; err == nil {
		t.Error("a cancelled send reported no error")
	}
	if _, a, _, holder := f.cursor(t, c.ID); a != 0 || holder != nil || len(f.deliveries(t, c.ID)) != 0 {
		t.Errorf("after a cancel: attempts %d, holder %v, %v", a, holder, f.deliveries(t, c.ID))
	}
}

// Moving past a held-back event (its type unsubscribed) starts the next
// event's retries afresh.
func TestMoveResetsRetries(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.platformExec(t, `UPDATE webhook_cursors SET attempts = 5 WHERE endpoint_id = $1`, c.ID)
	if _, err := f.s.Update(f.ctx, c.ID, nil, []string{"license.revoked"}); err != nil {
		t.Fatal(err)
	}
	f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, map[string]any{"to": "revoked"})
	f.recv.status = http.StatusInternalServerError
	f.once(t)
	if d := f.deliveries(t, c.ID); len(d) != 1 || d[0] != "failure http 500 #1" {
		t.Errorf("deliveries %v", d)
	}
}

// Entries pruned after the cursor: it moves to the cut, audited.
func TestPrunedSkip(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	old := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	owner := sqlOpen(t, env.OwnerURL)
	if _, err := owner.Exec(`UPDATE audit_events SET occurred_at = now() - interval '400 days' WHERE tenant_id = $1 AND seq <= $2`, f.a, old); err != nil {
		t.Fatal(err)
	}
	next := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	ret := sqlOpen(t, env.RetentionURL)
	if _, err := ret.Exec(`INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) SELECT $3, tenant_id, seq, hash, now()
		FROM audit_events WHERE tenant_id = $1 AND seq = $2`, f.a, old, ids.AuditAnchor()); err != nil {
		t.Fatal(err)
	}
	if _, err := ret.Exec(`DELETE FROM audit_events WHERE tenant_id = $1 AND seq <= $2`, f.a, old); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE webhook_cursors SET seq = 0 WHERE endpoint_id = $1`, c.ID); err != nil {
		t.Fatal(err)
	}
	f.once(t)
	ev := f.events(t, f.a, "webhook.pruned_skip")
	var d map[string]any
	if len(ev) != 1 || json.Unmarshal([]byte(ev[0].Details), &d) != nil || d["from_seq"] != float64(0) || d["to_seq"] != float64(old) {
		t.Fatalf("pruned skip audited as %v", ev)
	}
	if s, _, _, _ := f.cursor(t, c.ID); s < old {
		t.Errorf("cursor %d below the cut %d", s, old)
	}
	if f.recv.count() == 0 {
		f.once(t)
	}
	if s, _, _, _ := f.cursor(t, c.ID); s != next {
		t.Errorf("cursor %d after the cut, want %d", s, next)
	}
}

func TestRetryDelay(t *testing.T) {
	for i := range 200 {
		n := i%len(schedule) + 1
		d := retryDelay(n, 0)
		if base := schedule[n-1]; d < base*9/10 || d > base*11/10 {
			t.Fatalf("failure %d: %v, base %v", n, d, base)
		}
	}
	if d := retryDelay(1, time.Hour); d != time.Hour {
		t.Errorf("Retry-After not a floor: %v", d)
	}
	if d := retryDelay(7, time.Minute); d < 9*time.Hour {
		t.Errorf("Retry-After shortened the schedule: %v", d)
	}
}

func secretsBinding(tenant, row, purpose string) secrets.Binding {
	return secrets.Binding{Purpose: secrets.Purpose(purpose), TenantID: tenant, RowID: row}
}

func otherKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	kr, err := secrets.ParseKeyring("k9=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return kr
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

// platformExecOwner changes what neither serving pool may (test setup).
func (f dispatchFixture) platformExecOwner(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := sqlOpen(t, env.OwnerURL).Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// Disabled while the claim runs (after its candidate query): not sent.
func TestDisabledDuringClaim(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	testHookClaim = func() {
		f.platformExec(t, `UPDATE webhook_endpoints SET enabled = false, disabled_reason = 'during claim', updated_at = now() WHERE id = $1`, c.ID)
	}
	t.Cleanup(func() { testHookClaim = nil })
	f.once(t)
	testHookClaim = nil
	if f.recv.count() != 0 {
		t.Error("sent to an endpoint disabled during the claim")
	}
}

// The URL changed during the last retry: that send's disable misses (pinned
// to the endpoint as claimed), the count stays at its maximum, and the
// next failure disables; never past the bound.
func TestLastRetryAfterChange(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.platformExec(t, `UPDATE webhook_cursors SET seq = $2, attempts = 7 WHERE endpoint_id = $1`, c.ID, seq-1)
	hold := make(chan struct{})
	f.recv.status, f.recv.hold = http.StatusBadGateway, hold
	done := make(chan error, 1)
	go func() { _, err := f.d.Once(f.ctx); done <- err }()
	waitFor(t, "the send", func() bool { return f.recv.count() > 0 })
	u := f.srv.URL + "/fixed"
	if _, err := f.s.Update(f.ctx, c.ID, &u, nil); err != nil {
		t.Fatal(err)
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e, _ := f.s.Get(f.ctx, c.ID); !e.Enabled || e.Attempts != 8 {
		t.Fatalf("after the missed disable: %+v", e)
	}
	f.recv.mu.Lock()
	f.recv.hold = nil
	f.recv.mu.Unlock()
	f.platformExec(t, `UPDATE webhook_cursors SET next_attempt_at = now() WHERE endpoint_id = $1`, c.ID)
	if _, err := f.d.Once(f.ctx); err != nil {
		t.Fatalf("the next failure: %v", err)
	}
	if e, _ := f.s.Get(f.ctx, c.ID); e.Enabled || e.DisabledReason != ReasonFailing || e.Attempts != 8 {
		t.Errorf("after the next failure: %+v", e)
	}
}
