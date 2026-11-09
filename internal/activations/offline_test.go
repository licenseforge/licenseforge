package activations

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/schema"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// offlineReq is the lfreq1 text an SDK writes for key on machine.
func (f fixture) offlineReq(t *testing.T, key, machine string, edit func(*licensefile.Request)) string {
	t.Helper()
	r := licensefile.Request{Tenant: f.a, Product: "acme-db", Key: key, Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: machine},
		FPSource: "machine-id", Nonce: bytes.Repeat([]byte{1}, 16), Created: time.Now(), Hostname: "air-1"}
	if edit != nil {
		edit(&r)
	}
	s, err := licensefile.EncodeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOffline(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline")
	machine := fp()
	text := f.offlineReq(t, strings.ToLower(is.Key), machine, nil) // typed in lower case: normalised
	got, err := f.s.Offline(ctx, manager(f.a), text)
	if err != nil {
		t.Fatal(err)
	}
	c, status, err := f.open(t, got, machine)
	if err != nil || status != licensefile.StatusValid {
		t.Fatalf("Open = %v %v", status, err)
	}
	if c.LicenseID != is.License.ID || c.Expires == nil || !c.Expires.Equal(c.IssuedAt.Add(24*time.Hour)) || c.Grace != 0 ||
		c.RefreshAfter != nil || c.MaxOffline != nil || c.Binding != (licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: machine}) {
		t.Errorf("claims = %+v", c)
	}
	h, err := licensefile.FileSHA256(got.File)
	if err != nil {
		t.Fatal(err)
	}
	as := f.activations(t, is.License.ID)
	if len(as) != 1 || as[0].ID != got.ActivationID || as[0].Mode != activation.ModeOffline || as[0].OfflineFileSha256 == nil ||
		*as[0].OfflineFileSha256 != h || *as[0].Hostname != "air-1" || as[0].FpSource != activation.FpSourceMachineID {
		t.Fatalf("activations = %+v", as)
	}
	if l := f.license(t, is.License.ID); l.FirstActivatedAt == nil {
		t.Error("first activation not recorded")
	}
	es := f.events(t)
	e := es[len(es)-1]
	if e.Action != "activation.offline" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != got.ActivationID ||
		e.ActorType != auditevent.ActorTypeUser || *e.ActorID != "usr_test" || !strings.Contains(e.Details, licensefile.OfflineSHA256(text)) ||
		!strings.Contains(e.Details, h) || !strings.Contains(e.Details, `"new_seat":true`) || strings.Contains(e.Details, is.Key[3:12]) {
		t.Errorf("event %+v", e)
	}

	// Renewal: the same machine keeps its seat and gets a new file.
	again, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, func(r *licensefile.Request) { r.Nonce[0] = 2 }))
	if err != nil || again.ActivationID != got.ActivationID {
		t.Fatalf("renewal = %+v, %v", again, err)
	}
	h2, _ := licensefile.FileSHA256(again.File)
	if as := f.activations(t, is.License.ID); len(as) != 1 || *as[0].OfflineFileSha256 != h2 {
		t.Errorf("after renewal: %+v", as)
	}
	// The one seat is taken: another machine is refused, and audited.
	before := len(f.events(t))
	if _, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, fp(), nil)); !errors.Is(err, ErrLimit) {
		t.Errorf("second machine: %v", err)
	}
	if es := f.events(t); len(es) != before+1 || es[before].Outcome != auditevent.OutcomeFailure || es[before].ObjectID != nil {
		t.Errorf("refusal events: %+v", es[before:])
	}
}

func TestOfflineRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline")
	online := f.issue(t, "pro")
	revoked := f.issue(t, "offline")
	zero := f.issue(t, "offline-zero")
	suspended := f.issue(t, "offline")
	if _, err := f.lic.Suspend(ctx, manager(f.a), suspended.License.ID); err != nil {
		t.Fatal(err)
	}
	inGrace := f.issue(t, "offline") // grace 60s: offline issuing allows none
	f.tx(t, f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET expires_at = issued_at + interval '1 millisecond' WHERE id = $1`, inGrace.License.ID)
		return err
	})
	if _, err := f.lic.Revoke(ctx, manager(f.a), revoked.License.ID); err != nil {
		t.Fatal(err)
	}
	support := authz.Principal{Kind: authz.User, ID: "usr_s", TenantID: f.a, Role: authz.Support, Scope: authz.Scope{All: true}}
	scoped := authz.Principal{Kind: authz.User, ID: "usr_o", TenantID: f.a, Role: authz.Manager, Scope: authz.Scope{Products: []string{"prd_" + strings.Repeat("0", 26)}}}
	for name, c := range map[string]struct {
		p    authz.Principal
		text string
		want error
	}{
		"not a request":   {manager(f.a), "lfreq1.e30", ErrInvalid},
		"other tenant":    {manager(f.b), f.offlineReq(t, is.Key, fp(), nil), ErrInvalid},
		"other product":   {manager(f.a), f.offlineReq(t, is.Key, fp(), func(r *licensefile.Request) { r.Product = "other" }), ErrInvalid},
		"unknown key":     {manager(f.a), f.offlineReq(t, licensekey.New(), fp(), nil), ErrNotFound}, // well-formed, no license
		"no permission":   {support, f.offlineReq(t, is.Key, fp(), nil), authz.ErrDenied},
		"out of scope":    {scoped, f.offlineReq(t, is.Key, fp(), nil), ErrNotFound},
		"offline off":     {manager(f.a), f.offlineReq(t, online.Key, fp(), nil), ErrOffline},
		"max offline 0":   {manager(f.a), f.offlineReq(t, zero.Key, fp(), nil), ErrOffline},
		"suspended":       {manager(f.a), f.offlineReq(t, suspended.Key, fp(), nil), ErrSuspended},
		"in grace":        {manager(f.a), f.offlineReq(t, inGrace.Key, fp(), nil), ErrExpired},
		"revoked":         {manager(f.a), f.offlineReq(t, revoked.Key, fp(), nil), ErrRevoked},
		"cluster binding": {manager(f.a), f.offlineReq(t, is.Key, fp(), func(r *licensefile.Request) { r.Binding.Type, r.FPSource = licensefile.BindCluster, "kubernetes" }), ErrBinding},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(f.events(t))
			_, err := f.s.Offline(ctx, c.p, c.text)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			tenant := c.p.TenantID
			var es []*ent.AuditEvent
			f.tx(t, tenant, func(tx *ent.Tx) (err error) {
				es, err = tx.AuditEvent.Query().Where(auditevent.Action("activation.offline")).Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
				return
			})
			if tenant == f.a && len(f.events(t)) != before+1 {
				t.Fatalf("%d new events", len(f.events(t))-before)
			}
			e := es[len(es)-1]
			want := auditevent.OutcomeFailure
			if errors.Is(c.want, authz.ErrDenied) || name == "out of scope" {
				want = auditevent.OutcomeDenied
			}
			if e.Outcome != want || e.ObjectID != nil || strings.Contains(e.Details, is.Key[3:12]) || !strings.Contains(e.Details, "request_sha256") {
				t.Errorf("event %+v", e)
			}
			// Invalid requests: a fixed reason, nothing the request said.
			if errors.Is(c.want, ErrInvalid) && (!strings.Contains(e.Details, `"reason":"`+ErrInvalid.Error()+`"`) || strings.Contains(e.Details, "other") || strings.Contains(e.Details, f.a+`"`) && name == "other tenant") {
				t.Errorf("invalid request reason: %s", e.Details)
			}
			if !errors.Is(c.want, ErrInvalid) && want == auditevent.OutcomeFailure && !strings.Contains(e.Details, c.want.Error()) {
				t.Errorf("reason not recorded: %s", e.Details)
			}
		})
	}
	if as := f.activations(t, is.License.ID); len(as) != 0 {
		t.Errorf("a refusal took a seat: %+v", as)
	}
}

// Offline seats are returned by receipt or the dashboard only; online seats
// never turn offline (ADR-0043): the SDK's online calls can't free a seat
// whose file is still valid.
func TestOfflineAndOnlineSeatsStayApart(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	online := f.issue(t, "offline")
	machine := fp()
	act, err := f.s.Activate(ctx, f.req(online.Key, machine))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, online.Key, machine, nil)); !errors.Is(err, ErrOnlineSeat) {
		t.Errorf("offline on an online seat: %v", err)
	}
	err = f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error { // the schema backs it
		_, err := tx.ExecContext(ctx, `UPDATE activations SET offline_file_sha256 = repeat('a', 64) WHERE id = $1`, act.ActivationID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "activations_offline_mode") {
		t.Errorf("file on an online seat: %v", err)
	}

	is := f.issue(t, "offline")
	machine = fp()
	got, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"activate":   func() error { _, err := f.s.Activate(ctx, f.req(is.Key, machine)); return err },
		"refresh":    func() error { _, err := f.s.Refresh(ctx, f.req(is.Key, machine)); return err },
		"deactivate": func() error { return f.s.Deactivate(ctx, f.req(is.Key, machine)) },
	} {
		if err := call(); !errors.Is(err, ErrOfflineSeat) {
			t.Errorf("online %s of an offline seat: %v", name, err)
		}
	}
	if as := f.activations(t, is.License.ID); len(as) != 1 || as[0].DeactivatedAt != nil {
		t.Fatalf("offline seat changed: %+v", as)
	}
	refused := 0 // activate and deactivate are audited, refresh isn't
	for _, e := range f.events(t) {
		if e.Outcome == auditevent.OutcomeFailure && strings.Contains(e.Details, "seat is offline") {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("%d audited refusals of the offline seat", refused)
	}
	// The dashboard can return it.
	if a, err := f.s.DeactivateByID(ctx, manager(f.a), is.License.ID, got.ActivationID); err != nil || a.DeactivatedAt == nil {
		t.Errorf("dashboard deactivate: %+v, %v", a, err)
	}
}

// Seats are counted under the license's exclusive lock: a request waits
// for a refresh's share lock (and so for every other seat taker) instead
// of counting alongside it. Deterministic: the request must be seen waiting.
func TestOfflineTakesTheLicenseLock(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline") // max_activations 1
	if _, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, fp(), nil)); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	done := make(chan error, 1)
	err = f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.License.Query().Where(license.ID(is.License.ID)).ForShare().Only(ctx); err != nil {
			return err
		}
		text := f.offlineReq(t, is.Key, fp(), nil)
		go func() { _, err := f.s.Offline(ctx, manager(f.a), text); done <- err }()
		deadline := time.Now().Add(10 * time.Second)
		for {
			select {
			case err := <-done:
				return fmt.Errorf("the request didn't wait for the license lock: %v", err)
			default:
			}
			var n int
			if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
				WHERE l.locktype IN ('tuple', 'transactionid') AND NOT l.granted AND a.datname = $1`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if time.Now().After(deadline) {
				return errors.New("the request never waited")
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrLimit) {
		t.Errorf("after the lock: %v", err)
	}
}

func TestOfflineClaims(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 500, time.UTC)
	iat := now.Truncate(time.Second)
	in := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	sec := func(n int64) *int64 { return &n }
	for name, c := range map[string]struct {
		expires    *time.Time
		maxOffline *int64
		exp        *time.Time
		grace      time.Duration
	}{
		"capped by max offline":  {in(30 * 24 * time.Hour), sec(86400), ptr(iat.Add(24 * time.Hour)), 0},
		"license ends first":     {in(time.Hour), sec(86400), ptr(now.Add(time.Hour).Truncate(time.Second)), time.Minute},
		"no max offline":         {in(time.Hour), nil, ptr(now.Add(time.Hour).Truncate(time.Second)), time.Minute},
		"perpetual, max offline": {nil, sec(60), ptr(iat.Add(time.Minute)), 0},
		"perpetual":              {nil, nil, nil, 0},
	} {
		updates := now.Add(time.Hour)
		l := &ent.License{ID: "lic_x", TenantID: "tnt_x", BindType: license.BindTypeMachine, ExpiresAt: c.expires, MaxOfflineSeconds: c.maxOffline, GraceSeconds: 60,
			UpdatesUntil: &updates, Entitlements: schema.LicenseEntitlements{Features: []string{"sso"}, Limits: map[string]int64{"seats": 5}}}
		got := offlineClaims(l, "p", now, "fp")
		if got.UpdatesUntil == nil || !got.UpdatesUntil.Equal(updates.Truncate(time.Second)) || !got.Entitlements.HasFeature("sso") || got.Entitlements.Limits["seats"] != 5 {
			t.Errorf("%s: updates_until %v, entitlements %+v", name, got.UpdatesUntil, got.Entitlements)
		}
		if (got.Expires == nil) != (c.exp == nil) || (c.exp != nil && !got.Expires.Equal(*c.exp)) || got.Grace != c.grace ||
			!got.IssuedAt.Equal(iat) || got.RefreshAfter != nil || got.MaxOffline != nil {
			t.Errorf("%s: exp %v grace %v; want %v %v", name, got.Expires, got.Grace, c.exp, c.grace)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// OfflineTx audits a refusal in the caller's transaction, which commits it
// with the stored outcome; RecheckOffline re-checks the caller's rights.
func TestOfflineTxAndRecheck(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	online := f.issue(t, "pro") // offline not allowed
	support := authz.Principal{Kind: authz.User, ID: "usr_s", TenantID: f.a, Role: authz.Support, Scope: authz.Scope{All: true}}
	scoped := authz.Principal{Kind: authz.User, ID: "usr_o", TenantID: f.a, Role: authz.Manager, Scope: authz.Scope{Products: []string{"prd_" + strings.Repeat("0", 26)}}}
	before := len(f.events(t))
	f.tx(t, f.a, func(tx *ent.Tx) error {
		if _, err := f.s.OfflineTx(ctx, tx, manager(f.a), f.offlineReq(t, online.Key, fp(), nil)); !errors.Is(err, ErrOffline) {
			t.Errorf("OfflineTx: %v", err)
		}
		if _, err := f.s.OfflineTx(ctx, tx, support, f.offlineReq(t, online.Key, fp(), nil)); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("OfflineTx as support: %v", err)
		}
		if _, err := f.s.OfflineTx(ctx, tx, scoped, f.offlineReq(t, online.Key, fp(), nil)); err != ErrNotFound { //nolint:errorlint // exactly, not the internal errHidden
			t.Errorf("OfflineTx out of scope: %v", err)
		}
		return nil // the caller commits the refusals it stores
	})
	es := f.events(t)
	if len(es) != before+3 || es[before].Outcome != auditevent.OutcomeFailure || es[before+1].Outcome != auditevent.OutcomeDenied || es[before+2].Outcome != auditevent.OutcomeDenied {
		t.Fatalf("refusals recorded: %+v", es[before:])
	}
	is := f.issue(t, "offline")
	text := f.offlineReq(t, is.Key, fp(), nil)
	f.tx(t, f.a, func(tx *ent.Tx) error {
		for name, c := range map[string]struct {
			p    authz.Principal
			text string
			want error
		}{
			"allowed":      {manager(f.a), text, nil},
			"support":      {support, text, authz.ErrDenied},
			"out of scope": {scoped, text, ErrNotFound},
			"unknown key":  {manager(f.a), f.offlineReq(t, licensekey.New(), fp(), nil), ErrNotFound},
			"malformed":    {manager(f.a), "lfreq1.e30", ErrInvalid},
		} {
			if err := f.s.RecheckOffline(ctx, tx, c.p, c.text); !errors.Is(err, c.want) || (c.want == nil && err != nil) || errors.Is(err, errHidden) {
				t.Errorf("%s: %v", name, err)
			}
		}
		return nil
	})
	if len(f.activations(t, is.License.ID)) != 0 {
		t.Error("RecheckOffline took a seat")
	}
}
