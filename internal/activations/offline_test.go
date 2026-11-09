package activations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
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
	sum := sha256.Sum256([]byte(text))
	es := f.events(t)
	e := es[len(es)-1]
	if e.Action != "activation.offline" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != got.ActivationID ||
		e.ActorType != auditevent.ActorTypeUser || *e.ActorID != "usr_test" || !strings.Contains(e.Details, hex.EncodeToString(sum[:])) ||
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
		"unknown key":     {manager(f.a), f.offlineReq(t, "LF-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", fp(), nil), ErrNotFound},
		"no permission":   {support, f.offlineReq(t, is.Key, fp(), nil), authz.ErrDenied},
		"out of scope":    {scoped, f.offlineReq(t, is.Key, fp(), nil), ErrNotFound},
		"offline off":     {manager(f.a), f.offlineReq(t, online.Key, fp(), nil), ErrOffline},
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
			if e.Outcome == auditevent.OutcomeSuccess || e.ObjectID != nil || strings.Contains(e.Details, is.Key[3:12]) || !strings.Contains(e.Details, "request_sha256") {
				t.Errorf("event %+v", e)
			}
		})
	}
	if as := f.activations(t, is.License.ID); len(as) != 0 {
		t.Errorf("a refusal took a seat: %+v", as)
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
		l := &ent.License{ID: "lic_x", TenantID: "tnt_x", BindType: license.BindTypeMachine, ExpiresAt: c.expires, MaxOfflineSeconds: c.maxOffline, GraceSeconds: 60}
		got := offlineClaims(l, "p", now, "fp")
		if (got.Expires == nil) != (c.exp == nil) || (c.exp != nil && !got.Expires.Equal(*c.exp)) || got.Grace != c.grace ||
			!got.IssuedAt.Equal(iat) || got.RefreshAfter != nil || got.MaxOffline != nil {
			t.Errorf("%s: exp %v grace %v; want %v %v", name, got.Expires, got.Grace, c.exp, c.grace)
		}
	}
}

func ptr[T any](v T) *T { return &v }
