package activations

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/issue"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ent/planfeature"
	"licenseforge.io/licenseforge/internal/store/storetest"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db       *store.DB
	kr       *secrets.Keyring
	keys     signing.Local
	s        Service
	lic      licenses.Service
	a, b     string // tenants
	product  string // in a
	customer string
	plans    map[string]string // slug → ID, in a
	kid      string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	keys := signing.Local{DB: d, Keys: kr}
	f := fixture{db: d, kr: kr, keys: keys, s: Service{DB: d, Keys: kr, Issuer: issue.Issuer{DB: d, Keys: keys}},
		lic: licenses.Service{DB: d, Keys: kr}, plans: map[string]string{}}
	for _, tn := range []*string{&f.a, &f.b} {
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			x, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err == nil {
				*tn = x.ID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		k, err := keys.Create(ctx, *tn)
		if err != nil {
			t.Fatal(err)
		}
		if *tn == f.a {
			f.kid = k.ID
		}
	}
	f.tx(t, f.a, func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(f.a).SetSlug("acme-db").SetName("Acme DB").Save(ctx)
		if err != nil {
			return err
		}
		f.product = p.ID
		sso, err := tx.Feature.Create().SetTenantID(f.a).SetProductID(p.ID).SetKey("sso").SetName("SSO").SetType(feature.TypeBoolean).Save(ctx)
		if err != nil {
			return err
		}
		for slug, c := range map[string]func(*ent.PlanCreate){
			"pro": func(c *ent.PlanCreate) {
				c.SetDurationMonths(12).SetMaxActivations(2).SetLeaseSeconds(3600).SetMaxOfflineSeconds(7200).SetGraceSeconds(60)
			},
			"presold": func(c *ent.PlanCreate) { c.SetDurationMonths(12).SetExpiryBasis(plan.ExpiryBasisFromFirstActivation) },
			"cluster": func(c *ent.PlanCreate) { c.SetBindType(plan.BindTypeCluster) },
			"site":    func(c *ent.PlanCreate) { c.SetBindType(plan.BindTypeNone) },
			"moves":   func(c *ent.PlanCreate) { c.SetMaxActivations(1).SetMaxRehosts(2) },
			"locked":  func(c *ent.PlanCreate) { c.SetMaxActivations(1).SetMaxRehosts(0) },
		} {
			pc := tx.Plan.Create().SetTenantID(f.a).SetProductID(p.ID).SetSlug(slug).SetName(slug)
			c(pc)
			pl, err := pc.Save(ctx)
			if err != nil {
				return err
			}
			f.plans[slug] = pl.ID
		}
		if _, err := tx.PlanFeature.Create().SetTenantID(f.a).SetProductID(p.ID).SetPlanID(f.plans["pro"]).SetFeatureID(sso.ID).
			SetFeatureType(planfeature.FeatureTypeBoolean).Save(ctx); err != nil {
			return err
		}
		c, err := tx.Customer.Create().SetTenantID(f.a).SetName("Contoso").Save(ctx)
		f.customer = c.ID
		return err
	})
	return f
}

func (f fixture) tx(t *testing.T, tenant string, fn func(*ent.Tx) error) {
	t.Helper()
	if err := f.db.WithTenant(context.Background(), tenant, fn); err != nil {
		t.Fatal(err)
	}
}

var manager = func(tenant string) authz.Principal {
	return authz.Principal{Kind: authz.User, ID: "usr_test", TenantID: tenant, Role: authz.Manager, Scope: authz.Scope{All: true}}
}

// issue issues a license of plan slug through the real service.
func (f fixture) issue(t *testing.T, slug string) licenses.Issued {
	t.Helper()
	got, err := f.lic.Issue(context.Background(), manager(f.a), licenses.IssueRequest{ProductID: f.product, PlanID: f.plans[slug], CustomerID: f.customer})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func fp() string {
	sum := sha256.Sum256([]byte(rand.Text()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f fixture) req(key, fingerprint string) Request {
	return Request{TenantID: f.a, Key: key, Fingerprint: fingerprint, Source: activation.FpSourceMachineID, Hostname: "db-1", AppVersion: "1.2.3", SDKVersion: "go/0.1.0"}
}

func (f fixture) license(t *testing.T, id string) *ent.License {
	t.Helper()
	var l *ent.License
	f.tx(t, f.a, func(tx *ent.Tx) (err error) { l, err = tx.License.Get(context.Background(), id); return })
	return l
}

func (f fixture) activations(t *testing.T, licenseID string) []*ent.Activation {
	t.Helper()
	var as []*ent.Activation
	f.tx(t, f.a, func(tx *ent.Tx) (err error) {
		as, err = tx.Activation.Query().Where(activation.LicenseID(licenseID)).Order(ent.Asc(activation.FieldFirstSeenAt)).All(context.Background())
		return
	})
	return as
}

// events returns tenant a's audit entries after verifying the chain.
func (f fixture) events(t *testing.T) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	f.tx(t, f.a, func(tx *ent.Tx) error {
		if _, err := audit.Verify(context.Background(), tx, f.a); err != nil {
			return err
		}
		var err error
		es, err = tx.AuditEvent.Query().Order(ent.Asc(auditevent.FieldSeq)).All(context.Background())
		return err
	})
	return es
}

// open verifies a lease as the SDK does, at its iat, on machine fingerprint.
func (f fixture) open(t *testing.T, l Lease, fingerprint string) (*licensefile.Claims, licensefile.Status, error) {
	t.Helper()
	pk, err := f.keys.Public(context.Background(), f.a, l.KID)
	if err != nil {
		t.Fatal(err)
	}
	return licensefile.Open(l.File, licensefile.KeySet{{KID: pk.KID, Alg: licensefile.AlgEd25519, Key: pk.Key}},
		licensefile.CheckOptions{Now: l.Claims.IssuedAt, Product: "acme-db", Fingerprint: fingerprint})
}

func TestActivateReturnsVerifiableLease(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "pro")
	machine := fp()
	before := len(f.events(t))
	got, err := f.s.Activate(ctx, f.req(strings.ToLower(is.Key), machine)) // typed in lower case: normalised
	if err != nil {
		t.Fatal(err)
	}
	c, status, err := f.open(t, got, machine)
	if err != nil || status != licensefile.StatusValid {
		t.Fatalf("Open = %v %v", status, err)
	}
	iat := c.IssuedAt
	if c.LicenseID != is.License.ID || c.Tenant != f.a || c.Plan != "pro" || c.CustomerID != f.customer || got.KID != f.kid ||
		!c.Expires.Equal(iat.Add(time.Hour)) || !c.RefreshAfter.Equal(iat.Add(30*time.Minute)) ||
		c.MaxOffline == nil || *c.MaxOffline != 2*time.Hour || c.Grace != 0 || // not capped: no grace
		c.Binding != (licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: machine}) || !c.Entitlements.HasFeature("sso") {
		t.Errorf("claims = %+v", c)
	}
	if time.Since(iat) > time.Minute || time.Until(iat) > time.Minute {
		t.Errorf("iat %v is not the server time", iat)
	}
	// Another machine's fingerprint doesn't match the lease.
	if _, _, err := f.open(t, got, fp()); !errors.Is(err, licensefile.ErrBindingMismatch) {
		t.Errorf("other machine: %v", err)
	}
	as := f.activations(t, is.License.ID)
	if len(as) != 1 || as[0].ID != got.ActivationID || as[0].Mode != activation.ModeOnline || as[0].Binding != activation.BindingMachine ||
		*as[0].Hostname != "db-1" || *as[0].AppVersion != "1.2.3" || *as[0].SdkVersion != "go/0.1.0" {
		t.Fatalf("activations = %+v", as)
	}
	es := f.events(t)
	if len(es) != before+1 {
		t.Fatalf("%d new events", len(es)-before)
	}
	if e := es[len(es)-1]; e.Action != "activation.create" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != got.ActivationID ||
		e.ActorType != auditevent.ActorTypeSystem || !strings.Contains(e.Details, is.License.ID) || strings.Contains(e.Details, is.Key[3:12]) {
		t.Errorf("event %+v", e)
	}

	// Re-activating the same machine reuses the seat, records the metadata,
	// and isn't a new audited activation.
	req := f.req(is.Key, machine)
	req.AppVersion = "1.3.0"
	again, err := f.s.Activate(ctx, req)
	if err != nil || again.ActivationID != got.ActivationID {
		t.Fatalf("again = %+v, %v", again, err)
	}
	as = f.activations(t, is.License.ID)
	if len(as) != 1 || *as[0].AppVersion != "1.3.0" || as[0].LastSeenAt.Before(as[0].FirstSeenAt) {
		t.Errorf("after re-activation: %+v", as)
	}
	if n := len(f.events(t)); n != before+1 {
		t.Errorf("re-activation audited: %d events", n-before)
	}
}

func TestSeatLimitUnderConcurrency(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "pro") // max_activations 2
	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { _, errs[i] = f.s.Activate(ctx, f.req(is.Key, fp())) })
	}
	wg.Wait()
	ok, limited := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrLimit):
			limited++
		default:
			t.Errorf("err = %v", err)
		}
	}
	if ok != 2 || limited != n-2 || len(f.activations(t, is.License.ID)) != 2 {
		t.Fatalf("%d activated, %d refused, %d rows", ok, limited, len(f.activations(t, is.License.ID)))
	}
	fails := 0
	for _, e := range f.events(t) {
		if e.Action == "activation.create" && e.Outcome == auditevent.OutcomeFailure && strings.Contains(e.Details, "activation limit") {
			fails++
		}
	}
	if fails != n-2 {
		t.Errorf("%d refused activations audited", fails)
	}

	// Deactivating frees the seat, once.
	first := f.activations(t, is.License.ID)[0]
	if err := f.s.Deactivate(ctx, f.req(is.Key, first.Fingerprint)); err != nil {
		t.Fatal(err)
	}
	es := f.events(t)
	if e := es[len(es)-1]; e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != first.ID {
		t.Errorf("event %+v", e)
	}
	if err := f.s.Deactivate(ctx, f.req(is.Key, first.Fingerprint)); !errors.Is(err, ErrNotActivated) {
		t.Errorf("second deactivate: %v", err)
	}
	es = f.events(t)
	if e := es[len(es)-1]; e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeFailure {
		t.Errorf("event %+v", e)
	}
	// The deactivated machine can't refresh, but it can activate again: a
	// new activation in the freed seat.
	if _, err := f.s.Refresh(ctx, f.req(is.Key, first.Fingerprint)); !errors.Is(err, ErrNotActivated) {
		t.Errorf("refresh deactivated: %v", err)
	}
	if again, err := f.s.Activate(ctx, f.req(is.Key, first.Fingerprint)); err != nil || again.ActivationID == first.ID {
		t.Errorf("activate into the freed seat: %+v %v", again, err)
	}
	if _, err := f.s.Activate(ctx, f.req(is.Key, fp())); !errors.Is(err, ErrLimit) {
		t.Errorf("past the limit: %v", err)
	}
	if d := f.activations(t, is.License.ID)[0]; d.DeactivatedAt == nil {
		t.Errorf("not deactivated: %+v", d)
	}
}

func TestRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	m := manager(f.a)
	active := f.issue(t, "pro")
	suspended, revoked, expired := f.issue(t, "pro"), f.issue(t, "pro"), f.issue(t, "pro")
	if _, err := f.lic.Suspend(ctx, m, suspended.License.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lic.Revoke(ctx, m, revoked.License.ID); err != nil {
		t.Fatal(err)
	}
	f.tx(t, f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET expires_at = issued_at + interval '1 microsecond' WHERE id = $1`, expired.License.ID)
		return err
	})
	cluster, site := f.issue(t, "cluster"), f.issue(t, "site")
	// Lookup hash moved to a key that isn't the license's: the decrypted key decides.
	forged := licensekey.New()
	tampered := f.issue(t, "pro")
	f.tx(t, f.a, func(tx *ent.Tx) error {
		h, _ := f.kr.LookupHash(secrets.PurposeLicenseKey, []byte(forged))
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET key_lookup = $2 WHERE id = $1`, tampered.License.ID, h)
		return err
	})

	k8s := func(r Request) Request { r.Source = activation.FpSourceKubernetes; return r }
	for _, tc := range []struct {
		name    string
		req     Request
		want    error
		audited bool
	}{
		{"suspended", f.req(suspended.Key, fp()), ErrSuspended, true},
		{"revoked", f.req(revoked.Key, fp()), ErrRevoked, true},
		{"expired", f.req(expired.Key, fp()), ErrExpired, true},
		{"cluster fingerprint on a machine license", k8s(f.req(active.Key, fp())), ErrBinding, true},
		{"machine fingerprint on a cluster license", f.req(cluster.Key, fp()), ErrBinding, true},
		{"site license", f.req(site.Key, fp()), ErrBinding, true},
		{"unknown key", f.req(licensekey.New(), fp()), ErrUnauthenticated, false},
		{"malformed key", f.req("LF-NOPE", fp()), ErrUnauthenticated, false},
		{"forged lookup", f.req(forged, fp()), ErrUnauthenticated, false},
		{"another tenant", func() Request { r := f.req(active.Key, fp()); r.TenantID = f.b; return r }(), ErrUnauthenticated, false},
		{"malformed tenant", func() Request { r := f.req(active.Key, fp()); r.TenantID = "acme"; return r }(), ErrUnauthenticated, false},
		{"empty tenant", func() Request { r := f.req(active.Key, fp()); r.TenantID = ""; return r }(), ErrUnauthenticated, false},
		{"hostname with a space", func() Request { r := f.req(active.Key, fp()); r.Hostname = "db 1"; return r }(), ErrInvalid, false},
		{"hostname not ASCII", func() Request { r := f.req(active.Key, fp()); r.Hostname = "dé-1"; return r }(), ErrInvalid, false},
		{"hostname too long", func() Request { r := f.req(active.Key, fp()); r.Hostname = strings.Repeat("a", 254); return r }(), ErrInvalid, false},
		{"zero-width in version", func() Request { r := f.req(active.Key, fp()); r.AppVersion = "1.0\u200b"; return r }(), ErrInvalid, false},
		{"bidi override in SDK version", func() Request { r := f.req(active.Key, fp()); r.SDKVersion = "go/\u202e1"; return r }(), ErrInvalid, false},
		{"malformed fingerprint", f.req(active.Key, "sha256:ABC"), ErrInvalid, false},
		{"unknown source", func() Request { r := f.req(active.Key, fp()); r.Source = "bios"; return r }(), ErrInvalid, false},
		{"control character in hostname", func() Request { r := f.req(active.Key, fp()); r.Hostname = "db\n1"; return r }(), ErrInvalid, false},
		{"version too long", func() Request { r := f.req(active.Key, fp()); r.AppVersion = strings.Repeat("1", 65); return r }(), ErrInvalid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.events(t))
			if _, err := f.s.Activate(ctx, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			es := f.events(t)
			if tc.audited {
				if len(es) != before+1 || es[len(es)-1].Action != "activation.create" || es[len(es)-1].Outcome != auditevent.OutcomeFailure {
					t.Errorf("events %d→%d", before, len(es))
				}
			} else if len(es) != before {
				t.Errorf("audited: %+v", es[len(es)-1])
			}
		})
	}
	// Nothing was activated, and tenant b saw nothing.
	var n int
	f.tx(t, f.a, func(tx *ent.Tx) (err error) { n, err = tx.Activation.Query().Count(ctx); return })
	if n != 0 {
		t.Errorf("%d activations", n)
	}
	// A cluster fingerprint activates a cluster license.
	if _, err := f.s.Activate(ctx, k8s(f.req(cluster.Key, fp()))); err != nil {
		t.Errorf("cluster: %v", err)
	}

	// An activated machine loses its lease when the license is suspended,
	// gets it back when reinstated, and loses it for good when revoked.
	machine := fp()
	if _, err := f.s.Activate(ctx, f.req(active.Key, machine)); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		change func() error
		want   error
	}{
		{func() error { _, err := f.lic.Suspend(ctx, m, active.License.ID); return err }, ErrSuspended},
		{func() error { _, err := f.lic.Reinstate(ctx, m, active.License.ID); return err }, nil},
		{func() error { _, err := f.lic.Revoke(ctx, m, active.License.ID); return err }, ErrRevoked},
	} {
		if err := step.change(); err != nil {
			t.Fatal(err)
		}
		before := len(f.events(t))
		if _, err := f.s.Refresh(ctx, f.req(active.Key, machine)); !errors.Is(err, step.want) {
			t.Errorf("refresh = %v, want %v", err, step.want)
		}
		if n := len(f.events(t)); n != before {
			t.Errorf("refresh audited: %d events", n-before)
		}
	}
	// A revoked license's seat can still be freed.
	if err := f.s.Deactivate(ctx, f.req(active.Key, machine)); err != nil {
		t.Errorf("deactivate revoked: %v", err)
	}
	if err := f.s.Deactivate(ctx, f.req(licensekey.New(), machine)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("deactivate with an unknown key: %v", err)
	}
}

func TestFromFirstActivation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "presold")
	if is.License.ExpiresAt != nil || is.License.FirstActivatedAt != nil {
		t.Fatalf("issued %+v", is.License)
	}
	got, err := f.s.Activate(ctx, f.req(is.Key, fp()))
	if err != nil {
		t.Fatal(err)
	}
	l := f.license(t, is.License.ID)
	if l.FirstActivatedAt == nil || l.ExpiresAt == nil || !l.ExpiresAt.Equal(*licenses.Expiry(*l.FirstActivatedAt, l.DurationMonths, nil)) ||
		got.Claims.IssuedAt.Sub(*l.FirstActivatedAt).Abs() > time.Second {
		t.Fatalf("license %+v, lease iat %v", l, got.Claims.IssuedAt)
	}
	// The term starts once.
	if _, err := f.s.Activate(ctx, f.req(is.Key, fp())); err != nil {
		t.Fatal(err)
	}
	if again := f.license(t, is.License.ID); !again.FirstActivatedAt.Equal(*l.FirstActivatedAt) || !again.ExpiresAt.Equal(*l.ExpiresAt) {
		t.Errorf("term moved: %+v", again)
	}
}

func TestRefresh(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "pro")
	machine := fp()
	first, err := f.s.Activate(ctx, f.req(is.Key, machine))
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.events(t))
	req := f.req(is.Key, machine)
	req.AppVersion, req.Hostname = "2.0.0", ""
	got, err := f.s.Refresh(ctx, req)
	if err != nil || got.ActivationID != first.ActivationID {
		t.Fatalf("refresh = %+v, %v", got, err)
	}
	if _, status, err := f.open(t, got, machine); err != nil || status != licensefile.StatusValid {
		t.Errorf("Open = %v %v", status, err)
	}
	as := f.activations(t, is.License.ID)
	if len(as) != 1 || *as[0].AppVersion != "2.0.0" || as[0].Hostname != nil || !as[0].LastSeenAt.After(as[0].FirstSeenAt) {
		t.Errorf("activation %+v", as[0])
	}
	if len(f.events(t)) != before {
		t.Error("refresh audited")
	}
	// Refresh never takes a seat.
	if _, err := f.s.Refresh(ctx, f.req(is.Key, fp())); !errors.Is(err, ErrNotActivated) {
		t.Errorf("unknown machine: %v", err)
	}
	if n := len(f.activations(t, is.License.ID)); n != 1 {
		t.Errorf("%d activations", n)
	}
	// The lease never outlives the license.
	f.tx(t, f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET expires_at = clock_timestamp() + interval '10 minutes' WHERE id = $1`, is.License.ID)
		return err
	})
	got, err = f.s.Refresh(ctx, f.req(is.Key, machine))
	if err != nil {
		t.Fatal(err)
	}
	l := f.license(t, is.License.ID)
	if want := l.ExpiresAt.UTC().Truncate(time.Second); !got.Claims.Expires.Equal(want) || got.Claims.RefreshAfter.After(want) || got.Claims.Grace != time.Minute {
		t.Errorf("exp %v refresh %v, license expires %v", got.Claims.Expires, got.Claims.RefreshAfter, l.ExpiresAt)
	}
}

func TestLeaseClaims(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	d := func(s int64) *int64 { return &s }
	at := func(t time.Time) *time.Time { return &t }
	for _, tc := range []struct {
		name         string
		lease        int64
		maxOffline   *int64
		expires      *time.Time
		exp, refresh time.Duration // after now
		grace        time.Duration
	}{
		{"half the lease", 3600, nil, nil, time.Hour, 30 * time.Minute, 0},
		{"max_offline shorter than the lease", 7 * 86400, d(86400), nil, 7 * 24 * time.Hour, 12 * time.Hour, 0},
		{"max_offline longer than the lease", 3600, d(86400), nil, time.Hour, 30 * time.Minute, 0},
		{"max_offline zero: refresh at once", 3600, d(0), nil, time.Hour, 0, 0},
		{"term ends within the lease: capped, with grace", 3600, nil, at(now.Add(10 * time.Minute)), 10 * time.Minute, 10 * time.Minute, time.Minute},
		{"term ends exactly at the lease's end: grace", 3600, nil, at(now.Add(time.Hour)), time.Hour, 30 * time.Minute, time.Minute},
		{"term ends after the lease: no grace", 3600, nil, at(now.Add(time.Hour + time.Second)), time.Hour, 30 * time.Minute, 0},
		{"term ends within the lease's last second: grace", 3600, nil, at(now.Add(time.Hour + 500*time.Millisecond)), time.Hour, 30 * time.Minute, time.Minute},
		{"perpetual: no grace", 3600, nil, nil, time.Hour, 30 * time.Minute, 0},
		{"in grace: exp stays, refresh within the grace", 3600, nil, at(now.Add(-30 * time.Second)), -30 * time.Second, 30 * time.Second, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := &ent.License{ID: "lic_x", TenantID: "tnt_x", LeaseSeconds: tc.lease, MaxOfflineSeconds: tc.maxOffline,
				ExpiresAt: tc.expires, GraceSeconds: 60, BindType: "machine"}
			c := leaseClaims(l, "acme-db", now, "sha256:x")
			if !c.Expires.Equal(now.Add(tc.exp)) || !c.RefreshAfter.Equal(now.Add(tc.refresh)) || c.Grace != tc.grace {
				t.Errorf("exp %v refresh %v grace %v", c.Expires.Sub(now), c.RefreshAfter.Sub(now), c.Grace)
			}
		})
	}
}

func TestSeatMoves(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	move := func(t *testing.T, key, from, to string) error {
		t.Helper()
		if from != "" {
			if err := f.s.Deactivate(ctx, f.req(key, from)); err != nil {
				t.Fatal(err)
			}
		}
		_, err := f.s.Activate(ctx, f.req(key, to))
		return err
	}
	rehosts := func(id string) int { return f.license(t, id).RehostCount }

	// max_rehosts 0: reinstalling on the same machine is free; another machine is refused.
	locked := f.issue(t, "locked")
	a := fp()
	if err := move(t, locked.Key, "", a); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := move(t, locked.Key, a, a); err != nil {
			t.Fatalf("reinstall: %v", err)
		}
	}
	if err := move(t, locked.Key, a, fp()); !errors.Is(err, ErrRehostLimit) {
		t.Fatalf("move with max_rehosts 0: %v", err)
	}
	es := f.events(t)
	if e := es[len(es)-1]; e.Action != "activation.create" || e.Outcome != auditevent.OutcomeFailure || !strings.Contains(e.Details, "rehost limit") {
		t.Errorf("refusal audited as %+v", e)
	}
	if rehosts(locked.License.ID) != 0 {
		t.Errorf("rehost_count %d", rehosts(locked.License.ID))
	}

	// max_activations 1, max_rehosts 2: two moves to new machines; going back
	// to a machine seen before doesn't count.
	is := f.issue(t, "moves")
	m1, m2, m3, m4 := fp(), fp(), fp(), fp()
	if err := move(t, is.Key, "", m1); err != nil {
		t.Fatal(err)
	}
	for i, step := range [][2]string{{m1, m2}, {m2, m3}, {m3, m1}, {m1, m2}} {
		if err := move(t, is.Key, step[0], step[1]); err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
	}
	if rehosts(is.License.ID) != 2 {
		t.Errorf("rehost_count %d", rehosts(is.License.ID))
	}
	if err := move(t, is.Key, m2, m4); !errors.Is(err, ErrRehostLimit) {
		t.Fatalf("third move: %v", err)
	}
	// An upgrade reset (ADR-0013) allows moves again.
	f.tx(t, f.a, func(tx *ent.Tx) error { return tx.License.UpdateOneID(is.License.ID).SetRehostCount(0).Exec(ctx) })
	if err := move(t, is.Key, "", m4); err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if rehosts(is.License.ID) != 1 {
		t.Errorf("rehost_count %d", rehosts(is.License.ID))
	}

	// Machines are counted, not activation rows: a reinstall doesn't use up
	// the second seat's first activation.
	two := f.issue(t, "pro") // max_activations 2
	x := fp()
	if err := move(t, two.Key, "", x); err != nil {
		t.Fatal(err)
	}
	if err := move(t, two.Key, x, x); err != nil {
		t.Fatal(err)
	}
	if err := move(t, two.Key, "", fp()); err != nil || rehosts(two.License.ID) != 0 {
		t.Errorf("second machine: %v, rehost_count %d", err, rehosts(two.License.ID))
	}

	// Without max_rehosts, moves are unlimited (seats still bounded) and counted.
	pro := f.issue(t, "pro") // max_activations 2
	prev := ""
	for i := range 5 {
		next := fp()
		if err := move(t, pro.Key, prev, next); err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
		prev = next
	}
	if rehosts(pro.License.ID) != 3 {
		t.Errorf("rehost_count %d", rehosts(pro.License.ID))
	}
}

func TestGrace(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "pro") // grace 60s
	machine := fp()
	if _, err := f.s.Activate(ctx, f.req(is.Key, machine)); err != nil {
		t.Fatal(err)
	}
	// The term ended a moment ago.
	f.tx(t, f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET expires_at = issued_at + interval '1 millisecond' WHERE id = $1`, is.License.ID)
		return err
	})
	l := f.license(t, is.License.ID)
	got, err := f.s.Refresh(ctx, f.req(is.Key, machine))
	if err != nil {
		t.Fatalf("refresh in grace: %v", err)
	}
	if want := l.ExpiresAt.UTC().Truncate(time.Second); !got.Claims.Expires.Equal(want) || got.Claims.Grace != time.Minute || !got.Claims.IssuedAt.After(want.Add(-time.Second)) {
		t.Errorf("claims %+v", got.Claims)
	}
	// The SDK, half a minute after the term's end: in grace.
	later := got
	later.Claims.IssuedAt = got.Claims.Expires.Add(30 * time.Second)
	if _, status, err := f.open(t, later, machine); err != nil || status != licensefile.StatusGrace {
		t.Errorf("Open = %v %v", status, err)
	}
	// No new activations once the term has ended.
	if _, err := f.s.Activate(ctx, f.req(is.Key, fp())); !errors.Is(err, ErrExpired) {
		t.Errorf("new activation in grace: %v", err)
	}
	// Past the grace, refresh is refused too.
	f.tx(t, f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET grace_seconds = 0 WHERE id = $1`, is.License.ID)
		return err
	})
	if _, err := f.s.Refresh(ctx, f.req(is.Key, machine)); !errors.Is(err, ErrExpired) {
		t.Errorf("refresh past grace: %v", err)
	}
}
