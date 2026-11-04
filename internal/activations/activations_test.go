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
		c.MaxOffline == nil || *c.MaxOffline != 2*time.Hour || c.Grace != time.Minute ||
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
	if want := l.ExpiresAt.UTC().Truncate(time.Second); !got.Claims.Expires.Equal(want) || got.Claims.RefreshAfter.After(want) {
		t.Errorf("exp %v refresh %v, license expires %v", got.Claims.Expires, got.Claims.RefreshAfter, l.ExpiresAt)
	}
}
