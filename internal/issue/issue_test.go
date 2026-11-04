package issue

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
	"licenseforge.io/licenseforge/internal/store/storetest"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db                         *store.DB
	keys                       signing.Local
	kr                         *secrets.Keyring
	tenant, product, otherProd string
	plan                       *ent.Plan
	customer                   string
	kid                        string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, env.TenantURL, env.PlatformURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{db: d, kr: kr, keys: signing.Local{DB: d, Keys: kr}}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		tn, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
		if err == nil {
			f.tenant = tn.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	k, err := f.keys.Create(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	f.kid = k.ID
	if err := d.WithTenant(ctx, f.tenant, func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(f.tenant).SetSlug("acme-db").SetName("Acme DB").Save(ctx)
		if err != nil {
			return err
		}
		f.product = p.ID
		p2, err := tx.Product.Create().SetTenantID(f.tenant).SetSlug("other").SetName("Other").Save(ctx)
		if err != nil {
			return err
		}
		f.otherProd = p2.ID
		if f.plan, err = tx.Plan.Create().SetTenantID(f.tenant).SetProductID(f.product).SetSlug("site").SetName("Site").
			SetDurationMonths(12).SetBindType(plan.BindTypeNone).SetOfflineAllowed(true).SetGraceSeconds(3600).Save(ctx); err != nil {
			return err
		}
		c, err := tx.Customer.Create().SetTenantID(f.tenant).SetName("Contoso").SetEmail("it@contoso.example").Save(ctx)
		f.customer = c.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// newLicense creates a site license expiring in a year; change adjusts it.
func (f fixture) newLicense(t *testing.T, change func(*ent.LicenseCreate)) *ent.License {
	t.Helper()
	ctx := context.Background()
	var l *ent.License
	err := f.db.WithTenant(ctx, f.tenant, func(tx *ent.Tx) error {
		key, id := licensekey.New(), ids.License()
		ct, err := f.kr.Encrypt([]byte(key), secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: f.tenant, RowID: id})
		if err != nil {
			return err
		}
		lookup, err := f.kr.LookupHash(secrets.PurposeLicenseKey, []byte(key))
		if err != nil {
			return err
		}
		now := time.Now()
		c := tx.License.Create().SetID(id).SetTenantID(f.tenant).SetProductID(f.product).SetPlanID(f.plan.ID).
			SetCustomerID(f.customer).SetKeyCiphertext(ct).SetKeyLookup(lookup).SetKeyHint(key[len(key)-6:]).
			SetPlanSlug("site").SetExpiryBasis(license.ExpiryBasisFromIssue).SetDurationMonths(12).
			SetBindType(license.BindTypeNone).SetOfflineAllowed(true).SetLeaseSeconds(86400).SetGraceSeconds(3600).
			SetEntitlements(schema.LicenseEntitlements{Features: []string{"sso"}, Limits: map[string]int64{"nodes": 10}}).
			SetIssuedAt(now).SetExpiresAt(now.AddDate(1, 0, 0).Truncate(time.Second).Add(900 * time.Millisecond))
		if change != nil {
			change(c)
		}
		l, err = c.Save(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f fixture) as(role authz.Role, scope authz.Scope) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: "usr_test", TenantID: f.tenant, Role: role, Scope: scope})
}

var all = authz.Scope{All: true}

// lastEvent returns the newest audit entry of the tenant and checks the chain.
func (f fixture) lastEvent(t *testing.T) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	err := f.db.WithTenant(context.Background(), f.tenant, func(tx *ent.Tx) error {
		if _, err := audit.Verify(context.Background(), tx, f.tenant); err != nil {
			return err
		}
		var err error
		e, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).First(context.Background())
		if ent.IsNotFound(err) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOfflineFile(t *testing.T) {
	f := setup(t)
	l := f.newLicense(t, nil)
	now := time.Date(2026, 11, 4, 12, 0, 0, 999_000_000, time.UTC)
	is := Issuer{DB: f.db, Keys: f.keys, Now: func() time.Time { return now }}

	file, err := is.OfflineFile(f.as(authz.Manager, all), l.ID)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := f.keys.Public(context.Background(), f.tenant, f.kid)
	if err != nil {
		t.Fatal(err)
	}
	keys := licensefile.KeySet{{KID: pk.KID, Alg: licensefile.AlgEd25519, Key: pk.Key}}
	c, status, err := licensefile.Open(file, keys, licensefile.CheckOptions{Now: now, Product: "acme-db"})
	if err != nil || status != licensefile.StatusValid {
		t.Fatalf("Open = %v %v", status, err)
	}
	wantExp := l.ExpiresAt.UTC().Truncate(time.Second) // rounded down: never outlives the license
	if c.LicenseID != l.ID || c.Tenant != f.tenant || c.Plan != "site" || c.CustomerID != f.customer ||
		!c.IssuedAt.Equal(now.Truncate(time.Second)) || c.Expires == nil || !c.Expires.Equal(wantExp) ||
		c.Grace != time.Hour || c.Binding.Type != licensefile.BindNone ||
		!c.Entitlements.HasFeature("sso") || c.Entitlements.Limit("nodes") != 10 || c.CustomerName != "" {
		t.Errorf("claims = %+v", c)
	}
	e := f.lastEvent(t)
	if e == nil || e.Action != "license.offline_file" || e.Outcome != auditevent.OutcomeSuccess ||
		e.ObjectID == nil || *e.ObjectID != l.ID || e.ActorID == nil || *e.ActorID != "usr_test" {
		t.Errorf("audit = %+v", e)
	}
}

func TestOfflineFileDenied(t *testing.T) {
	f := setup(t)
	l := f.newLicense(t, nil)
	other := setup(t)
	is := Issuer{DB: f.db, Keys: f.keys}
	for name, ctx := range map[string]context.Context{
		"support can't export":   f.as(authz.Support, all),
		"scoped to another prod": f.as(authz.Manager, authz.Scope{Products: []string{f.otherProd}}),
		"unknown license":        f.as(authz.Manager, all),
	} {
		id := l.ID
		if name == "unknown license" {
			id = ids.License()
		}
		if _, err := is.OfflineFile(ctx, id); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: err = %v", name, err)
		}
		if e := f.lastEvent(t); e == nil || e.Outcome != auditevent.OutcomeDenied || *e.ObjectID != id {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
	// Another tenant's principal can't reach f's license, and its own chain
	// records the attempt.
	if _, err := (Issuer{DB: other.db, Keys: other.keys}).OfflineFile(other.as(authz.Owner, all), l.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("cross-tenant: err = %v", err)
	}
	if e := other.lastEvent(t); e == nil || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("cross-tenant audit = %+v", e)
	}
	if _, err := is.OfflineFile(context.Background(), l.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("no principal: err = %v", err)
	}
}

func TestOfflineFileNotIssuable(t *testing.T) {
	f := setup(t)
	is := Issuer{DB: f.db, Keys: f.keys}
	past := time.Now().Add(-time.Hour)
	for name, change := range map[string]func(*ent.LicenseCreate){
		"suspended":     func(c *ent.LicenseCreate) { c.SetStatus(license.StatusSuspended).SetSuspendedAt(time.Now()) },
		"revoked":       func(c *ent.LicenseCreate) { c.SetStatus(license.StatusRevoked).SetRevokedAt(time.Now()) },
		"offline off":   func(c *ent.LicenseCreate) { c.SetOfflineAllowed(false) },
		"machine bound": func(c *ent.LicenseCreate) { c.SetBindType(license.BindTypeMachine) },
		"expired":       func(c *ent.LicenseCreate) { c.SetIssuedAt(past.Add(-time.Hour)).SetExpiresAt(past) },
	} {
		l := f.newLicense(t, change)
		if _, err := is.OfflineFile(f.as(authz.Owner, all), l.ID); !errors.Is(err, ErrNotIssuable) {
			t.Errorf("%s: err = %v", name, err)
		}
		if e := f.lastEvent(t); e == nil || e.Outcome != auditevent.OutcomeFailure || *e.ObjectID != l.ID {
			t.Errorf("%s: audit = %+v", name, e)
		}
	}
}

// revokeWhileSigning revokes the license from inside Sign, as a concurrent
// request would.
type revokeWhileSigning struct {
	signing.Local
	f  fixture
	id string
}

func (r revokeWhileSigning) Sign(ctx context.Context, tenantID, kid string, msg []byte) ([]byte, error) {
	if err := r.f.db.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		return tx.License.UpdateOneID(r.id).SetStatus(license.StatusRevoked).SetRevokedAt(time.Now()).Exec(ctx)
	}); err != nil {
		return nil, err
	}
	return r.Local.Sign(ctx, tenantID, kid, msg)
}

func TestOfflineFileRevokedWhileSigning(t *testing.T) {
	f := setup(t)
	l := f.newLicense(t, nil)
	before := f.lastEvent(t)
	is := Issuer{DB: f.db, Keys: revokeWhileSigning{Local: f.keys, f: f, id: l.ID}}
	if file, err := is.OfflineFile(f.as(authz.Owner, all), l.ID); !errors.Is(err, ErrNotIssuable) || file != "" {
		t.Errorf("OfflineFile = %q, %v", file, err)
	}
	if e := f.lastEvent(t); (e == nil) != (before == nil) || (e != nil && e.Seq != before.Seq) {
		t.Errorf("an entry was recorded for a file that wasn't handed out: %+v", e)
	}
}

func TestOfflineFileNeedsActiveKey(t *testing.T) {
	f := setup(t)
	l := f.newLicense(t, nil)
	if err := f.db.WithTenant(context.Background(), f.tenant, func(tx *ent.Tx) error {
		return tx.SigningKey.UpdateOneID(f.kid).SetStatus("retired").SetRetiredAt(time.Now()).ClearPrivateKeyCiphertext().Exec(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (Issuer{DB: f.db, Keys: f.keys}).OfflineFile(f.as(authz.Owner, all), l.ID); !errors.Is(err, signing.ErrNoActiveKey) {
		t.Errorf("err = %v", err)
	}
}
