package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

type licensed struct {
	catalog
	customer *ent.Customer
	license  *ent.License
	key      string
}

// newLicense issues a license the way the licensing service will: a new key,
// encrypted and bound to the row, with its lookup hash and a plan snapshot.
func newLicense(t *testing.T, d *DB, kr *secrets.Keyring) licensed {
	t.Helper()
	ctx := context.Background()
	l := licensed{catalog: newCatalog(t, d), key: licensekey.New()}
	err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		var err error
		if l.customer, err = tx.Customer.Create().SetTenantID(l.tenant.ID).SetName("Contoso").
			SetEmail("it@contoso.example").SetExternalRefs(map[string]string{"stripe": "cus_123"}).Save(ctx); err != nil {
			return err
		}
		id := ids.License()
		ct, err := kr.Encrypt([]byte(l.key), secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: l.tenant.ID, RowID: id})
		if err != nil {
			return err
		}
		lookup, err := kr.LookupHash(secrets.PurposeLicenseKey, []byte(l.key))
		if err != nil {
			return err
		}
		l.license, err = tx.License.Create().SetID(id).SetTenantID(l.tenant.ID).SetProductID(l.product.ID).
			SetPlanID(l.plan.ID).SetCustomerID(l.customer.ID).
			SetKeyCiphertext(ct).SetKeyLookup(lookup).SetKeyHint(l.key[len(l.key)-6:]).
			SetPlanSlug(l.plan.Slug).SetExpiryBasis(license.ExpiryBasis(l.plan.ExpiryBasis)).SetNillableDurationMonths(l.plan.DurationMonths).
			SetOfflineAllowed(l.plan.OfflineAllowed).SetLeaseSeconds(l.plan.LeaseSeconds).SetGraceSeconds(l.plan.GraceSeconds).
			SetEntitlements(schema.LicenseEntitlements{Features: []string{}, Limits: map[string]int64{"max_users": 50}}).
			SetIssuedAt(time.Now()).Save(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLicenseIssueAndLookup(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	l := newLicense(t, d, kr)

	// A user pastes the key in another form; activation normalises it and
	// finds the license by hash under every keyring key, without decrypting.
	pasted, err := licensekey.Normalize(" " + l.key[3:] + "\n")
	if err != nil {
		t.Fatal(err)
	}
	err = d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		found, err := tx.License.Query().Where(license.KeyLookupIn(kr.LookupHashes(secrets.PurposeLicenseKey, []byte(pasted))...)).Only(ctx)
		if err != nil {
			return err
		}
		if found.ID != l.license.ID || found.Entitlements.Limits["max_users"] != 50 || *found.DurationMonths != 12 {
			t.Errorf("found %+v", found)
		}
		// Reveal (audited in the service): decrypts only with this row's binding.
		key, err := kr.Decrypt(found.KeyCiphertext, secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: l.tenant.ID, RowID: found.ID})
		if err != nil || string(key) != l.key {
			t.Errorf("reveal = %q, %v", key, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Another tenant can't find it even with the right key.
	other := newCatalog(t, d)
	_ = d.WithTenant(ctx, other.tenant.ID, func(tx *ent.Tx) error {
		if n, _ := tx.License.Query().Where(license.KeyLookup(l.license.KeyLookup)).Count(ctx); n != 0 {
			t.Error("another tenant found the license by key hash")
		}
		return nil
	})
}

// Foreign key checks bypass row-level security: licenses and activations may
// only reference rows of their own tenant (and the license's own product),
// even from the platform pool.
func TestLicenseReferencesStayInTenant(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	a, b := newLicense(t, d, kr), newLicense(t, d, kr)
	var otherProductPlan *ent.Plan
	if err := d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		var err error
		otherProductPlan, err = tx.Plan.Create().SetTenantID(a.tenant.ID).SetProductID(a.product2.ID).SetSlug("basic").SetName("Basic").Save(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for name, op := range map[string]func(tx *ent.Tx) error{
		"activation for another tenant's license": func(tx *ent.Tx) error {
			return tx.Activation.Create().SetTenantID(a.tenant.ID).SetLicenseID(b.license.ID).
				SetFingerprint("sha256:" + string(bytes.Repeat([]byte("a"), 64))).SetFpSource(activation.FpSourceMachineID).
				SetBinding(activation.BindingMachine).SetMode(activation.ModeOnline).SetFirstSeenAt(now).SetLastSeenAt(now).Exec(ctx)
		},
		"move license to another tenant's plan": func(tx *ent.Tx) error {
			return tx.License.UpdateOne(a.license).SetPlanID(b.plan.ID).Exec(ctx)
		},
		"move license to another product's plan": func(tx *ent.Tx) error {
			return tx.License.UpdateOne(a.license).SetPlanID(otherProductPlan.ID).Exec(ctx)
		},
		"license for another tenant's customer": func(tx *ent.Tx) error {
			return tx.License.Create().SetTenantID(a.tenant.ID).SetProductID(a.product.ID).SetPlanID(a.plan.ID).
				SetCustomerID(b.customer.ID).SetKeyCiphertext(a.license.KeyCiphertext).
				SetKeyLookup(string(bytes.Repeat([]byte("f"), 64))).SetKeyHint("AAAAAA").SetPlanSlug("pro").
				SetExpiryBasis(license.ExpiryBasisFromIssue).SetOfflineAllowed(false).SetLeaseSeconds(60).SetGraceSeconds(0).
				SetEntitlements(schema.LicenseEntitlements{Features: []string{}, Limits: map[string]int64{}}).SetIssuedAt(now).Exec(ctx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := d.WithPlatform(ctx, op); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	// Upgrading to another plan of the same product works.
	if err := d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		upgrade, err := tx.Plan.Create().SetTenantID(a.tenant.ID).SetProductID(a.product.ID).SetSlug("enterprise").SetName("Enterprise").Save(ctx)
		if err != nil {
			return err
		}
		return tx.License.UpdateOne(a.license).SetPlanID(upgrade.ID).SetPlanSlug(upgrade.Slug).Exec(ctx)
	}); err != nil {
		t.Fatalf("upgrade within product: %v", err)
	}
}

func TestLicenseImmutableInDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	l, other := newLicense(t, d, kr), newLicense(t, d, kr)
	now := time.Now()
	var act *ent.Activation
	if err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		var err error
		act, err = tx.Activation.Create().SetTenantID(l.tenant.ID).SetLicenseID(l.license.ID).
			SetFingerprint("sha256:" + string(bytes.Repeat([]byte("b"), 64))).SetFpSource(activation.FpSourceKubernetes).
			SetBinding(activation.BindingCluster).SetMode(activation.ModeOnline).SetFirstSeenAt(now).SetLastSeenAt(now).Save(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) error {
		return d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, q, args...)
			return err
		})
	}
	for name, q := range map[string][]any{
		"move license to another customer":   {`UPDATE licenses SET customer_id = $2 WHERE id = $1`, l.license.ID, other.customer.ID},
		"move license to another product":    {`UPDATE licenses SET product_id = $2 WHERE id = $1`, l.license.ID, l.product2.ID},
		"change license tenant":              {`UPDATE licenses SET tenant_id = $2 WHERE id = $1`, l.license.ID, other.tenant.ID},
		"backdate issue time":                {`UPDATE licenses SET issued_at = '2000-01-01' WHERE id = $1`, l.license.ID},
		"delete license":                     {`DELETE FROM licenses WHERE id = $1`, l.license.ID},
		"delete customer":                    {`DELETE FROM customers WHERE id = $1`, l.customer.ID},
		"delete activation":                  {`DELETE FROM activations WHERE id = $1`, act.ID},
		"change activation fingerprint":      {`UPDATE activations SET fingerprint = $2 WHERE id = $1`, act.ID, "sha256:" + string(bytes.Repeat([]byte("c"), 64))},
		"move activation to another license": {`UPDATE activations SET license_id = $2 WHERE id = $1`, act.ID, other.license.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec(q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s allowed", name)
			}
		})
	}
	// Lifecycle changes the service makes are allowed.
	for name, q := range map[string][]any{
		"suspend":            {`UPDATE licenses SET status = 'suspended', suspended_at = now() WHERE id = $1`, l.license.ID},
		"reinstate":          {`UPDATE licenses SET status = 'active', suspended_at = NULL WHERE id = $1`, l.license.ID},
		"rotate key":         {`UPDATE licenses SET key_lookup = $2 WHERE id = $1`, l.license.ID, string(bytes.Repeat([]byte("d"), 64))},
		"heartbeat":          {`UPDATE activations SET last_seen_at = now(), app_version = '2.1.0' WHERE id = $1`, act.ID},
		"deactivate":         {`UPDATE activations SET deactivated_at = now() WHERE id = $1`, act.ID},
		"anonymise customer": {`UPDATE customers SET name = 'erased', email = NULL WHERE id = $1`, l.customer.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec(q[0].(string), q[1:]...); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
}

func TestLicenseConstraintsInDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	l := newLicense(t, d, testKeyring(t))
	for name, q := range map[string][]any{
		"revoked without revoked_at":  {`UPDATE licenses SET status = 'revoked' WHERE id = $1`, l.license.ID},
		"revoked_at while active":     {`UPDATE licenses SET revoked_at = now() WHERE id = $1`, l.license.ID},
		"suspended without timestamp": {`UPDATE licenses SET status = 'suspended' WHERE id = $1`, l.license.ID},
		"unknown status":              {`UPDATE licenses SET status = 'expired' WHERE id = $1`, l.license.ID},
		"plaintext key":               {`UPDATE licenses SET key_ciphertext = 'LF-AAAAA-AAAAA' WHERE id = $1`, l.license.ID},
		"bad lookup hash":             {`UPDATE licenses SET key_lookup = 'xyz' WHERE id = $1`, l.license.ID},
		"bad key hint":                {`UPDATE licenses SET key_hint = 'lf-123' WHERE id = $1`, l.license.ID},
		"entitlements not an object":  {`UPDATE licenses SET entitlements = '[]' WHERE id = $1`, l.license.ID},
		"features not an array":       {`UPDATE licenses SET entitlements = '{"features": "sso", "limits": {}}' WHERE id = $1`, l.license.ID},
		"two durations":               {`UPDATE licenses SET duration_seconds = 60 WHERE id = $1`, l.license.ID},
		"negative rehosts":            {`UPDATE licenses SET rehost_count = -1 WHERE id = $1`, l.license.ID},
		"bad email":                   {`UPDATE customers SET email = 'not-an-email' WHERE id = $1`, l.customer.ID},
		"refs not an object":          {`UPDATE customers SET external_refs = '["x"]' WHERE id = $1`, l.customer.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := d.platformDB.ExecContext(ctx, q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
}

func TestOneActiveActivationPerMachine(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	l := newLicense(t, d, testKeyring(t))
	fp := "sha256:" + string(bytes.Repeat([]byte("e"), 64))
	now := time.Now()
	activate := func() (*ent.Activation, error) {
		var a *ent.Activation
		err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
			var err error
			a, err = tx.Activation.Create().SetTenantID(l.tenant.ID).SetLicenseID(l.license.ID).SetFingerprint(fp).
				SetFpSource(activation.FpSourceMachineID).SetBinding(activation.BindingMachine).SetMode(activation.ModeOffline).
				SetFirstSeenAt(now).SetLastSeenAt(now).Save(ctx)
			return err
		})
		return a, err
	}
	first, err := activate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := activate(); err == nil {
		t.Fatal("second active activation for the same machine accepted")
	}
	if err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		return tx.Activation.UpdateOne(first).SetDeactivatedAt(now).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := activate(); err != nil {
		t.Fatalf("re-activation after deactivation: %v", err)
	}
	for name, q := range map[string][]any{
		"last seen before first": {`UPDATE activations SET last_seen_at = first_seen_at - interval '1 second' WHERE license_id = $1`, l.license.ID},
		"bad fingerprint":        {`INSERT INTO activations (id, tenant_id, license_id, fingerprint, fp_source, binding, mode, first_seen_at, last_seen_at, created_at, updated_at) VALUES ($1, $2, $3, 'sha256:XYZ', 'env', 'machine', 'online', now(), now(), now(), now())`, ids.Activation(), l.tenant.ID, l.license.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := d.platformDB.ExecContext(ctx, q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
}
