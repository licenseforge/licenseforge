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
			SetBindType(license.BindType(l.plan.BindType)).SetOfflineAllowed(l.plan.OfflineAllowed).SetLeaseSeconds(l.plan.LeaseSeconds).SetGraceSeconds(l.plan.GraceSeconds).
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
				SetExpiryBasis(license.ExpiryBasisFromIssue).SetBindType(license.BindTypeMachine).SetOfflineAllowed(false).SetLeaseSeconds(60).SetGraceSeconds(0).
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
	// The snapshot's slug must name the plan: the old slug with the new plan is refused.
	if err := d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		return tx.License.UpdateOneID(a.license.ID).SetPlanSlug("pro").Exec(ctx)
	}); err == nil {
		t.Error("plan_slug disagreeing with plan_id accepted")
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
			SetFingerprint("sha256:" + string(bytes.Repeat([]byte("b"), 64))).SetFpSource(activation.FpSourceMachineID).
			SetBinding(activation.BindingMachine).SetMode(activation.ModeOnline).SetFirstSeenAt(now).SetLastSeenAt(now).Save(ctx)
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
		"change activation source":           {`UPDATE activations SET fp_source = 'env' WHERE id = $1`, act.ID},
		"change activation binding":          {`UPDATE activations SET binding = 'cluster' WHERE id = $1`, act.ID},
		"change activation mode":             {`UPDATE activations SET mode = 'offline' WHERE id = $1`, act.ID},
		"backdate first seen":                {`UPDATE activations SET first_seen_at = '2000-01-01' WHERE id = $1`, act.ID},
		"change activation created_at":       {`UPDATE activations SET created_at = now() WHERE id = $1`, act.ID},
		"move customer to another tenant":    {`UPDATE customers SET tenant_id = $2 WHERE id = $1`, l.customer.ID, other.tenant.ID},
		"change binding with activations":    {`UPDATE licenses SET bind_type = 'cluster' WHERE id = $1`, l.license.ID},
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
		"erase customer":     {`UPDATE customers SET name = 'erased', email = NULL, external_refs = '{}' WHERE id = $1`, l.customer.ID},
		"erase license refs": {`UPDATE licenses SET external_refs = '{}' WHERE customer_id = $1`, l.customer.ID},
		"erase hostnames":    {`UPDATE activations SET hostname = NULL WHERE license_id = $1`, l.license.ID},
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
		"customer refs not strings":   {`UPDATE customers SET external_refs = '{"crm": {"email": "x@y"}}' WHERE id = $1`, l.customer.ID},
		"license refs not strings":    {`UPDATE licenses SET external_refs = '{"n": 5}' WHERE id = $1`, l.license.ID},
		"short ciphertext":            {`UPDATE licenses SET key_ciphertext = 'v1.k1.A' WHERE id = $1`, l.license.ID},
		"feature not a string":        {`UPDATE licenses SET entitlements = '{"features": [1], "limits": {}}' WHERE id = $1`, l.license.ID},
		"feature null":                {`UPDATE licenses SET entitlements = '{"features": [null], "limits": {}}' WHERE id = $1`, l.license.ID},
		"feature bad key":             {`UPDATE licenses SET entitlements = '{"features": ["Max-Users"], "limits": {}}' WHERE id = $1`, l.license.ID},
		"limit a string":              {`UPDATE licenses SET entitlements = '{"features": [], "limits": {"n": "ten"}}' WHERE id = $1`, l.license.ID},
		"limit below -1":              {`UPDATE licenses SET entitlements = '{"features": [], "limits": {"n": -5}}' WHERE id = $1`, l.license.ID},
		"limit fractional":            {`UPDATE licenses SET entitlements = '{"features": [], "limits": {"n": 1.5}}' WHERE id = $1`, l.license.ID},
		"limit above 2^53-1":          {`UPDATE licenses SET entitlements = '{"features": [], "limits": {"n": 9007199254740992}}' WHERE id = $1`, l.license.ID},
		"limit null":                  {`UPDATE licenses SET entitlements = '{"features": [], "limits": {"n": null}}' WHERE id = $1`, l.license.ID},
		"expires before issue":        {`UPDATE licenses SET expires_at = issued_at - interval '1 day' WHERE id = $1`, l.license.ID},
		"activated before issue":      {`UPDATE licenses SET first_activated_at = issued_at - interval '1 day' WHERE id = $1`, l.license.ID},
		"perpetual with expiry":       {`UPDATE licenses SET duration_months = NULL, expires_at = issued_at + interval '1 day' WHERE id = $1`, l.license.ID},
		"unstarted with expiry":       {`UPDATE licenses SET expiry_basis = 'from_first_activation', expires_at = issued_at + interval '1 day' WHERE id = $1`, l.license.ID},
		"started without expiry":      {`UPDATE licenses SET expiry_basis = 'from_first_activation', first_activated_at = issued_at WHERE id = $1`, l.license.ID},
		"rehosts over the limit":      {`UPDATE licenses SET max_rehosts = 0, rehost_count = 5 WHERE id = $1`, l.license.ID},
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
		"deactivated before first seen":           {`UPDATE activations SET deactivated_at = first_seen_at - interval '1 second' WHERE license_id = $1`, l.license.ID},
		"kubernetes source bound to a machine":    {`INSERT INTO activations (id, tenant_id, license_id, fingerprint, fp_source, binding, mode, first_seen_at, last_seen_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 'kubernetes', 'machine', 'online', now(), now(), now(), now())`, ids.Activation(), l.tenant.ID, l.license.ID, "sha256:" + string(bytes.Repeat([]byte("1"), 64))},
		"cluster activation on a machine license": {`INSERT INTO activations (id, tenant_id, license_id, fingerprint, fp_source, binding, mode, first_seen_at, last_seen_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 'kubernetes', 'cluster', 'online', now(), now(), now(), now())`, ids.Activation(), l.tenant.ID, l.license.ID, "sha256:" + string(bytes.Repeat([]byte("2"), 64))},
		"last seen before first":                  {`UPDATE activations SET last_seen_at = first_seen_at - interval '1 second' WHERE license_id = $1`, l.license.ID},
		"bad fingerprint":                         {`INSERT INTO activations (id, tenant_id, license_id, fingerprint, fp_source, binding, mode, first_seen_at, last_seen_at, created_at, updated_at) VALUES ($1, $2, $3, 'sha256:XYZ', 'env', 'machine', 'online', now(), now(), now(), now())`, ids.Activation(), l.tenant.ID, l.license.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := d.platformDB.ExecContext(ctx, q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
}

// The key hash index is per tenant: another tenant using the same hash is
// accepted, so a duplicate-key error can't reveal whether a key exists elsewhere.
func TestKeyLookupIsPerTenant(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	a, b := newLicense(t, d, kr), newLicense(t, d, kr)
	if err := d.WithTenant(ctx, b.tenant.ID, func(tx *ent.Tx) error {
		return tx.License.UpdateOne(b.license).SetKeyLookup(a.license.KeyLookup).Exec(ctx)
	}); err != nil {
		t.Fatalf("same hash in another tenant: %v", err)
	}
	// Within a tenant it stays unique.
	if err := d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET key_lookup = $2 WHERE id <> $1 AND tenant_id = $3`, a.license.ID, a.license.KeyLookup, a.tenant.ID)
		if err != nil {
			return err
		}
		second := newLicenseIn(t, tx, a, kr)
		return tx.License.UpdateOne(second).SetKeyLookup(a.license.KeyLookup).Exec(ctx)
	}); err == nil {
		t.Fatal("duplicate key hash within a tenant accepted")
	}
}

// newLicenseIn adds a second license for l's customer inside tx.
func newLicenseIn(t *testing.T, tx *ent.Tx, l licensed, kr *secrets.Keyring) *ent.License {
	t.Helper()
	ctx := context.Background()
	key := licensekey.New()
	id := ids.License()
	ct, _ := kr.Encrypt([]byte(key), secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: l.tenant.ID, RowID: id})
	lookup, _ := kr.LookupHash(secrets.PurposeLicenseKey, []byte(key))
	lic, err := tx.License.Create().SetID(id).SetTenantID(l.tenant.ID).SetProductID(l.product.ID).SetPlanID(l.plan.ID).
		SetCustomerID(l.customer.ID).SetKeyCiphertext(ct).SetKeyLookup(lookup).SetKeyHint(key[len(key)-6:]).
		SetPlanSlug(l.plan.Slug).SetExpiryBasis(license.ExpiryBasisFromIssue).SetBindType(license.BindTypeMachine).
		SetOfflineAllowed(false).SetLeaseSeconds(60).SetGraceSeconds(0).SetIssuedAt(time.Now()).
		SetEntitlements(schema.LicenseEntitlements{}).Save(ctx) // nil features/limits: stored as [] and {}
	if err != nil {
		t.Fatal(err)
	}
	return lic
}

func TestNilEntitlementsAreStoredEmpty(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	l := newLicense(t, d, kr)
	var lic *ent.License
	if err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		lic = newLicenseIn(t, tx, l, kr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := d.platformDB.QueryRowContext(ctx, `SELECT entitlements::text FROM licenses WHERE id = $1`, lic.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != `{"limits": {}, "features": []}` {
		t.Fatalf("entitlements stored as %s", raw)
	}
}

// Site licenses (bind_type none) have no activations; activations must bind
// what the license requires.
func TestActivationBindingMatchesLicense(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	l := newLicense(t, d, testKeyring(t))
	if err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		return tx.License.UpdateOne(l.license).SetBindType(license.BindTypeNone).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err := d.WithTenant(ctx, l.tenant.ID, func(tx *ent.Tx) error {
		return tx.Activation.Create().SetTenantID(l.tenant.ID).SetLicenseID(l.license.ID).
			SetFingerprint("sha256:" + string(bytes.Repeat([]byte("3"), 64))).SetFpSource(activation.FpSourceMachineID).
			SetBinding(activation.BindingMachine).SetMode(activation.ModeOnline).SetFirstSeenAt(now).SetLastSeenAt(now).Exec(ctx)
	})
	if err == nil {
		t.Fatal("activation on a site license accepted")
	}
}

// The tenant pool can't read another tenant's customers, licenses or activations.
func TestLicenseTablesAreTenantIsolated(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	kr := testKeyring(t)
	a, b := newLicense(t, d, kr), newLicense(t, d, kr)
	now := time.Now()
	if err := d.WithTenant(ctx, b.tenant.ID, func(tx *ent.Tx) error {
		return tx.Activation.Create().SetTenantID(b.tenant.ID).SetLicenseID(b.license.ID).
			SetFingerprint("sha256:" + string(bytes.Repeat([]byte("4"), 64))).SetFpSource(activation.FpSourceMachineID).
			SetBinding(activation.BindingMachine).SetMode(activation.ModeOnline).SetFirstSeenAt(now).SetLastSeenAt(now).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	_ = d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		if n, _ := tx.Customer.Query().Count(ctx); n != 1 {
			t.Errorf("tenant A sees %d customers, want only its own", n)
		}
		if n, _ := tx.License.Query().Count(ctx); n != 1 {
			t.Errorf("tenant A sees %d licenses, want only its own", n)
		}
		if n, _ := tx.Activation.Query().Count(ctx); n != 0 {
			t.Errorf("tenant A sees %d activations, want 0", n)
		}
		if n, _ := tx.License.Update().Where(license.ID(b.license.ID)).SetType(license.TypeDev).Save(ctx); n != 0 {
			t.Errorf("tenant A updated %d of B's licenses", n)
		}
		return nil
	})
}

// Rules that need the previous value are the licensing service's job (no
// triggers, CHECKs can't see the old row). This test pins that decision: if the
// database starts enforcing them, update ADR-0013 and the service.
func TestServiceEnforcedRulesAreNotInTheDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	l := newLicense(t, d, testKeyring(t))
	for name, q := range []string{
		`UPDATE licenses SET status = 'revoked', revoked_at = now() WHERE id = $1`,
		`UPDATE licenses SET status = 'active', revoked_at = NULL WHERE id = $1`, // un-revoke
	} {
		if _, err := d.platformDB.ExecContext(ctx, q, l.license.ID); err != nil {
			t.Fatalf("step %d: %v", name, err)
		}
	}
}
