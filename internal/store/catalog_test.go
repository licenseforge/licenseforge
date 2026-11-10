package store

import (
	"context"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/planfeature"
	"licenseforge.io/licenseforge/internal/store/ids"
)

type catalog struct {
	tenant   *ent.Tenant
	product  *ent.Product
	feature  *ent.Feature
	plan     *ent.Plan
	product2 *ent.Product
	feature2 *ent.Feature
}

// newCatalog creates a tenant with two products, a feature on each and a plan
// on the first, through the tenant pool as normal requests would.
func newCatalog(t *testing.T, d *DB) catalog {
	t.Helper()
	ctx := context.Background()
	c := catalog{tenant: createTenants(t, d, 1)[0]}
	err := d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
		var err error
		if c.product, err = tx.Product.Create().SetTenantID(c.tenant.ID).SetSlug("db").SetName("DB").Save(ctx); err != nil {
			return err
		}
		if c.product2, err = tx.Product.Create().SetTenantID(c.tenant.ID).SetSlug("cache").SetName("Cache").Save(ctx); err != nil {
			return err
		}
		if c.feature, err = tx.Feature.Create().SetTenantID(c.tenant.ID).SetProductID(c.product.ID).
			SetKey("max_users").SetName("Users").SetType(feature.TypeLimit).Save(ctx); err != nil {
			return err
		}
		if c.feature2, err = tx.Feature.Create().SetTenantID(c.tenant.ID).SetProductID(c.product2.ID).
			SetKey("sso").SetName("SSO").SetType(feature.TypeBoolean).Save(ctx); err != nil {
			return err
		}
		c.plan, err = tx.Plan.Create().SetTenantID(c.tenant.ID).SetProductID(c.product.ID).
			SetSlug("pro").SetName("Pro").SetDurationMonths(12).Save(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogHappyPath(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	c := newCatalog(t, d)
	err := d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
		if err := tx.PlanFeature.Create().SetTenantID(c.tenant.ID).SetProductID(c.product.ID).
			SetPlanID(c.plan.ID).SetFeatureID(c.feature.ID).SetFeatureType(planfeature.FeatureTypeLimit).SetLimitValue(50).Exec(ctx); err != nil {
			return err
		}
		pfs, err := tx.Plan.QueryPlanFeatures(c.plan).WithFeature().All(ctx)
		if err != nil {
			return err
		}
		if len(pfs) != 1 || pfs[0].Edges.Feature.Key != "max_users" || *pfs[0].LimitValue != 50 {
			t.Errorf("plan features = %+v", pfs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Foreign key checks bypass row-level security, so the same-tenant keys must
// reject references to other tenants' or other products' rows, even from the
// platform pool, which sees every tenant.
func TestCatalogReferencesStayInTenantAndProduct(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	a, b := newCatalog(t, d), newCatalog(t, d)
	for name, op := range map[string]func(tx *ent.Tx) error{
		"plan for another tenant's product": func(tx *ent.Tx) error {
			return tx.Plan.Create().SetTenantID(a.tenant.ID).SetProductID(b.product.ID).SetSlug("x").SetName("x").Exec(ctx)
		},
		"feature for another tenant's product": func(tx *ent.Tx) error {
			return tx.Feature.Create().SetTenantID(a.tenant.ID).SetProductID(b.product.ID).
				SetKey("x").SetName("x").SetType(feature.TypeBoolean).Exec(ctx)
		},
		"plan feature with another tenant's feature": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(a.product.ID).
				SetPlanID(a.plan.ID).SetFeatureID(b.feature.ID).SetFeatureType(planfeature.FeatureTypeLimit).SetLimitValue(1).Exec(ctx)
		},
		"plan feature with another product's feature": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(a.product.ID).
				SetPlanID(a.plan.ID).SetFeatureID(a.feature2.ID).SetFeatureType(planfeature.FeatureTypeBoolean).Exec(ctx)
		},
		"plan feature entirely in another tenant": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(b.product.ID).
				SetPlanID(b.plan.ID).SetFeatureID(b.feature.ID).SetFeatureType(planfeature.FeatureTypeLimit).SetLimitValue(1).Exec(ctx)
		},
		"plan feature claiming the other product": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(a.product2.ID).
				SetPlanID(a.plan.ID).SetFeatureID(a.feature2.ID).SetFeatureType(planfeature.FeatureTypeBoolean).Exec(ctx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := d.WithPlatform(ctx, op)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			t.Log(err)
		})
	}
}

func TestFeatureKeysAreNeverReused(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	c := newCatalog(t, d)
	err := d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
		return tx.Feature.UpdateOne(c.feature).SetArchivedAt(time.Now()).Exec(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
		return tx.Feature.Create().SetTenantID(c.tenant.ID).SetProductID(c.product.ID).
			SetKey("max_users").SetName("Users again").SetType(feature.TypeBoolean).Exec(ctx)
	})
	if err == nil {
		t.Fatal("an archived feature's key was reused")
	}
}

// The database enforces formats and ranges itself, also for writers that skip
// ent's validators (raw SQL, manual fixes).
func TestCatalogConstraintsInDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	c := newCatalog(t, d)
	now := time.Now()
	for name, q := range map[string][]any{
		"bad feature key":      {`INSERT INTO features (id, tenant_id, product_id, key, name, type, created_at, updated_at) VALUES ($1, $2, $3, 'Max-Users', 'x', 'boolean', $4, $4)`, ids.Feature(), c.tenant.ID, c.product.ID, now},
		"unknown feature type": {`INSERT INTO features (id, tenant_id, product_id, key, name, type, created_at, updated_at) VALUES ($1, $2, $3, 'k', 'x', 'flag', $4, $4)`, ids.Feature(), c.tenant.ID, c.product.ID, now},
		"limit below -1":       {`INSERT INTO plan_features (id, tenant_id, product_id, plan_id, feature_id, feature_type, limit_value, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'limit', -2, $6, $6)`, ids.PlanFeature(), c.tenant.ID, c.product.ID, c.plan.ID, c.feature.ID, now},
		"limit above 2^53-1":   {`INSERT INTO plan_features (id, tenant_id, product_id, plan_id, feature_id, feature_type, limit_value, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'limit', 9007199254740992, $6, $6)`, ids.PlanFeature(), c.tenant.ID, c.product.ID, c.plan.ID, c.feature.ID, now},
		"zero duration":        {`UPDATE plans SET duration_seconds = 0 WHERE id = $1`, c.plan.ID},
		"grace over 100 years": {`UPDATE plans SET grace_seconds = 3153600001 WHERE id = $1`, c.plan.ID},
		"negative max_offline": {`UPDATE plans SET max_offline_seconds = -1 WHERE id = $1`, c.plan.ID},
		"zero max_activations": {`UPDATE plans SET max_activations = 0 WHERE id = $1`, c.plan.ID},
		"zero updates_months":  {`UPDATE plans SET updates_months = 0 WHERE id = $1`, c.plan.ID},
		"updates_months 1201":  {`UPDATE plans SET updates_months = 1201 WHERE id = $1`, c.plan.ID},
		"unknown expiry basis": {`UPDATE plans SET expiry_basis = 'whenever' WHERE id = $1`, c.plan.ID},
		"bad plan id format":   {`INSERT INTO plans (id, tenant_id, product_id, slug, name, expiry_basis, offline_allowed, lease_seconds, grace_seconds, created_at, updated_at) VALUES ('pln_x', $1, $2, 'p2', 'x', 'from_issue', false, 60, 0, $3, $3)`, c.tenant.ID, c.product.ID, now},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := d.platformDB.ExecContext(ctx, q[0].(string), q[1:]...)
			if err == nil {
				t.Fatalf("%s accepted by the database", name)
			}
			t.Log(err)
		})
	}
}

// Row-level security (not only missing privileges) stops cross-tenant
// deletes: plan_features is the one catalog table tenants may delete from.
func TestCrossTenantDeleteAffectsNothing(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	a, b := newCatalog(t, d), newCatalog(t, d)
	if err := d.WithTenant(ctx, b.tenant.ID, func(tx *ent.Tx) error {
		return tx.PlanFeature.Create().SetTenantID(b.tenant.ID).SetProductID(b.product.ID).SetPlanID(b.plan.ID).
			SetFeatureID(b.feature.ID).SetFeatureType(planfeature.FeatureTypeLimit).SetLimitValue(5).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.WithTenant(ctx, a.tenant.ID, func(tx *ent.Tx) error {
		n, err := tx.PlanFeature.Delete().Where(planfeature.PlanID(b.plan.ID)).Exec(ctx)
		if err == nil && n != 0 {
			t.Errorf("tenant A deleted %d of B's plan features", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.WithTenant(ctx, b.tenant.ID, func(tx *ent.Tx) error {
		n, err := tx.PlanFeature.Query().Count(ctx)
		if n != 1 {
			t.Errorf("B has %d plan features after A's delete, want 1", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// Keys, slugs, types and ownership never change and catalog rows are never
// deleted (licenses carry keys and slugs), enforced by column-level grants.
func TestCatalogImmutableInDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	c := newCatalog(t, d)
	other := newCatalog(t, d)
	exec := func(q string, args ...any) error {
		return d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, q, args...)
			return err
		})
	}
	for name, q := range map[string][]any{
		"rename feature key":       {`UPDATE features SET key = 'seats' WHERE id = $1`, c.feature.ID},
		"change feature type":      {`UPDATE features SET type = 'boolean' WHERE id = $1`, c.feature.ID},
		"move feature to product":  {`UPDATE features SET product_id = $2 WHERE id = $1`, c.feature.ID, c.product2.ID},
		"change feature tenant":    {`UPDATE features SET tenant_id = $2 WHERE id = $1`, c.feature.ID, other.tenant.ID},
		"delete feature":           {`DELETE FROM features WHERE id = $1`, c.feature2.ID},
		"rename plan slug":         {`UPDATE plans SET slug = 'pro-old' WHERE id = $1`, c.plan.ID},
		"delete plan":              {`DELETE FROM plans WHERE id = $1`, c.plan.ID},
		"rename product slug":      {`UPDATE products SET slug = 'renamed' WHERE id = $1`, c.product.ID},
		"delete product":           {`DELETE FROM products WHERE id = $1`, c.product2.ID},
		"repoint plan feature":     {`UPDATE plan_features SET plan_id = $2 WHERE plan_id = $1`, c.plan.ID, c.plan.ID},
		"change plan feature type": {`UPDATE plan_features SET feature_type = 'boolean' WHERE plan_id = $1`, c.plan.ID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec(q[0].(string), q[1:]...); err == nil {
				t.Fatalf("%s allowed", name)
			}
		})
	}
	// Editable columns still work.
	if err := exec(`UPDATE features SET name = 'Seats', unit = 'seats', archived_at = now() WHERE id = $1`, c.feature.ID); err != nil {
		t.Fatalf("editing a feature's name: %v", err)
	}
	if err := exec(`UPDATE plans SET name = 'Pro 2026', grace_seconds = 86400 WHERE id = $1`, c.plan.ID); err != nil {
		t.Fatalf("editing a plan's terms: %v", err)
	}
	if err := exec(`UPDATE products SET name = 'Database' WHERE id = $1`, c.product.ID); err != nil {
		t.Fatalf("renaming a product: %v", err)
	}
}

// A plan feature's limit_value must match the feature's type, and it can't
// claim a type the feature doesn't have.
func TestPlanFeatureMatchesFeatureType(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	c := newCatalog(t, d)
	var boolFeature *ent.Feature
	if err := d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
		var err error
		boolFeature, err = tx.Feature.Create().SetTenantID(c.tenant.ID).SetProductID(c.product.ID).
			SetKey("export").SetName("Export").SetType(feature.TypeBoolean).Save(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	insert := `INSERT INTO plan_features (id, tenant_id, product_id, plan_id, feature_id, feature_type, limit_value, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`
	for name, tc := range map[string]struct {
		feature *ent.Feature
		typ     string
		limit   any
		ok      bool
	}{
		"boolean grant":             {boolFeature, "boolean", nil, true},
		"limit grant":               {c.feature, "limit", 10, true},
		"boolean with a limit":      {boolFeature, "boolean", 500, false},
		"limit without a value":     {c.feature, "limit", nil, false},
		"limit claimed for boolean": {boolFeature, "limit", 5, false},
		"boolean claimed for limit": {c.feature, "boolean", nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
				_, err := tx.ExecContext(ctx, insert, ids.PlanFeature(), c.tenant.ID, c.product.ID, c.plan.ID,
					tc.feature.ID, tc.typ, tc.limit, now)
				return err
			})
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v, got err %v", tc.ok, err)
			}
			if err == nil { // undo so cases stay independent
				_ = d.WithTenant(ctx, c.tenant.ID, func(tx *ent.Tx) error {
					_, err := tx.ExecContext(ctx, `DELETE FROM plan_features WHERE feature_id = $1`, tc.feature.ID)
					return err
				})
			}
		})
	}
}
