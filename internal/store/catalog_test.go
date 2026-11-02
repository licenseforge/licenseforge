package store

import (
	"context"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
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
			SetSlug("pro").SetName("Pro").SetDurationSeconds(365 * 24 * 3600).Save(ctx)
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
			SetPlanID(c.plan.ID).SetFeatureID(c.feature.ID).SetLimitValue(50).Exec(ctx); err != nil {
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
				SetPlanID(a.plan.ID).SetFeatureID(b.feature.ID).Exec(ctx)
		},
		"plan feature with another product's feature": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(a.product.ID).
				SetPlanID(a.plan.ID).SetFeatureID(a.feature2.ID).Exec(ctx)
		},
		"plan feature claiming the other product": func(tx *ent.Tx) error {
			return tx.PlanFeature.Create().SetTenantID(a.tenant.ID).SetProductID(a.product2.ID).
				SetPlanID(a.plan.ID).SetFeatureID(a.feature2.ID).Exec(ctx)
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
		"limit below -1":       {`INSERT INTO plan_features (id, tenant_id, product_id, plan_id, feature_id, limit_value, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, -2, $6, $6)`, ids.PlanFeature(), c.tenant.ID, c.product.ID, c.plan.ID, c.feature.ID, now},
		"limit above 2^53-1":   {`INSERT INTO plan_features (id, tenant_id, product_id, plan_id, feature_id, limit_value, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 9007199254740992, $6, $6)`, ids.PlanFeature(), c.tenant.ID, c.product.ID, c.plan.ID, c.feature.ID, now},
		"zero duration":        {`UPDATE plans SET duration_seconds = 0 WHERE id = $1`, c.plan.ID},
		"grace over 100 years": {`UPDATE plans SET grace_seconds = 3153600001 WHERE id = $1`, c.plan.ID},
		"negative max_offline": {`UPDATE plans SET max_offline_seconds = -1 WHERE id = $1`, c.plan.ID},
		"zero max_activations": {`UPDATE plans SET max_activations = 0 WHERE id = $1`, c.plan.ID},
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
