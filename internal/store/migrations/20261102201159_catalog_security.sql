-- Catalog tables: same-tenant keys, privileges and row-level security
-- (ADR-0009, ADR-0015). Hand-written; same pattern as the security migration.

-- Foreign key checks bypass row-level security, so a plain product_id
-- reference would let a tenant point at another tenant's product. These
-- composite keys require referenced rows to share tenant_id (and, for plan
-- features, product_id). The migrate tool keeps constraints ending in
-- _same_tenant, which ent can't model.
ALTER TABLE "features" ADD CONSTRAINT "features_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");
ALTER TABLE "plans" ADD CONSTRAINT "plans_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");
ALTER TABLE "plan_features" ADD CONSTRAINT "plan_features_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");
ALTER TABLE "plan_features" ADD CONSTRAINT "plan_features_plan_same_tenant"
  FOREIGN KEY ("product_id", "plan_id") REFERENCES "plans" ("product_id", "id");
ALTER TABLE "plan_features" ADD CONSTRAINT "plan_features_feature_same_tenant"
  FOREIGN KEY ("product_id", "feature_id") REFERENCES "features" ("product_id", "id");

GRANT SELECT, INSERT, UPDATE, DELETE ON "features", "plans", "plan_features" TO licenseforge_app, licenseforge_platform;

ALTER TABLE "features" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "features" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "features" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "features" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "features" TO CURRENT_USER USING (true) WITH CHECK (true);

ALTER TABLE "plans" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "plans" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "plans" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "plans" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "plans" TO CURRENT_USER USING (true) WITH CHECK (true);

ALTER TABLE "plan_features" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "plan_features" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "plan_features" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "plan_features" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "plan_features" TO CURRENT_USER USING (true) WITH CHECK (true);
