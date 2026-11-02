-- Customers, licenses, activations: same-tenant keys, privileges and
-- row-level security (ADR-0009, ADR-0013, ADR-0025). Same pattern as the
-- catalog security migration.

-- Same-tenant keys (foreign key checks bypass row-level security).
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");
-- Includes the plan slug (immutable on plans), so the snapshot's plan_slug,
-- signed into licenses as the "plan" claim, always names the license's plan.
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_plan_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id", "plan_id", "plan_slug") REFERENCES "plans" ("tenant_id", "product_id", "id", "slug");
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_customer_same_tenant"
  FOREIGN KEY ("tenant_id", "customer_id") REFERENCES "customers" ("tenant_id", "id");
-- Includes the binding: an activation must bind what its license requires
-- (machine or cluster; site licenses with bind_type none have no activations),
-- and a license's bind_type can't change while it has activations.
ALTER TABLE "activations" ADD CONSTRAINT "activations_license_same_tenant"
  FOREIGN KEY ("tenant_id", "license_id", "binding") REFERENCES "licenses" ("tenant_id", "id", "bind_type");

-- Privileges. Nothing here is deleted: customers are archived, licenses
-- revoked, activations deactivated. GDPR erasure nulls or replaces the
-- customer's name, email and external_refs, its licenses' external_refs and its
-- activations' hostnames (all updatable). Ownership, product, customer, issue
-- time and the activation's identity never change. Rules that need the old
-- value (revocation is final, deactivation can't be undone, first activation
-- is set once) are enforced by the licensing service and recorded in the
-- audit log; CHECKs can't see the previous row and triggers aren't used.
GRANT SELECT, INSERT ON "customers", "licenses", "activations" TO licenseforge_app, licenseforge_platform;
GRANT UPDATE ("name", "email", "external_refs", "archived_at", "updated_at")
  ON "customers" TO licenseforge_app, licenseforge_platform;
GRANT UPDATE ("plan_id", "type", "status", "key_ciphertext", "key_lookup", "key_hint",
  "plan_slug", "bind_type", "expiry_basis", "duration_months", "duration_seconds", "max_activations", "max_rehosts",
  "offline_allowed", "lease_seconds", "max_offline_seconds", "grace_seconds", "entitlements",
  "expires_at", "first_activated_at", "updates_until", "suspended_at", "revoked_at", "rehost_count",
  "external_refs", "updated_at")
  ON "licenses" TO licenseforge_app, licenseforge_platform;
GRANT UPDATE ("hostname", "app_version", "sdk_version", "last_seen_at", "deactivated_at", "updated_at")
  ON "activations" TO licenseforge_app, licenseforge_platform;

ALTER TABLE "customers" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "customers" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "customers" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "customers" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "customers" TO CURRENT_USER USING (true) WITH CHECK (true);

ALTER TABLE "licenses" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "licenses" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "licenses" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "licenses" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "licenses" TO CURRENT_USER USING (true) WITH CHECK (true);

ALTER TABLE "activations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "activations" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "activations" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "activations" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "activations" TO CURRENT_USER USING (true) WITH CHECK (true);
