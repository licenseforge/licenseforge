-- API tokens: privileges and row-level security (ADR-0019, ADR-0029).
-- Tenant pool only; the identity login has no access. Tokens are looked up
-- by hash under the URL's tenant, never across tenants.

ALTER TABLE "api_token_products" ADD CONSTRAINT "api_token_products_token_same_tenant"
  FOREIGN KEY ("tenant_id", "api_token_id", "scope_all") REFERENCES "api_tokens" ("tenant_id", "id", "scope_all");
ALTER TABLE "api_token_products" ADD CONSTRAINT "api_token_products_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");

-- A token starts unused and unrevoked; afterwards only its last use and its
-- revocation change. Never deleted.
GRANT SELECT ON "api_tokens" TO licenseforge_app;
GRANT INSERT ("id", "tenant_id", "name", "role", "scope_all", "token_hash", "display", "created_by", "expires_at", "created_at", "updated_at")
  ON "api_tokens" TO licenseforge_app;
GRANT UPDATE ("last_used_at", "revoked_at", "updated_at") ON "api_tokens" TO licenseforge_app;
GRANT SELECT ON "api_tokens" TO licenseforge_platform;
GRANT UPDATE ("revoked_at", "updated_at") ON "api_tokens" TO licenseforge_platform;
ALTER TABLE "api_tokens" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "api_tokens" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "api_tokens" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
-- The creator is a member of the tenant (no spoofed attribution, no probing
-- user IDs through the foreign key).
CREATE POLICY creator_is_member ON "api_tokens" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK (EXISTS (SELECT 1 FROM "memberships" m WHERE m."tenant_id" = "api_tokens"."tenant_id" AND m."user_id" = "api_tokens"."created_by"));
-- Revocation is one-way: a revoked token can't be used (last_used_at) or
-- un-revoked.
CREATE POLICY not_revoked ON "api_tokens" AS RESTRICTIVE FOR UPDATE TO licenseforge_app
  USING ("revoked_at" IS NULL) WITH CHECK (true); -- what may change: the column grants
CREATE POLICY platform_all ON "api_tokens" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "api_tokens" TO CURRENT_USER USING (true) WITH CHECK (true);

-- Scope is fixed at creation: products only on a token never used or revoked.
GRANT SELECT, INSERT ON "api_token_products" TO licenseforge_app;
GRANT SELECT ON "api_token_products" TO licenseforge_platform;
ALTER TABLE "api_token_products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "api_token_products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "api_token_products" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY new_token ON "api_token_products" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK (EXISTS (SELECT 1 FROM "api_tokens" t WHERE t."id" = "api_token_products"."api_token_id"
    AND t."last_used_at" IS NULL AND t."revoked_at" IS NULL));
CREATE POLICY platform_all ON "api_token_products" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "api_token_products" TO CURRENT_USER USING (true) WITH CHECK (true);
