-- Modify "tenants" table
ALTER TABLE "tenants" ADD COLUMN "test" boolean NOT NULL DEFAULT false;
-- Test mode (ADR-0047): the tenant switcher shows it (identity login).
GRANT SELECT ("test") ON "tenants" TO licenseforge_identity;
-- Set at creation, never changed. The serving login has no UPDATE grant on
-- the column; the platform pool (UPDATE on the table) is held by this policy.
CREATE POLICY test_fixed ON "tenants" AS RESTRICTIVE FOR UPDATE TO licenseforge_platform
  USING (true)
  WITH CHECK (EXISTS (SELECT 1 FROM "tenants" o WHERE o."id" = "tenants"."id" AND o."test" = "tenants"."test"));
