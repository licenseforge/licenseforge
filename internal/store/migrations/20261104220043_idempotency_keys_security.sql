-- Idempotency keys: privileges and row-level security (ADR-0032). Tenant
-- table under canonical RLS. A key is claimed (inserted, outcome empty) and
-- completed (outcome set) in the operation's own transaction; a stored
-- outcome never changes. Keys are deleted only after 24 hours: by the tenant
-- pool when the same key is used again, by the platform pool's cleanup.
GRANT SELECT ON "idempotency_keys" TO licenseforge_app, licenseforge_platform;
GRANT INSERT ("id", "tenant_id", "credential", "key", "request_hash", "created_at") ON "idempotency_keys" TO licenseforge_app;
GRANT UPDATE ("status", "body") ON "idempotency_keys" TO licenseforge_app;
GRANT DELETE ON "idempotency_keys" TO licenseforge_app, licenseforge_platform;
ALTER TABLE "idempotency_keys" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "idempotency_keys" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "idempotency_keys" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
-- Claimed now, by the database clock, without an outcome.
CREATE POLICY claim_now ON "idempotency_keys" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK ("status" IS NULL AND "created_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes');
-- Only an empty claim gets its outcome: stored outcomes are immutable.
CREATE POLICY complete_once ON "idempotency_keys" AS RESTRICTIVE FOR UPDATE TO licenseforge_app
  USING ("status" IS NULL) WITH CHECK ("status" IS NOT NULL);
-- Only expired keys are deleted (a live key must keep answering).
CREATE POLICY delete_expired ON "idempotency_keys" AS RESTRICTIVE FOR DELETE TO licenseforge_app
  USING ("created_at" < clock_timestamp() - interval '24 hours');
CREATE POLICY platform_all ON "idempotency_keys" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY platform_delete_expired ON "idempotency_keys" AS RESTRICTIVE FOR DELETE TO licenseforge_platform
  USING ("created_at" < clock_timestamp() - interval '24 hours');
CREATE POLICY migrator_all ON "idempotency_keys" TO CURRENT_USER USING (true) WITH CHECK (true);
