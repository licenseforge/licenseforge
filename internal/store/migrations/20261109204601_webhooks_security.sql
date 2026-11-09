-- Outbound webhooks (ADR-0044): same-tenant keys, privileges and row-level
-- security. The tenant pool manages endpoints and their recovery actions; the
-- platform pool (the dispatcher) leases cursors, records deliveries and
-- disables endpoints. The identity and retention logins get nothing.

-- Foreign key checks bypass row-level security: cursors and delivery records
-- reference their endpoint within the same tenant.
ALTER TABLE "webhook_cursors" ADD CONSTRAINT "webhook_cursors_endpoint_same_tenant"
  FOREIGN KEY ("tenant_id", "endpoint_id") REFERENCES "webhook_endpoints" ("tenant_id", "id");
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_endpoint_same_tenant"
  FOREIGN KEY ("tenant_id", "endpoint_id") REFERENCES "webhook_endpoints" ("tenant_id", "id");

-- Endpoints: the tenant pool creates, edits and deletes them (with their
-- cursor and records, in one transaction); the dispatcher only disables.
GRANT SELECT, INSERT, DELETE ON "webhook_endpoints" TO licenseforge_app;
GRANT UPDATE ("url_ciphertext", "url_display", "events", "secret_ciphertext", "previous_secret_ciphertext",
  "previous_secret_until", "enabled", "disabled_reason", "updated_at") ON "webhook_endpoints" TO licenseforge_app;
GRANT SELECT ON "webhook_endpoints" TO licenseforge_platform;
GRANT UPDATE ("enabled", "disabled_reason", "updated_at") ON "webhook_endpoints" TO licenseforge_platform;
ALTER TABLE "webhook_endpoints" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "webhook_endpoints" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "webhook_endpoints" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "webhook_endpoints" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "webhook_endpoints" TO CURRENT_USER USING (true) WITH CHECK (true);

-- Cursors. The tenant pool never sees or writes the lease holder (a pod
-- name); it creates the cursor with its endpoint, deletes it with it, and
-- moves seq and resets retry state (re-enable, skip). The dispatcher writes
-- the lease and the delivery state, and can't create or delete cursors.
GRANT SELECT ("id", "tenant_id", "endpoint_id", "seq", "claimed_until", "attempts", "next_attempt_at") ON "webhook_cursors" TO licenseforge_app;
GRANT INSERT ("id", "tenant_id", "endpoint_id", "seq") ON "webhook_cursors" TO licenseforge_app;
GRANT UPDATE ("seq", "attempts", "next_attempt_at") ON "webhook_cursors" TO licenseforge_app;
GRANT DELETE ON "webhook_cursors" TO licenseforge_app;
GRANT SELECT ON "webhook_cursors" TO licenseforge_platform;
GRANT UPDATE ("seq", "claimed_by", "claimed_until", "attempts", "next_attempt_at") ON "webhook_cursors" TO licenseforge_platform;
ALTER TABLE "webhook_cursors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "webhook_cursors" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "webhook_cursors" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "webhook_cursors" TO licenseforge_platform USING (true) WITH CHECK (true);
-- A new cursor starts at or below its chain's end (entries or the anchor):
-- it can't skip events that don't exist yet. Not replaying history is the
-- application's rule (a lower bound would race concurrent commits).
CREATE POLICY start_at_end ON "webhook_cursors" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK ("seq" <= GREATEST(
    COALESCE((SELECT max(e."seq") FROM "audit_events" e WHERE e."tenant_id" = "webhook_cursors"."tenant_id"), 0),
    COALESCE((SELECT max(a."seq") FROM "audit_anchors" a WHERE a."tenant_id" = "webhook_cursors"."tenant_id"), 0)));
-- seq only moves forward, to an entry of its chain that exists or to the
-- chain's anchor (entries after the cursor were pruned). An update that
-- keeps seq (lease, retry state) is always allowed. The subquery reads the
-- row as it was before this update.
CREATE POLICY forward_to_entry ON "webhook_cursors" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING (true)
  WITH CHECK (EXISTS (SELECT 1 FROM "webhook_cursors" o WHERE o."id" = "webhook_cursors"."id"
    AND (o."seq" = "webhook_cursors"."seq" OR (o."seq" < "webhook_cursors"."seq" AND (
      EXISTS (SELECT 1 FROM "audit_events" e WHERE e."tenant_id" = "webhook_cursors"."tenant_id" AND e."seq" = "webhook_cursors"."seq")
      OR "webhook_cursors"."seq" = (SELECT max(a."seq") FROM "audit_anchors" a WHERE a."tenant_id" = "webhook_cursors"."tenant_id"))))));
-- The tenant pool only resets the retry count (re-enable, skip).
CREATE POLICY tenant_resets_attempts ON "webhook_cursors" AS RESTRICTIVE FOR UPDATE TO licenseforge_app
  USING (true) WITH CHECK ("attempts" = 0);
CREATE POLICY migrator_all ON "webhook_cursors" TO CURRENT_USER USING (true) WITH CHECK (true);

-- Delivery records: written by the dispatcher, read (the delivery log) and
-- deleted with their endpoint by the tenant pool; the dispatcher prunes
-- records older than 7 days. Records never change.
GRANT SELECT, DELETE ON "webhook_deliveries" TO licenseforge_app;
GRANT SELECT, INSERT, DELETE ON "webhook_deliveries" TO licenseforge_platform;
ALTER TABLE "webhook_deliveries" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "webhook_deliveries" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "webhook_deliveries" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "webhook_deliveries" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "webhook_deliveries" TO CURRENT_USER USING (true) WITH CHECK (true);
