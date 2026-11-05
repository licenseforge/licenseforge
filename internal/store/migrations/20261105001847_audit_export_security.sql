-- Audit export (ADR-0036): privileges and row-level security. Only the
-- platform pool, the one serving login that reads every chain, registers
-- sinks and leases and advances cursors. The tenant and identity pools get
-- nothing. Removing a sink (and with it its cursors) is an owner-login step.
GRANT SELECT, INSERT ON "audit_export_sinks" TO licenseforge_platform;
ALTER TABLE "audit_export_sinks" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_export_sinks" FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_all ON "audit_export_sinks" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "audit_export_sinks" TO CURRENT_USER USING (true) WITH CHECK (true);

GRANT SELECT, INSERT ON "audit_export_cursors" TO licenseforge_platform;
GRANT UPDATE ("seq", "claimed_by", "claimed_until") ON "audit_export_cursors" TO licenseforge_platform;
ALTER TABLE "audit_export_cursors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_export_cursors" FORCE ROW LEVEL SECURITY;
-- Canonical (ADR-0009), though the tenant pool has no privileges here.
CREATE POLICY tenant_isolation ON "audit_export_cursors" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "audit_export_cursors" TO licenseforge_platform USING (true) WITH CHECK (true);
-- A new cursor starts at the chain's start (no anchors yet: seq 0), so it
-- can't skip entries the prune gate then treats as exported.
CREATE POLICY start_at_zero ON "audit_export_cursors" AS RESTRICTIVE FOR INSERT TO licenseforge_platform
  WITH CHECK ("seq" = 0);
-- A cursor only moves forward, and only to an entry of its chain that exists.
-- The subquery reads the row as it was before this update.
CREATE POLICY forward_to_entry ON "audit_export_cursors" AS RESTRICTIVE FOR UPDATE TO licenseforge_platform
  USING (true)
  WITH CHECK (EXISTS (SELECT 1 FROM "audit_export_cursors" o WHERE o."id" = "audit_export_cursors"."id" AND o."seq" <= "audit_export_cursors"."seq")
    AND ("seq" = 0 OR EXISTS (SELECT 1 FROM "audit_events" e WHERE e."tenant_id" = "audit_export_cursors"."tenant_id" AND e."seq" = "audit_export_cursors"."seq")));
CREATE POLICY migrator_all ON "audit_export_cursors" TO CURRENT_USER USING (true) WITH CHECK (true);
