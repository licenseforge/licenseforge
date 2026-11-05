DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_retention') THEN
    RAISE EXCEPTION 'create role licenseforge_retention NOLOGIN before migrating (as a database admin; see deploy/database-setup.sql, ADR-0036)';
  END IF;
END $$;

-- Audit retention (ADR-0036): the fifth login's privileges and policies, and
-- anchors. Needs the group role licenseforge_retention, which the operator
-- creates before migrating (deploy/database-setup.sql; the owner can't create
-- roles). Serving logins keep no DELETE on audit entries.
GRANT USAGE ON SCHEMA public TO licenseforge_retention;

-- audit_events: the retention login reads every chain, deletes only a prefix
-- that is at least 365 days old and at or below the chain's newest anchor
-- (the restrictive policy is the floor), and appends only its own
-- audit.retention entries (audit.Record).
GRANT SELECT, INSERT, DELETE ON "audit_events" TO licenseforge_retention;
CREATE POLICY retention_read ON "audit_events" FOR SELECT TO licenseforge_retention USING (true);
CREATE POLICY retention_record ON "audit_events" FOR INSERT TO licenseforge_retention
  WITH CHECK ("action" = 'audit.retention' AND "actor_type" = 'system' AND "occurred_at" >= now()); -- never backdated
CREATE POLICY retention_delete ON "audit_events" FOR DELETE TO licenseforge_retention USING (true);
CREATE POLICY retention_floor ON "audit_events" AS RESTRICTIVE FOR DELETE TO licenseforge_retention
  USING ("occurred_at" < now() - interval '365 days'
    AND "seq" <= (SELECT max(a."seq") FROM "audit_anchors" a WHERE a."tenant_id" = "audit_events"."tenant_id"));

-- audit_anchors: insert-only. An anchor names a real entry (seq and hash)
-- at least 365 days old that isn't its chain's last, and moves the chain's
-- start forward. Serving logins read anchors (Verify);
-- the anchors' SELECT policies never read audit_events, so the policies of
-- the two tables can't recurse.
GRANT SELECT ON "audit_anchors" TO licenseforge_app, licenseforge_platform;
GRANT SELECT, INSERT ON "audit_anchors" TO licenseforge_retention;
ALTER TABLE "audit_anchors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_anchors" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "audit_anchors" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "audit_anchors" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY retention_read ON "audit_anchors" FOR SELECT TO licenseforge_retention USING (true);
CREATE POLICY retention_anchor ON "audit_anchors" FOR INSERT TO licenseforge_retention
  WITH CHECK (EXISTS (SELECT 1 FROM "audit_events" e WHERE e."tenant_id" = "audit_anchors"."tenant_id"
      AND e."seq" = "audit_anchors"."seq" AND e."hash" = "audit_anchors"."hash"
      AND e."occurred_at" < now() - interval '365 days')
    AND EXISTS (SELECT 1 FROM "audit_events" e2 WHERE e2."tenant_id" = "audit_anchors"."tenant_id" AND e2."seq" > "audit_anchors"."seq")
    AND "seq" > COALESCE((SELECT max(a."seq") FROM "audit_anchors" a WHERE a."tenant_id" = "audit_anchors"."tenant_id"), 0));
CREATE POLICY migrator_all ON "audit_anchors" TO CURRENT_USER USING (true) WITH CHECK (true);

-- The export gate: the retention login reads sinks and cursors.
GRANT SELECT ON "audit_export_sinks", "audit_export_cursors" TO licenseforge_retention;
CREATE POLICY retention_read ON "audit_export_sinks" FOR SELECT TO licenseforge_retention USING (true);
CREATE POLICY retention_read ON "audit_export_cursors" FOR SELECT TO licenseforge_retention USING (true);
