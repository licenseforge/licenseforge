-- Sessions: privileges and row-level security (ADR-0020, ADR-0029). Global
-- table: the login path (identity pool) creates, reads, touches and ends
-- sessions; the platform pool reads and ends them (suspension); tenants never
-- see them. Times by the database clock.
GRANT SELECT, DELETE ON "sessions" TO licenseforge_identity;
GRANT INSERT ("id", "user_id", "token_hash", "created_at", "expires_at", "last_seen_at") ON "sessions" TO licenseforge_identity;
GRANT UPDATE ("last_seen_at") ON "sessions" TO licenseforge_identity;
GRANT SELECT, DELETE ON "sessions" TO licenseforge_platform;
ALTER TABLE "sessions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "sessions" FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_all ON "sessions" TO licenseforge_identity USING (true) WITH CHECK (true);
-- A session starts now, for an enabled user, and lasts at most a day.
CREATE POLICY new_session ON "sessions" AS RESTRICTIVE FOR INSERT TO licenseforge_identity
  WITH CHECK ("created_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'
    AND "expires_at" <= clock_timestamp() + interval '1 day'
    AND EXISTS (SELECT 1 FROM "users" u WHERE u."id" = "sessions"."user_id" AND u."disabled_at" IS NULL));
-- last_seen_at only moves forward, to about now.
CREATE POLICY seen_forward ON "sessions" AS RESTRICTIVE FOR UPDATE TO licenseforge_identity
  USING (true)
  WITH CHECK ("last_seen_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes');
CREATE POLICY platform_all ON "sessions" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "sessions" TO CURRENT_USER USING (true) WITH CHECK (true);
