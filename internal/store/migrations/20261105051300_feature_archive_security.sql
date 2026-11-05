-- Feature archive is one-way and at the database clock (ADR-0015), as for
-- products (archive_once on products): an update keeps archived_at, or sets
-- it once, from NULL, to about now (5 minutes' skew); renaming and editing
-- an archived feature still work. The subqueries read the statement's
-- snapshot; USING admits only a row whose archived_at is what that snapshot
-- saw, so an update or row lock that waited for a concurrent archive is
-- rechecked against the newer row and matches nothing (callers look again
-- in a new statement), and an upsert is refused. No triggers (ADR-0009).
CREATE POLICY archive_once ON "features" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING (EXISTS (SELECT 1 FROM "features" o WHERE o."id" = "features"."id" AND o."archived_at" IS NOT DISTINCT FROM "features"."archived_at"))
  WITH CHECK (EXISTS (SELECT 1 FROM "features" o WHERE o."id" = "features"."id"
    AND ("features"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "features"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'))));
