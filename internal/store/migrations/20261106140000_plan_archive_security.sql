-- Plan archive is one-way and at the database clock (ADR-0015), as for
-- products and features (archive_once): an update keeps archived_at, or sets
-- it once, from NULL, to about now (5 minutes' skew); editing an archived
-- plan's name and terms still works. The subqueries read the statement's
-- snapshot; USING admits only a row whose archived_at is what that snapshot
-- saw, so an update or row lock that waited for a concurrent archive is
-- rechecked against the newer row and matches nothing, and an upsert is
-- refused. License issue locks the plan FOR SHARE with archived_at IS NULL
-- already, so an empty lock there is the same "no such plan" it answers for
-- an archived one. No triggers (ADR-0009).
CREATE POLICY archive_once ON "plans" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING (EXISTS (SELECT 1 FROM "plans" o WHERE o."id" = "plans"."id" AND o."archived_at" IS NOT DISTINCT FROM "plans"."archived_at"))
  WITH CHECK (EXISTS (SELECT 1 FROM "plans" o WHERE o."id" = "plans"."id"
    AND ("plans"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "plans"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'))));
