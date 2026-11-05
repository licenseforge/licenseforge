-- Policies that compare with the row as it was (a self-subquery in WITH
-- CHECK) read the statement's snapshot, but an update that waited for a
-- concurrent commit is rechecked against the newer row (READ COMMITTED's
-- EvalPlanQual): it could move last_used_at or an export cursor back past
-- what was committed meanwhile. USING now admits only a row whose guarded
-- column is what that snapshot saw, as archive_once on products does: such
-- an update changes nothing and an upsert (ON CONFLICT DO UPDATE) is
-- refused. Row locks (FOR UPDATE / FOR SHARE) take the same check, so a
-- caller that waited for a concurrent change locks nothing and must look
-- again in a new statement. No triggers (ADR-0009).
ALTER POLICY use_moves_forward ON "api_tokens"
  USING (EXISTS (SELECT 1 FROM "api_tokens" o WHERE o."id" = "api_tokens"."id" AND o."last_used_at" IS NOT DISTINCT FROM "api_tokens"."last_used_at"));
ALTER POLICY forward_to_entry ON "audit_export_cursors"
  USING (EXISTS (SELECT 1 FROM "audit_export_cursors" o WHERE o."id" = "audit_export_cursors"."id" AND o."seq" = "audit_export_cursors"."seq"));

-- Customer archive (ADR-0015) is one-way and at the database clock, as for
-- products: an update keeps archived_at, or sets it once, from NULL, to
-- about now (5 minutes' skew). Un-archiving or back- or future-dating it
-- would let issue mint licenses for the customer again or hide when it
-- happened; renaming an archived customer still works.
CREATE POLICY archive_once ON "customers" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING (EXISTS (SELECT 1 FROM "customers" o WHERE o."id" = "customers"."id" AND o."archived_at" IS NOT DISTINCT FROM "customers"."archived_at"))
  WITH CHECK (EXISTS (SELECT 1 FROM "customers" o WHERE o."id" = "customers"."id"
    AND ("customers"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "customers"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'))));
