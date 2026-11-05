-- Product archive (ADR-0015): products are archived, never deleted. The
-- serving pools may set archived_at (the service sets it once); slug and
-- ownership stay immutable, and there is still no DELETE grant.
GRANT UPDATE ("archived_at") ON "products" TO licenseforge_app, licenseforge_platform;

-- Archive is one-way and at the database clock: an update keeps archived_at,
-- or sets it once, from NULL, to about now (5 minutes' skew). Un-archiving
-- or back- or future-dating it would let issue mint licenses again or hide
-- when it happened; renaming an archived product still works. The subquery
-- reads the row before this update (the statement's snapshot), as
-- api_tokens' use_moves_forward does. No triggers (ADR-0009).
CREATE POLICY archive_once ON "products" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING (true)
  WITH CHECK (EXISTS (SELECT 1 FROM "products" o WHERE o."id" = "products"."id"
    AND ("products"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "products"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'))));
