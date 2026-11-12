-- Archive becomes reversible (ADR-0015, amended 2026-11-12): an update keeps
-- archived_at, sets it from NULL to the database clock (archive), or clears it
-- (restore). Still never to a made-up date; USING still admits only the row
-- the statement's snapshot saw (snapshot match), so a stale writer changes nothing.
ALTER POLICY archive_once ON "products" RENAME TO archive_or_restore;
ALTER POLICY archive_or_restore ON "products"
  WITH CHECK (EXISTS (SELECT 1 FROM "products" o WHERE o."id" = "products"."id"
    AND ("products"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "products"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes')
      OR (o."archived_at" IS NOT NULL AND "products"."archived_at" IS NULL))));
ALTER POLICY archive_once ON "features" RENAME TO archive_or_restore;
ALTER POLICY archive_or_restore ON "features"
  WITH CHECK (EXISTS (SELECT 1 FROM "features" o WHERE o."id" = "features"."id"
    AND ("features"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "features"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes')
      OR (o."archived_at" IS NOT NULL AND "features"."archived_at" IS NULL))));
ALTER POLICY archive_once ON "plans" RENAME TO archive_or_restore;
ALTER POLICY archive_or_restore ON "plans"
  WITH CHECK (EXISTS (SELECT 1 FROM "plans" o WHERE o."id" = "plans"."id"
    AND ("plans"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "plans"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes')
      OR (o."archived_at" IS NOT NULL AND "plans"."archived_at" IS NULL))));
ALTER POLICY archive_once ON "customers" RENAME TO archive_or_restore;
ALTER POLICY archive_or_restore ON "customers"
  WITH CHECK (EXISTS (SELECT 1 FROM "customers" o WHERE o."id" = "customers"."id"
    AND ("customers"."archived_at" IS NOT DISTINCT FROM o."archived_at"
      OR (o."archived_at" IS NULL AND "customers"."archived_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes')
      OR (o."archived_at" IS NOT NULL AND "customers"."archived_at" IS NULL))));
