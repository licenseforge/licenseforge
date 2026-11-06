-- License transitions (ADR-0013, ADR-0027): revocation is final, and the
-- states are reached at the database clock, as the service does
-- (internal/licenses: suspend, reinstate, revoke), so a raw UPDATE from a
-- serving pool can't un-revoke a license or back- or forward-date a
-- transition, unaudited.
--
-- USING: a revoked license is out of an UPDATE's (and a row lock's) reach.
-- It's evaluated on the row version the statement finally updates, so an
-- UPDATE that waited for a concurrent revoke changes nothing either. Code
-- that locks a license re-reads it unlocked when the lock comes back empty
-- (a revoked license needs no lock: nothing about it changes again).
-- WITH CHECK: revoked_at is unset or about now (it can only be set from
-- unset, since revoked rows can't be updated); suspended_at is unset, about
-- now, or what the row had (a suspended license's other updates). The
-- subquery reads the statement's snapshot; a back-dated suspension racing a
-- concurrent transition could slip through it, which only misdates a
-- reversible state. The migrator stays exempt. No triggers (ADR-0009).
CREATE POLICY license_transitions ON "licenses" AS RESTRICTIVE FOR UPDATE TO licenseforge_app, licenseforge_platform
  USING ("revoked_at" IS NULL)
  WITH CHECK (
    ("revoked_at" IS NULL OR "revoked_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes')
    AND ("suspended_at" IS NULL
      OR "suspended_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'
      OR EXISTS (SELECT 1 FROM "licenses" o WHERE o."id" = "licenses"."id" AND o."suspended_at" = "licenses"."suspended_at")));
