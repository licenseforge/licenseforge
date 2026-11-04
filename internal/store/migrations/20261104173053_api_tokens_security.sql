-- API tokens: privileges and row-level security (ADR-0019, ADR-0029).
-- Tenant pool only; the identity login has no access. Tokens are looked up
-- by hash under the URL's tenant, never across tenants.

ALTER TABLE "api_token_products" ADD CONSTRAINT "api_token_products_token_same_tenant"
  FOREIGN KEY ("tenant_id", "api_token_id", "scope_all") REFERENCES "api_tokens" ("tenant_id", "id", "scope_all");
ALTER TABLE "api_token_products" ADD CONSTRAINT "api_token_products_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");

-- A token starts unused and unrevoked; afterwards only its last use and its
-- revocation change. Never deleted.
GRANT SELECT ON "api_tokens" TO licenseforge_app;
GRANT INSERT ("id", "tenant_id", "name", "role", "scope_all", "token_hash", "display", "created_by", "expires_at", "created_at", "updated_at")
  ON "api_tokens" TO licenseforge_app;
GRANT UPDATE ("last_used_at", "revoked_at", "updated_at") ON "api_tokens" TO licenseforge_app;
GRANT SELECT ON "api_tokens" TO licenseforge_platform;
GRANT UPDATE ("revoked_at", "updated_at") ON "api_tokens" TO licenseforge_platform;
ALTER TABLE "api_tokens" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "api_tokens" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "api_tokens" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
-- The creator is a member of the tenant who may create this token (no spoofed
-- attribution, no probing user IDs through the foreign key): an owner or admin
-- with every product, and only owners create owner tokens (authz.CanAssign,
-- enforced here too).
CREATE POLICY creator_is_member ON "api_tokens" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK (EXISTS (SELECT 1 FROM "memberships" m WHERE m."tenant_id" = "api_tokens"."tenant_id" AND m."user_id" = "api_tokens"."created_by"
    AND m."scope_all" AND (m."role" = 'owner' OR (m."role" = 'admin' AND "api_tokens"."role" <> 'owner'))));
-- Times by the database clock (created_at is client-set): created now (5
-- minutes' skew), expiring in the future and at most a year away.
CREATE POLICY expiry_from_now ON "api_tokens" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK ("expires_at" > clock_timestamp() AND "expires_at" <= clock_timestamp() + interval '1 year'
    AND "created_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes');
-- Revocation is one-way: a revoked token can't be used (last_used_at) or
-- un-revoked. Every update records a use or the revocation (last_used_at is
-- never reset, which would also hide use and reopen the scope); a use is
-- within the token's life and neither is future-dated.
CREATE POLICY not_revoked ON "api_tokens" AS RESTRICTIVE FOR UPDATE TO licenseforge_app
  USING ("revoked_at" IS NULL)
  WITH CHECK (("last_used_at" IS NOT NULL OR "revoked_at" IS NOT NULL)
    AND ("last_used_at" IS NULL OR ("last_used_at" <= "expires_at" AND "last_used_at" <= clock_timestamp() + interval '5 minutes'))
    AND ("revoked_at" IS NULL OR "revoked_at" BETWEEN clock_timestamp() - interval '5 minutes' AND clock_timestamp() + interval '5 minutes'));
-- A use only moves forward, to about now: it can't be backdated, cleared or
-- written after expiry. The subquery reads the row before this update (the
-- statement's snapshot). Residual (accepted, no triggers per ADR-0009): two
-- concurrent writers can move last_used_at back by at most 5 minutes, since a
-- waiting update compares with its snapshot, not the version committed
-- meanwhile. Record use in one DB-side statement, e.g.
-- SET last_used_at = GREATEST(coalesce(last_used_at, '-infinity'), clock_timestamp()),
-- and treat a refusal as a no-op (never fail authentication on it).
CREATE POLICY use_moves_forward ON "api_tokens" AS RESTRICTIVE FOR UPDATE TO licenseforge_app
  USING (true)
  WITH CHECK (EXISTS (SELECT 1 FROM "api_tokens" o WHERE o."id" = "api_tokens"."id"
    AND ("api_tokens"."last_used_at" IS NOT DISTINCT FROM o."last_used_at"
      OR ("api_tokens"."last_used_at" >= clock_timestamp() - interval '5 minutes'
        AND "api_tokens"."last_used_at" >= coalesce(o."last_used_at", '-infinity')))));
CREATE POLICY platform_all ON "api_tokens" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY platform_no_unrevoke ON "api_tokens" AS RESTRICTIVE FOR UPDATE TO licenseforge_platform
  USING ("revoked_at" IS NULL) WITH CHECK (true);
CREATE POLICY migrator_all ON "api_tokens" TO CURRENT_USER USING (true) WITH CHECK (true);

-- Scope is fixed at creation: products only in the transaction that inserted
-- the token (its row version is ours: xmin), never used or revoked. A later
-- update creates a new row version, but every allowed update sets last_used_at
-- or revoked_at, which this policy refuses. Fails closed for a token inserted
-- in a savepoint (subtransaction xid). ponytail: a token left unused and
-- unrevoked for ~2^32 transactions could match a recycled xid; tokens expire
-- within a year, long before that on any real workload.
GRANT SELECT, INSERT ON "api_token_products" TO licenseforge_app;
GRANT SELECT ON "api_token_products" TO licenseforge_platform;
ALTER TABLE "api_token_products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "api_token_products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "api_token_products" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY new_token ON "api_token_products" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK (EXISTS (SELECT 1 FROM "api_tokens" t WHERE t."id" = "api_token_products"."api_token_id"
    AND t."last_used_at" IS NULL AND t."revoked_at" IS NULL AND t."xmin" = xid(pg_current_xact_id())));
CREATE POLICY platform_all ON "api_token_products" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "api_token_products" TO CURRENT_USER USING (true) WITH CHECK (true);
