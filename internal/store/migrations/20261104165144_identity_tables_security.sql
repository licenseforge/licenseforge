-- Identity tables: privileges and row-level security (ADR-0029, ADR-0009).
-- Hand-written: Atlas does not manage grants or policies.
--
-- Three serving roles touch these tables:
--   licenseforge_app       tenant requests: members and invitations of the
--                          current tenant only (canonical tenant_isolation)
--   licenseforge_identity  the login path: reads identity data of every tenant
--                          (login runs before a tenant is known), never any
--                          licensing table; may add a membership only as the
--                          acceptance of a matching invitation (identity_accept)
--   licenseforge_platform  platform-admin work
-- ent inserts with RETURNING, so a role that inserts also needs SELECT.

GRANT USAGE ON SCHEMA public TO licenseforge_identity;
GRANT EXECUTE ON FUNCTION app_tenant_id() TO licenseforge_identity;

-- Same-tenant keys (ADR-0009). Product rows carry scope_all = false and point
-- at (tenant_id, id, scope_all) of their invitation or membership, so an
-- all-products invitation or membership can't have product rows (and a
-- membership can't switch to all products while it still has them).
ALTER TABLE "invitation_products" ADD CONSTRAINT "invitation_products_invitation_same_tenant"
  FOREIGN KEY ("tenant_id", "invitation_id", "scope_all") REFERENCES "invitations" ("tenant_id", "id", "scope_all");
ALTER TABLE "invitation_products" ADD CONSTRAINT "invitation_products_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_invitation_same_tenant"
  FOREIGN KEY ("tenant_id", "invitation_id") REFERENCES "invitations" ("tenant_id", "id");
ALTER TABLE "membership_products" ADD CONSTRAINT "membership_products_membership_same_tenant"
  FOREIGN KEY ("tenant_id", "membership_id", "scope_all") REFERENCES "memberships" ("tenant_id", "id", "scope_all");
ALTER TABLE "membership_products" ADD CONSTRAINT "membership_products_product_same_tenant"
  FOREIGN KEY ("tenant_id", "product_id") REFERENCES "products" ("tenant_id", "id");

-- tenants: identity reads id, slug and name (tenant switcher, slug -> ID).
-- ponytail: no reserved platform tenant exists yet; exclude it here when the
-- platform chain (ADR-0027) adds one.
GRANT SELECT ("id", "slug", "name") ON "tenants" TO licenseforge_identity;
CREATE POLICY identity_read ON "tenants" FOR SELECT TO licenseforge_identity USING (true);

-- users: global (no tenant_id). A tenant sees id, email and name of its own
-- members only; it can't add members, so it can't make any user visible.
-- Erasure (DELETE) is an owner-login command.
GRANT SELECT ("id", "email", "name") ON "users" TO licenseforge_app;
GRANT SELECT ON "users" TO licenseforge_identity;
GRANT INSERT ("id", "issuer", "subject", "email", "email_verified", "name", "last_login_at", "created_at", "updated_at")
  ON "users" TO licenseforge_identity;
GRANT UPDATE ("email", "email_verified", "name", "last_login_at", "updated_at") ON "users" TO licenseforge_identity;
GRANT SELECT, UPDATE ON "users" TO licenseforge_platform;
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "users" FORCE ROW LEVEL SECURITY;
CREATE POLICY users_member_of_tenant ON "users" FOR SELECT TO licenseforge_app
  USING (EXISTS (SELECT 1 FROM "memberships" m WHERE m."user_id" = "users"."id" AND m."tenant_id" = app_tenant_id()));
CREATE POLICY identity_all ON "users" TO licenseforge_identity USING (true) WITH CHECK (true);
CREATE POLICY platform_all ON "users" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "users" TO CURRENT_USER USING (true) WITH CHECK (true);

-- invitations: tenant admins create and revoke; identity marks one accepted
-- after inserting its membership (identity_mark_accepted). Never deleted by
-- serving roles; role, scope, email and token never change.
GRANT SELECT, INSERT ON "invitations" TO licenseforge_app;
GRANT UPDATE ("revoked_at", "updated_at") ON "invitations" TO licenseforge_app;
GRANT SELECT ON "invitations" TO licenseforge_identity;
GRANT UPDATE ("accepted_at", "accepted_by", "updated_at") ON "invitations" TO licenseforge_identity;
GRANT SELECT, INSERT, UPDATE ON "invitations" TO licenseforge_platform;
ALTER TABLE "invitations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "invitations" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "invitations" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
-- The inviter is a member of the tenant: no spoofed attribution, no probing
-- which user IDs exist through the foreign key.
CREATE POLICY inviter_is_member ON "invitations" AS RESTRICTIVE FOR INSERT TO licenseforge_app
  WITH CHECK (EXISTS (SELECT 1 FROM "memberships" m WHERE m."tenant_id" = "invitations"."tenant_id" AND m."user_id" = "invitations"."invited_by"));
CREATE POLICY identity_read ON "invitations" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY identity_mark_accepted ON "invitations" FOR UPDATE TO licenseforge_identity
  USING ("accepted_at" IS NULL AND "revoked_at" IS NULL AND "expires_at" > clock_timestamp())
  WITH CHECK ("accepted_by" IS NOT NULL AND EXISTS (SELECT 1 FROM "memberships" m
    WHERE m."invitation_id" = "invitations"."id" AND m."user_id" = "invitations"."accepted_by"));
CREATE POLICY platform_all ON "invitations" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "invitations" TO CURRENT_USER USING (true) WITH CHECK (true);

GRANT SELECT, INSERT ON "invitation_products" TO licenseforge_app;
GRANT SELECT ON "invitation_products" TO licenseforge_identity;
GRANT SELECT, INSERT ON "invitation_products" TO licenseforge_platform;
ALTER TABLE "invitation_products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "invitation_products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "invitation_products" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY identity_read ON "invitation_products" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY platform_all ON "invitation_products" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "invitation_products" TO CURRENT_USER USING (true) WITH CHECK (true);

-- memberships: only the acceptance of an open, matching invitation creates
-- one (identity_accept), in the invitation's tenant, with its role and scope,
-- for a user whose verified email matches (NFC, case-insensitive, the same
-- function on both sides) and, if the invitation is bound to an issuer, from
-- that issuer. invitation_id is unique: an invitation is used once.
GRANT SELECT, DELETE ON "memberships" TO licenseforge_app;
GRANT UPDATE ("role", "scope_all", "updated_at") ON "memberships" TO licenseforge_app;
GRANT SELECT, INSERT ON "memberships" TO licenseforge_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON "memberships" TO licenseforge_platform;
ALTER TABLE "memberships" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "memberships" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "memberships" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY identity_read ON "memberships" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY identity_accept ON "memberships" FOR INSERT TO licenseforge_identity
  WITH CHECK ("tenant_id" = app_tenant_id() AND EXISTS (SELECT 1 FROM "invitations" i JOIN "users" u ON u."id" = "memberships"."user_id"
    WHERE i."id" = "memberships"."invitation_id" AND i."tenant_id" = "memberships"."tenant_id"
      AND i."role" = "memberships"."role" AND i."scope_all" = "memberships"."scope_all"
      AND i."accepted_at" IS NULL AND i."revoked_at" IS NULL AND i."expires_at" > clock_timestamp()
      AND u."email_verified" AND u."disabled_at" IS NULL
      AND lower(normalize(u."email", NFC)) = lower(normalize(i."email", NFC))
      AND (i."issuer" IS NULL OR i."issuer" = u."issuer")));
CREATE POLICY platform_all ON "memberships" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "memberships" TO CURRENT_USER USING (true) WITH CHECK (true);

-- membership_products: identity copies exactly the invitation's products.
GRANT SELECT, INSERT, DELETE ON "membership_products" TO licenseforge_app;
GRANT SELECT, INSERT ON "membership_products" TO licenseforge_identity;
GRANT SELECT, INSERT, DELETE ON "membership_products" TO licenseforge_platform;
ALTER TABLE "membership_products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "membership_products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "membership_products" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY identity_read ON "membership_products" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY identity_copy_scope ON "membership_products" FOR INSERT TO licenseforge_identity
  WITH CHECK ("tenant_id" = app_tenant_id() AND EXISTS (SELECT 1 FROM "memberships" m
    JOIN "invitation_products" ip ON ip."invitation_id" = m."invitation_id" AND ip."tenant_id" = m."tenant_id"
    WHERE m."id" = "membership_products"."membership_id" AND ip."product_id" = "membership_products"."product_id"));
CREATE POLICY platform_all ON "membership_products" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "membership_products" TO CURRENT_USER USING (true) WITH CHECK (true);

-- audit_events: identity records an acceptance in the invitation's tenant, in
-- the same transaction (ADR-0027). audit.Record reads the chain head.
-- ponytail: exclude the reserved platform tenant here once it exists.
GRANT SELECT, INSERT ON "audit_events" TO licenseforge_identity;
CREATE POLICY identity_audit ON "audit_events" TO licenseforge_identity
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
