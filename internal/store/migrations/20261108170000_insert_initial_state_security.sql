-- More one-way states start unset (ADR-0013, ADR-0029, ADR-0027), as
-- insert_unarchived and insert_active do: a serving pool can't insert a
-- license already activated, an activation already deactivated, or an
-- invitation already accepted or revoked. Activation sets first_activated_at
-- and deactivation sets deactivated_at later, audited; acceptance and
-- revocation update the invitation. The tenant pool's invitation INSERT grant
-- already leaves the outcome columns out; the platform pool (tenant
-- onboarding) has full INSERT, so the policy is what keeps its invitations
-- open. The migrator stays exempt. No triggers (ADR-0009).
CREATE POLICY insert_unactivated ON "licenses" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("first_activated_at" IS NULL);
CREATE POLICY insert_active ON "activations" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("deactivated_at" IS NULL);
CREATE POLICY insert_open ON "invitations" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("accepted_at" IS NULL AND "accepted_by" IS NULL AND "revoked_at" IS NULL);
