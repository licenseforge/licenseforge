-- MFA enforcement (ADR-0038): the session check resolves the tenant on the
-- identity pool and compares the session's assurance with the tenant's
-- policy, so that login may read the policy (it already reads slug and ID).
GRANT SELECT ("mfa_policy") ON "tenants" TO licenseforge_identity;
