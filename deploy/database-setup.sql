-- One-time PostgreSQL setup for LicenseForge (ADR-0009). Run as an admin
-- (superuser, or rds_superuser / cloudsqlsuperuser on managed Postgres).
-- Replace the passwords, or use your cloud's IAM authentication.
--
-- Three logins, never shared:
--   licenseforge_owner     runs migrations (`licenseforge migrate`); owns the schema
--   licenseforge_api       serves tenant requests     (member of licenseforge_app)
--   licenseforge_admin     platform-admin operations  (member of licenseforge_platform)
-- The server refuses to start if the api/admin logins can bypass row-level
-- security (superuser, BYPASSRLS, CREATEROLE, owning tables, or membership in
-- such roles or in the other group).

-- Group roles referenced by migrations (cluster-wide, created once).
CREATE ROLE licenseforge_app NOLOGIN;
CREATE ROLE licenseforge_platform NOLOGIN;

CREATE ROLE licenseforge_owner LOGIN PASSWORD 'change-me-owner';
CREATE ROLE licenseforge_api   LOGIN PASSWORD 'change-me-api'   IN ROLE licenseforge_app;
CREATE ROLE licenseforge_admin LOGIN PASSWORD 'change-me-admin' IN ROLE licenseforge_platform;

CREATE DATABASE licenseforge OWNER licenseforge_owner;

-- Only these logins may connect. Group grants are cluster-wide, so this is what
-- keeps logins of another LicenseForge install on the same cluster out.
REVOKE CONNECT ON DATABASE licenseforge FROM PUBLIC;
GRANT CONNECT ON DATABASE licenseforge TO licenseforge_owner, licenseforge_api, licenseforge_admin;
