-- One-time PostgreSQL setup for LicenseForge (ADR-0009). Run as an admin
-- (superuser, or rds_superuser / cloudsqlsuperuser on managed Postgres), the
-- same admin for every statement. Replace the passwords, or use your cloud's
-- IAM authentication.
--
-- Create the logins with SQL as below. On Cloud SQL, users created through the
-- console or gcloud become members of cloudsqlsuperuser, and the server
-- refuses them.
--
-- Three logins, never shared:
--   licenseforge_owner     runs migrations (`licenseforge migrate`); owns the schema
--   licenseforge_api       serves tenant requests     (member of licenseforge_app)
--   licenseforge_admin     platform-admin operations  (member of licenseforge_platform)
-- The server refuses to start if the api/admin logins could bypass row-level
-- security: privileged attributes, owning the database, schema or tables, being
-- able to create temporary tables, or membership in any role other than their
-- own group (so never GRANT them the owner, the other group or pg_* roles).

-- Group roles referenced by migrations (cluster-wide, created once).
CREATE ROLE licenseforge_app NOLOGIN;
CREATE ROLE licenseforge_platform NOLOGIN;

CREATE ROLE licenseforge_owner LOGIN PASSWORD 'change-me-owner';
CREATE ROLE licenseforge_api   LOGIN PASSWORD 'change-me-api'   IN ROLE licenseforge_app;
CREATE ROLE licenseforge_admin LOGIN PASSWORD 'change-me-admin' IN ROLE licenseforge_platform;

-- PostgreSQL 16+: a non-superuser admin must be able to SET ROLE to the owner
-- to create a database owned by it.
GRANT licenseforge_owner TO CURRENT_USER WITH SET TRUE;
CREATE DATABASE licenseforge OWNER licenseforge_owner;

-- Only these logins may connect. Group grants are cluster-wide, so this is what
-- keeps logins of another LicenseForge install on the same cluster out.
REVOKE CONNECT ON DATABASE licenseforge FROM PUBLIC;
-- No temporary tables: a temp table named like a real one would shadow it for
-- later requests on the same pooled connection. The server refuses logins
-- that still have TEMPORARY.
REVOKE TEMPORARY ON DATABASE licenseforge FROM PUBLIC;
GRANT CONNECT ON DATABASE licenseforge TO licenseforge_owner, licenseforge_api, licenseforge_admin;
