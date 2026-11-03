# ADR-0028 PostgreSQL 17 minimum

*Status: accepted · Date: 2026-11-03*

## Context
[ADR-0009 Multi-tenancy](0009-multi-tenancy.md) required PostgreSQL 15+, the oldest version where roles can't create objects in `public` by default. CI only tested 17, and two 16/17-only features (jsonpath `.string()`, `GRANT … WITH SET`) slipped into the schema and setup script before a 15 job caught them. Supporting 15, 16 and 17 means three majors in CI and in support.

## Decision
- **PostgreSQL 17 or newer is required.** `store.Open` and `store.Migrate` refuse older servers; `Migrate` checks before taking its lock or writing anything.
- CI tests 17 only. A newer major is added to CI when it is released and supported by the major managed providers (RDS, Cloud SQL, Azure).
- Everything else in [ADR-0009 Multi-tenancy](0009-multi-tenancy.md) stands.

## Consequences
- Installs on 15/16 must upgrade before running LicenseForge. Acceptable: there are no production installs yet, and all major managed services offer 17.
- Features up to 17 may be used freely.
