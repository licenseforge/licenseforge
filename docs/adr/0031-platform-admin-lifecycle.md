# ADR-0031 Platform admin lifecycle

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0029 Identity tables and tenancy](0029-identity-tables-and-tenancy.md) defines `platform_admins` and a bootstrap that grants `LICENSEFORGE_BOOTSTRAP_ADMIN` only while the table is empty ([ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)). It says nothing about removal: if the last admin is removed (or two remove each other), the table is empty and the next login matching the bootstrap value becomes platform admin, possibly via the weakest issuer that marks that email verified. Decided under the maintainer's delegation.

## Decision
- **The last platform admin can't be removed**: removal (`RemovePlatformAdmin`) locks the admin set and refuses if none would remain, like the last tenant owner. Bootstrap, grant and removal all serialize on that one lock.
- **Grants record how they were made**: `bootstrap` (only while there are no admins, `granted_by` NULL) or a grant by an existing, enabled admin (`granted_by` that admin). The database enforces the shape of each row (CHECK) and **at most one bootstrap row, ever** (partial unique index).
- **Database backstops are partial, by choice**: restrictive policies refuse a single-row removal of the last admin and a single-row grant of the wrong shape, but they read a snapshot, so a multi-row statement or two racing raw statements on the platform pool can pass them. Closing that needs a trigger, which [ADR-0009 Multi-tenancy](0009-multi-tenancy.md) refuses; the platform pool is the most privileged serving login (all tenants) anyway, so the store functions are the rule.
- **Bootstrap and grants** never involve a disabled or unknown user (target or granter).
- **Erasure** (`licenseforge user erase`) removes the user's `platform_admins` row first and refuses while they are the last admin (hand over first), as it refuses a tenant's last owner.
- **Recovery** when no admin can log in is an explicit operator action on the owner login (a `licenseforge admin` command, to be built with the CLI), never an empty table reopening bootstrap. The erase command (ADR-0029) is also still to be built; it must follow this ADR.

## Consequences
- Bootstrap fires once in an installation's life unless an operator deliberately empties the table with the owner login.
- One more owner-login command to document.
