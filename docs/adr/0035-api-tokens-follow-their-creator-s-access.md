# ADR-0035 API tokens follow their creator's access

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0029 Identity tables and tenancy](0029-identity-tables-and-tenancy.md) caps a token's role at its creator's role **at creation** and lets tokens outlive their creator, so offboarding a person doesn't break integrations. The member endpoints (PR #54) revoke a removed member's tokens by default. Review found the other half missing: a member demoted from owner to viewer keeps the owner tokens they created, so demotion doesn't reduce what they can do (AC-2, AC-6). This amends [ADR-0029 Identity tables and tenancy](0029-identity-tables-and-tenancy.md). Decided under the maintainer's delegation.

## Decision
- **Removal** revokes the member's active tokens by default, in the same transaction; `revoke_tokens=false` keeps them (the integration-continuity case of ADR-0029).
- **Demotion or narrowed product scope** revokes, by default and in the same transaction, the member's active tokens that the change newly excludes: tokens whose role has a permission the new role lacks (`sdk` tokens, which anyone may create, only by scope) or whose products reach outside the new scope. `revoke_tokens=false` keeps them, and a token kept that way isn't revoked by a later change that doesn't newly exclude it.
- The response names the revoked tokens (PATCH: `revoked_token_ids`; DELETE: the `X-Revoked-Token-Ids` header), and the dashboard can preview them from the token list (creator, role, products).
- Either way it is all or nothing: if the caller can't revoke one of those tokens, nothing changes (403). Each revocation is audited with the member change as its reason.
- **Creation races**: creating a token reads the creator's membership `FOR SHARE` in the same transaction, so a token can't be created by a member who is being removed or demoted at that moment.
- Kept tokens stay bounded by their own role, scope and expiry (at most a year, ADR-0029).
- **Suspension** (`disabled_at`) ends sessions but doesn't touch tokens (it is reversible); remove the membership to revoke them.

## Consequences
- An admin who demotes someone sees which tokens were revoked (and can preview them) and can opt out deliberately.
- Integrations owned by a departing person keep working only when someone chooses that.

## Alternatives considered
- **Cap tokens at authentication by the creator's current membership**: automatic, but a token silently loses or regains rights as its creator changes, and a creator's removal breaks every integration they made.
- **Leave tokens untouched** (ADR-0029 as written): demotion would not reduce access.
