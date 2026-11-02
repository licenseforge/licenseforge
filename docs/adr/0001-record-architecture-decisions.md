# ADR-0001 Record architecture decisions

*Status: accepted · Date: 2026-11-02*

## Context
This is a business we intend to sell and an open-source project others will audit. Decisions need to be traceable.

## Decision
Record every significant decision as an ADR in `03 ADR/` using ADR Template (Michael Nygard format). Statuses: `proposed`, `accepted`, `superseded`, `rejected`. ADRs are immutable once accepted; change = new ADR that supersedes.

When the code repo exists, mirror accepted ADRs into `docs/adr/` so contributors see them.

## Consequences
Small overhead per decision; buyers/contributors get a clear rationale trail.
