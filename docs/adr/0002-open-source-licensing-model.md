# ADR-0002 Open source licensing model

*Status: accepted · Date: 2026-11-02*

## Context
We want trust (vendors put their revenue gate on us, so they want to audit it), maximum adoption, and a business we can sell.

## Decision
- **Everything under Apache-2.0**: server, CLI, SDKs, license file spec, Helm chart.
- Contributions via **DCO** (`Signed-off-by`), no CLA. Apache already lets us (and anyone) ship contributions in proprietary products, so a CLA buys little and adds friction.
- **Register the "LicenseForge" trademark.** With a permissive license the name and brand are the moat; Apache-2.0 grants no trademark rights.
- Enterprise-only features, if any, live in a separate commercial repo (open core).

## Consequences
- No license friction for any company, including AGPL-banning enterprises. Easiest possible adoption.
- Explicit patent grant (Apache §3) reassures enterprise legal teams.
- **No legal barrier against a competitor hosting LicenseForge as a service.** Revenue must come from being the best hosted offering, enterprise features, support, and brand.
- Clean IP story for an acquirer as long as DCO sign-offs are enforced in CI.

## Alternatives considered
- **AGPL server + Apache SDKs**: protects against hosted clones, scares some enterprises, needs a CLA to dual-license.
- **BSL / Elastic / Fair Source**: not OSI open source, weakens the trust story.
