# ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1

*Status: accepted · Date: 2026-11-02*

## Context
We want to sell to US federal, defence and healthcare buyers. These regimes don't certify *software*, they authorize *systems and organizations*:

| Regime | What it actually applies to | What a product can do |
|---|---|---|
| **FedRAMP** | Authorization of a **cloud service offering** (our future hosted LicenseForge), via agency sponsorship or the FedRAMP 20x process, with a 3PAO assessment and continuous monitoring | Be **assessment-ready for FedRAMP**: implement the NIST SP 800-53 controls, ship machine-readable control documentation, FIPS crypto. Self-hosted in an agency's environment, it inherits **their** ATO, and we make that ATO easy |
| **HIPAA** | Covered entities and business associates handling **PHI** | Never need PHI; provide the Security Rule technical safeguards (45 CFR 164.312) for vendors deploying it; sign a **BAA** for hosted when offered |
| **NIST SP 800-53 Rev 5** | Control catalogue behind FedRAMP, FISMA, DoD | Implement and document the controls the product owns |
| **NIST SP 800-218 (SSDF)** | How software is built; US federal suppliers must attest to it (CISA secure software attestation) | Follow and document it from the first commit |
| **NIST SP 800-63** | Digital identity assurance | Delegated to the IdP; we enforce MFA / assurance claims |
| **FIPS 140-3** | Validated crypto modules | Use validated modules in FIPS builds |

So "from day 1" means: **the product is built and documented so that a FedRAMP Moderate / HIPAA / NIST 800-53 assessment of a system running LicenseForge finds the product side done.** Our own FedRAMP authorization and BAA come with the hosted offering.

## Decision: in v0.1

### Crypto (SC-13, SC-8, SC-28)
- **FIPS build in CI from day 1** with `GOFIPS140=certified` (latest Go module with a CMVP certificate; today v1.0.0, cert #5247), tested on every PR, published as `-fips` images.
- **Ed25519 stays the only key type in v0.1**: EdDSA is on the approved-algorithm list of CMVP #5247, so it is FIPS-approved inside Go's validated module. **ECDSA P-256 is decided in v0.2** with the Java SDK: added only if Bouncy Castle FIPS lacks EdDSA (decided below). No format change needed ([License File Format](../../spec/license-format.md): algorithm bound to `kid`).
  - **Decided 2026-11-10: no P-256.** Bouncy Castle FIPS Java (BC-FJA) 2.1.1 has EdDSA (Ed25519, Ed448) in its approved algorithms under FIPS 186-5 (CAVP A4270; FIPS 140-3 certificate #4943, interim validation, sunset 2030-01-16; Java 8, 11, 17 and 21 tested). The security policy also lists EdDSA in its Table 6 (not allowed in approved mode); the certificate's approved list and the policy's Table 10 (approved services) govern. The Java SDK (v0.2) will verify Ed25519 in approved mode with the validated jar: BC-FJA 2.1.1, or a later version once a CMVP certificate lists it with EdDSA; its tests will run with `CryptoServicesRegistrar.isInApprovedOnlyMode()` true. BC-FJA 2.0.0 (certificate #4743) doesn't approve EdDSA. The JDK's own Ed25519 (SunEC) is fine outside FIPS mode but isn't a validated module. Ed25519 stays the only key type; P-256 comes back only if a buyer's mandated module lacks EdDSA (Compliance verification 2026-11).
- FIPS mode restricts TLS to FIPS-approved suites; TLS 1.2+ everywhere, 1.3 preferred.
- Encryption at rest for all secrets (envelope), DB/disk encryption documented as a deployment requirement.

### Identification and access (AC, IA)
- **Enforce MFA per tenant** by checking the IdP's `amr`/`acr` claims, including a **"require phishing-resistant MFA"** policy (passkeys/WebAuthn, PIV/CAC via the IdP, e.g. Keycloak X.509) matching FedRAMP 20x KSI-IAM-APM ([ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)). Accepted `acr`/`amr` values are configurable per IdP.
- **Session controls**: configurable idle timeout and absolute session lifetime, explicit logout that kills the server-side session (AC-12, AC-12(1)).
- **System use notification banner** (AC-8): configurable login banner, required by many federal and DoD deployments.
- Least privilege RBAC, no shared accounts, API tokens with expiry ([ADR-0019 Authorization model](0019-authorization-model.md)).
- Account lifecycle: deactivate member, revoke all their sessions and tokens immediately (AC-2).

### Audit and accountability (AU)
- Audit records contain who, what, when (UTC, from synced clock), where (source IP, user agent), outcome, tenant, object (AU-2, AU-3, AU-8).
- Hash-chained, append-only (AU-9); configurable retention (AU-11).
- **Export to SIEM**: syslog (RFC 5424, TLS) and OpenTelemetry logs (AU-6).
- Audit failures alert and are visible in metrics (AU-5).

### Data (HIPAA, PT, SC)
- **PHI-free by design**: documented data inventory; LicenseForge has no field that requires health data. Docs tell vendors not to put PHI in metadata/custom fields; secrets and license keys are redacted from logs.
- HIPAA technical safeguards mapping published: access control, audit controls, integrity, authentication, transmission security (164.312 a–e).

### Secure development (SSDF, SR, SI)
- SSDF practice mapping in the repo; DCO sign-off enforced in CI, branch protection, code review, CodeQL, dependency scanning, secret scanning (already live on GitHub).
- SBOM + SLSA provenance + cosign signatures on every release: images, chart, binaries; SDKs use their ecosystem's mechanism ([ADR-0021 Certification readiness](0021-certification-readiness.md), amended 2026-11-09).
- **Vulnerability remediation SLAs aligned to FedRAMP continuous monitoring**: Critical/High 30 days, Moderate 90 days, Low 180 days. Published in the org-wide `SECURITY.md` (licenseforge/.github).

### Documentation as code
- *To be created in v0.1:* **OSCAL 1.2.x component definition** (pinned to OSCAL v1.2.3, validated in CI) (`compliance/oscal/component-definition.json`) describing how LicenseForge implements each NIST 800-53 Rev 5 control it owns. FedRAMP (incl. 20x) consumes OSCAL; agencies paste it into their SSP instead of writing it.
- `compliance/` also holds: control matrix (human-readable), HIPAA safeguards mapping, SSDF mapping, data inventory, and the **Secure Configuration Guide** (named after the FedRAMP 20x SCG ruleset).
- Updated in the same PR as the feature that implements a control.

### Deployment
- Hardened images (non-root, read-only, minimal) and chart defaults ([ADR-0005 Kubernetes deployment via Helm](0005-kubernetes-deployment-via-helm.md)); hardening guide aligned with the Kubernetes STIG / NSA-CISA Kubernetes hardening guidance.
- Air-gapped install fully supported ([ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md)): images, chart and vectors installable from an offline bundle.

## Decision: later, with the hosted offering
- FedRAMP authorization of hosted LicenseForge targeting **20x Class C (Moderate)** (46 Key Security Indicators across 10 themes, defined in FedRAMP's Consolidated Rules for 2026 ([fedramp.gov/2026](https://fedramp.gov/2026/))); agency sponsorship as fallback: dedicated US-only instance (e.g. AWS GovCloud), US-person operations, 3PAO assessment, ConMon ([ADR-0009 Multi-tenancy](0009-multi-tenancy.md) dedicated-instance option).
- BAA for hosted customers who want one, SOC 2 Type II, ISO 27001.
- **Iron Bank** (DoD hardened container registry) submission for the images.
- DoD IL4/IL5 only if a defence customer requires it.

## Consequences
- Roughly 1–2 extra weeks in v0.1 (FIPS CI, phishing-resistant MFA policy, banner, session controls, SIEM export, OSCAL skeleton), saving a rewrite later.
- Strong differentiation: we are not aware of another open-source licensing tool that ships OSCAL and FIPS builds; incumbents sell this as enterprise extras.
- We can say "designed to support FedRAMP Moderate, HIPAA and NIST 800-53 assessments" and "NIST 800-53 Rev 5 control mapping (OSCAL)". We must **not** say "FedRAMP Ready" (an official designation earned through a 3PAO readiness assessment and Marketplace listing), "FedRAMP authorized", or "HIPAA certified" (no such certification exists) (marketing claims are a legal risk).

## Verification results (2026-11-02)
Details: Compliance verification 2026-11 (design vault). Primary sources: [NIST CMVP certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247), [Go FIPS 140-3 docs](https://go.dev/doc/security/fips140), [FedRAMP 20x](https://www.fedramp.gov/20x), [Class C Key Security Indicators](https://fedramp.gov/2026/reference/20x/c/key-security-indicators/), [OSCAL releases](https://github.com/usnistgov/OSCAL/releases).
- [x] Go module v1.0.0: CMVP #5247 active (to 2031), EdDSA approved. v1.26.0 pending review.
- [x] FedRAMP 20x: Phase 3, Classes A–C final in the Consolidated Rules for 2026 (CR26), Class C = Moderate, 46 Key Security Indicators (KSIs). Product-relevant KSIs: IAM-APM, MLA-OSM, SVC-VRI, SVC-SIN, SCR-MON.
- [x] OSCAL: latest v1.2.3; target 1.2.x component definition.

## Still open
- [x] Bouncy Castle FIPS (Java): is EdDSA approved? Yes, BC-FJA 2.1.1 (certificate #4943): no P-256 (2026-11-10).
- [ ] FedRAMP VDR/VER rulesets: exact vulnerability remediation timelines; align `SECURITY.md` SLAs if they differ.
- [ ] FedRAMP RFC-0024 (machine-readable authorization packages; unrelated to ADR numbering): scope and deadlines confirmed on fedramp.gov (secondary sources disagree).
