# ADR-0014 Product scope and won't-do list

*Status: accepted · Date: 2026-11-02*

## Context
Competitors' feature lists are long because each serves a different buyer: desktop ISVs (Cryptlex), industrial/embedded (Wibu, Thales), ERP back office (Revenera), distribution (Replicated). A small team must serve one buyer completely. See Licensing competitor feature gaps.

## Decision
**Target buyer:** B2B vendors shipping software into customers' Kubernetes clusters, including air-gapped ones. Desktop/native ISVs are a secondary market, not targeted before v0.4.

**Positioning:** "the Apache-2.0 licensing layer for software that runs in Kubernetes". Complementary to Zarf and Distr (they deliver the bits, LicenseForge decides who may run them), not a Replicated clone.

**Won't do:**
| Item | Reason |
|---|---|
| Hardware dongles / secure elements | Hardware logistics, wrong audience. TPM/PKCS#11 via later HSM work. |
| Binary wrapping, code encryption, anti-debug | Contradicts our threat model; an OSS wrapper is a map for attackers. Document compatibility with garble, ProGuard, etc. |
| Piracy telemetry / lead generation | Phones home from unconsenting users; legal and ethical exposure. Only opt-in instance telemetry. |
| VM / container detection **as an anti-piracy control** (refusing to run in VMs/containers) | Hostile to the cloud-native audience, where everything is a VM or container. (Detecting a container only to avoid an unstable or shared fingerprint, [ADR-0017 Default machine fingerprint](0017-default-machine-fingerprint.md), is not this: the app still runs, with an override or a mounted host ID.) |
| Software distribution, registries, installers | Zarf/Distr/Harbor do it. Later: registry token-auth endpoint only. |
| Prebuilt SAP / Oracle / MS Dynamics connectors | Enterprise-sales maintenance burden. API, signed webhooks and iPaaS (MuleSoft, Workato, n8n) cover them. **Salesforce and HubSpot are in scope since [ADR-0022 CRM and business tool integrations](0022-crm-and-business-tool-integrations.md).** |
| Billing, coupons, tax; Keygen-style policy-knob matrix | Billing delegated ([ADR-0007 Billing and campaigns delegated to payment providers](0007-billing-and-campaigns-delegated-to-payment-providers.md)). Opinionated defaults over dozens of interacting flags. |

**Threat model (public):** LicenseForge guarantees licenses can't be forged without the vendor's key and gives control and visibility. It does not stop a determined attacker from patching the client. Optional encrypted license files are not offered as security.

## Consequences
- Clear "no" answers save roadmap time for the v0.4 floating server, the feature nobody else ships Kubernetes-natively.
- We'll lose some desktop and defence deals early; acceptable.
