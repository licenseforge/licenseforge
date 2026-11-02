# ADR-0005 Kubernetes deployment via Helm

*Status: accepted · Date: 2026-11-02*

## Context
Project should be "Kubernetes driven". Two meanings, both relevant:
1. **LicenseForge itself** runs on Kubernetes.
2. **Vendors' software** increasingly ships to customers' Kubernetes clusters, and needs licensing there.

## Decision
- v0.1: LicenseForge is a stateless container; official **Helm chart** (server Deployment, HPA, optional Keycloak + Postgres subcharts, or external DB). Also a docker-compose for local dev.
- Config via env/ConfigMap, secrets via Kubernetes Secrets (master key, DB creds). External Secrets compatible.
- **No custom operator / CRDs in v0.1.** Helm covers install and upgrade of a stateless app + DB.
- v0.4: Kubernetes features for vendors' customers: cluster-bound licenses (`bind.type: cluster`, kube-system namespace UID), in-cluster on-prem license server, optional validating admission webhook.

## Consequences
- Fast to ship, familiar to operators.
- Revisit an operator only if we need Day-2 automation Helm can't do (e.g., managing license CRs declaratively in customer clusters, which is a plausible v0.4+ feature).

## Certification amendments (2026-11-02)
Hardened defaults from v0.1 so SOC 2 / ISO 27001 / CIS reviews pass without rework ([ADR-0021 Certification readiness](0021-certification-readiness.md)):
- Distroless, non-root, read-only root FS, no privilege escalation, dropped capabilities; Pod Security Standard **restricted**.
- NetworkPolicies in the chart; TLS everywhere (ingress and DB), cert-manager compatible.
- Images and Helm chart **signed with cosign** (keyless/Sigstore), **SBOM** (SPDX/CycloneDX) and SLSA provenance attached to every release.
- Secrets only via Kubernetes Secrets / External Secrets, never in values files or ConfigMaps.
- FIPS image variant (`-fips` tag) built with `GOFIPS140`.

## Alternatives considered
- **Operator first**: weeks of work for zero user-visible value at v0.1.
- **Kustomize only**: fine, but Helm is the de facto distribution format and what Artifact Hub indexes.
