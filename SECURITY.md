# Security Policy

This repository follows the [LicenseForge organization security policy](https://github.com/licenseforge/.github/blob/main/SECURITY.md): how to report, what to expect, supported versions and scope.

## Reporting a vulnerability

**Don't open public issues for security problems.** Report privately:
1. GitHub private vulnerability reporting: **Report a vulnerability** on this repository's [Security tab](https://github.com/licenseforge/licenseforge/security/advisories/new) (preferred).
2. Email **security@licenseforge.io**.

## Remediation targets

Once our assessment confirms a vulnerability, we aim to release a fix within:

| Severity (CVSS score in the advisory) | Target |
|---|---|
| Critical (9.0–10.0) | 30 days |
| High (7.0–8.9) | 30 days |
| Moderate (4.0–6.9) | 90 days |
| Low (0.1–3.9) | 180 days |

Actively exploited vulnerabilities come first. These targets are best effort, modeled on FedRAMP continuous-monitoring timeframes; the organization policy is authoritative. Deployment hardening is covered in the [Secure Configuration Guide](compliance/secure-configuration-guide.md).
