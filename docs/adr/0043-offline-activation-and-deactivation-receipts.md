# ADR-0043 Offline activation and deactivation receipts

*Status: accepted · Date: 2026-11-08*

## Context
[ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md) decides offline activation by file exchange: the app writes an activation request, someone carries it to the vendor's LicenseForge, and a license file comes back. It leaves open the request format, how long the returned file is valid, how offline machines take and return seats, and what a "deactivation receipt" proves. Today only site licenses (`bind: none`) can be exported offline (#30); a machine- or cluster-bound license can only be used online. Accepted by the maintainer on 2026-11-08.

## Decision
### Activation request (`lfreq1`)
- A text artifact `lfreq1.` + base64url (no padding) of a JSON object: `v` (1), `tenant`, `product`, `key` (the license key), `bind` (`type` machine or cluster, `fp` computed exactly as online, [License File Format](../../spec/license-format.md) Fingerprints), `nonce` (16 random bytes, base64url), `created` (the machine's clock, informational only), optional `hostname`, `app_version`, `sdk_version`.
- **Unsigned**: an air-gapped machine has no key the vendor trusts, and the license key already proves the right to activate, as it does online. The request is as sensitive as the key it carries: the docs say so, and the server stores only its SHA-256.
- Size limit 4 KiB; unknown fields refused; the SDK writes it (`offline.Request`), the CLI and dashboard only carry it.

### Issuing the offline file
- `POST /api/v1/tenants/{tenant}/activation-requests` with the request text answers the signed `lf1` license file. It needs `activation:offline` (managers and up, ADR-0019) on the license's product, honours `Idempotency-Key` (ADR-0032: activation creation), and refuses unless the license is usable and its plan has `offline_allowed`.
- **Seats** (ADR-0034, unchanged rules): the request takes or reuses the seat for its fingerprint as an activation with `mode = offline`; it counts toward `max_activations`, and a new fingerprint past the limit is a seat move counted in `rehost_count`. Renewal is a new request from the same machine: same fingerprint, same seat, a new file.
- **Validity**: `exp` = the earlier of the license's expiry and issue time + the plan's `max_offline_seconds` (unset: the license's expiry; a perpetual license with no `max_offline_seconds` gets a perpetual file, as site-license files do today). `grace` = the plan's. No `refresh_after` or `max_offline` claims: the file is the offline term. Bound to the request's fingerprint, so it works on that machine only.
- The server records the request hash, the file's SHA-256 and the issuing principal on the activation and in the audit log ([ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md) certification amendment).

### Deactivation receipt (`lfrcpt1`)
- The SDK's offline deactivate deletes the installed file, remembers its license ID and `iat` in the clock store so that file is refused on that machine afterwards, and writes a receipt: `lfrcpt1.` + base64url JSON with `v`, `tenant`, `license_id`, `fp`, `file_sha256` (of the file it deleted), `nonce`, `created`.
- `POST /api/v1/tenants/{tenant}/deactivation-receipts` frees the seat when `file_sha256` is the activation's **current** file; an older file's receipt (the machine renewed since) is refused, a repeated receipt answers 200 with no new entry. Needs `activation:offline`; audited with the receipt hash.
- **What it proves**: possession of the latest file and the SDK's statement that it deleted it. No cryptography can prove deletion on a machine the vendor doesn't control, and an air-gapped machine has no trusted signing key; "signed" in the Roadmap means the receipt is bound to the signed file it returns. The vendor's alternative stays: dashboard deactivate (#86) frees the seat without a receipt, and the file keeps working until its `exp`, which the dashboard says.

### Tools
- **Go SDK** (`sdk/go/offline`): `Request`, `Install` (verify and store; picks up a renewed file without restart, ADR-0006), `Deactivate` (receipt). Java and TypeScript follow with the shared vectors.
- **Dashboard**: on the license page, "Offline activation" (paste or upload a request, download the file) and "Return a seat" (paste a receipt).
- **CLI**: `licenseforge offline activate --request req.txt > license.lic` and `licenseforge offline return --receipt r.txt`, calling the API with an API token, for vendors scripting it.

### Formats
- `lfreq1` and `lfrcpt1` are added to the license format spec with conformance vectors (valid, malformed, unknown field, oversize, bad fingerprint shape). The `lf1` license file itself doesn't change.

## Consequences
- Machine- and cluster-bound licenses become usable air-gapped, with the same seat limits and audit trail as online.
- Offline files can't be revoked early (ADR-0006); a revoked license stops issuing and renewing, and the vendor chooses short `max_offline_seconds` for riskier customers.
- A lost receipt or a dead machine needs the vendor's dashboard deactivate; that seat's last file keeps working until `exp`.
- PRs in order: spec + vectors for `lfreq1`/`lfrcpt1` (user merge: format); server request endpoint and offline activations; receipts endpoint; Go SDK; dashboard; CLI.

## Alternatives considered
- **Request without the license key** (license ID only, vendor staff upload authenticated): the machine doesn't know its license ID, and a self-service portal later needs the key as proof anyway.
- **A machine key pair to sign requests and receipts**: nothing on the vendor side could trust a key generated on the customer's machine; it adds ceremony without proof.
- **A receipt secret embedded in the license file** (new claim): equivalent to binding the receipt to the file's hash, but changes the `lf1` claims; the hash binding needs no format change.
- **Offline validity from a new plan term**: `max_offline_seconds` already means "how long without contact"; a second term would confuse vendors.
