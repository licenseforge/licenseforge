# Compliance documentation

Machine-readable and human-readable evidence of how LicenseForge supports NIST SP 800-53 Rev 5, FedRAMP Moderate, HIPAA and SSDF assessments of the systems that run it (ADR-0021, ADR-0024). The product is *designed to support* these assessments; it isn't "FedRAMP Ready", "FedRAMP authorized" or "HIPAA certified".

| File | What it is |
|---|---|
| [`oscal/component-definition.json`](oscal/component-definition.json) | OSCAL 1.2.3 component definition of the server, for your SSP |
| [`nist-800-53-matrix.md`](nist-800-53-matrix.md) | The same controls as a table: status, how, evidence, gaps |
| [`hipaa-164-312.md`](hipaa-164-312.md) | HIPAA Security Rule technical safeguards |
| [`ssdf-sp800-218.md`](ssdf-sp800-218.md) | NIST SSDF practices and repository evidence |
| [`data-inventory.md`](data-inventory.md) | Personal and sensitive data: where, how protected, retention, erasure |
| [`secure-configuration-guide.md`](secure-configuration-guide.md) | Secure deployment settings for operators |

A change that implements or changes a control updates these files in the same pull request. `go test ./...` in this directory, run by the `Compliance` workflow, validates the OSCAL file against the vendored [OSCAL schema](oscal/schema/README.md), checks that cited files and tests exist and links resolve, and that the matrix matches the OSCAL statuses. The validator is its own Go module, so its dependency (`github.com/santhosh-tekuri/jsonschema/v6`) never reaches the server.
