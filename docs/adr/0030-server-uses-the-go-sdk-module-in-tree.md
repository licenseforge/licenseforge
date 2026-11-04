# ADR-0030 Server uses the Go SDK module in-tree

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0023 Repository structure](0023-repository-structure.md) keeps the Go SDK a separate module (`licenseforge.io/licenseforge/sdk/go`) in the main repo, so a format change, its vectors and both the issuer and the verifier land in one PR. Its Consequences mention `go.work` for local development. The server is the first module to import the SDK (license issuing). The vanity host `licenseforge.io` doesn't serve `go-import` tags yet, so a plain `require` can't be resolved, and `go mod tidy` ignores `go.work`.

## Decision
- The server's `go.mod` requires the SDK at `v0.0.0` with `replace licenseforge.io/licenseforge/sdk/go => ./sdk/go`. The server always builds against the SDK in the same commit, which is what ADR-0023 wants.
- A `replace` only applies inside the server module: vendors importing the SDK are unaffected and pull none of the server's dependencies.
- The Dockerfile copies `sdk/go/go.mod` before `go mod download`.
- `go.work` stays an option for local work across modules.

## Consequences
- The server can't be installed with `go install licenseforge.io/licenseforge/cmd/licenseforge@version`; it ships as container images and release binaries ([ADR-0005 Kubernetes deployment via Helm](0005-kubernetes-deployment-via-helm.md)), so nothing relies on that.
- Revisit when SDK tags are published through the vanity host: the `replace` can stay (monorepo practice) or be dropped for a tagged version.
