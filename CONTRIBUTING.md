# Contributing

The general rules (Code of Conduct, DCO sign-off, pull request process, security reporting) are in the [organization contributing guide](https://github.com/licenseforge/.github/blob/main/CONTRIBUTING.md). This file covers working on this repository.

## Prerequisites
- Go 1.26+
- [golangci-lint](https://golangci-lint.run/) for `make lint`
- Docker (PostgreSQL for tests, and the dev stack)

## Common tasks
```
make dev-db   # throwaway PostgreSQL 17 for tests; prints the variables to export
make test     # go test -race ./...
make lint     # go vet + golangci-lint
make build    # bin/licenseforge
docker compose up --build   # server + PostgreSQL with the production logins, on 127.0.0.1:8080
```
`make run` runs the server directly; it needs the `LICENSEFORGE_*` variables listed in `cmd/licenseforge/main.go`.

## Design changes
Read the [ADRs](docs/adr/README.md) first. A change that contradicts an accepted ADR needs a new ADR in the same pull request.

## Sensitive areas
Changes to license signing/verification, the license file format, authorization or tenant isolation need a maintainer review and tests that fail without the change. Format changes must update `spec/` and the conformance vectors.
