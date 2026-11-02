# Contributing

The general rules (Code of Conduct, DCO sign-off, pull request process, security reporting) are in the [organization contributing guide](https://github.com/licenseforge/.github/blob/main/CONTRIBUTING.md). This file covers working on this repository.

## Prerequisites
- Go 1.26+
- [golangci-lint](https://golangci-lint.run/) for `make lint`
- Docker (integration tests with PostgreSQL, once they exist)

## Common tasks
```
make test     # go test -race ./...
make lint     # go vet + golangci-lint
make build    # bin/licenseforge
make run      # run the server on :8080
```

## Design changes
Read the [ADRs](docs/adr/README.md) first. A change that contradicts an accepted ADR needs a new ADR in the same pull request.

## Sensitive areas
Changes to license signing/verification, the license file format, authorization or tenant isolation need a maintainer review and tests that fail without the change. Format changes must update `spec/` and the conformance vectors.
