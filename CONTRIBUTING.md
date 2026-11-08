# Contributing

The general rules (Code of Conduct, DCO sign-off, pull request process, security reporting) are in the [organization contributing guide](https://github.com/licenseforge/.github/blob/main/CONTRIBUTING.md). This file covers working on this repository.

## Prerequisites
- Go 1.26+
- [golangci-lint](https://golangci-lint.run/) for `make lint`
- Docker (PostgreSQL for tests, and the dev stack)

## Common tasks
```
make dev-db   # throwaway PostgreSQL 17 for tests; prints the variables to export
make test     # go test -race ./...; fails if the dev-db variables aren't exported
make lint     # go vet + golangci-lint
make build    # bin/licenseforge
docker compose up --build   # server + PostgreSQL with the production logins, on 127.0.0.1:8080
```
Without `LICENSEFORGE_TEST_DATABASE_URL`, a plain `go test` skips the database tests (and still prints `ok`); `make test` and CI fail instead, so a green run means they ran.

`make run` runs the server directly; it needs the `LICENSEFORGE_*` variables listed in `cmd/licenseforge/main.go`.

## End-to-end tests
Journeys through the real chart, server, identity provider and Go SDK (ADR-0041). They run locally on minikube and aren't part of CI yet. A PR that changes a journey's path (catalog, issuing, activation, login, roles) runs them and says so.
```
minikube start --driver=docker --cpus=4 --memory=6g --addons=ingress
e2e/env/up.sh   # deploys this checkout (see e2e/env/README.md)
make e2e         # API journeys (Go)
make e2e-browser # dashboard smoke test (Playwright; first time: cd web && npx playwright install chromium)
```
After a Playwright upgrade (Dependabot bumps it with the other web packages), run `npx playwright install chromium` in `web/` again.

## Design changes
Read the [ADRs](docs/adr/README.md) first. A change that contradicts an accepted ADR needs a new ADR in the same pull request.

## Sensitive areas
Changes to license signing/verification, the license file format, authorization or tenant isolation need a maintainer review and tests that fail without the change. Format changes must update `spec/` and the conformance vectors.
