VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-fips vet vet-cross lint fmt run generate dev-db dev-db-stop migrate-check compliance
# Go modules in this repo: the server (root) and the SDK.
MODULES := . sdk/go
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/licenseforge ./cmd/licenseforge

test:
	for m in $(MODULES); do (cd $$m && go test -race ./...) || exit 1; done

# FIPS 140-3 mode with the latest CMVP-certified Go Cryptographic Module (ADR-0024).
# fips140=only makes non-approved algorithms fail, so tests catch accidental use (testing only).
test-fips:
	for m in $(MODULES); do (cd $$m && GOFIPS140=certified GODEBUG=fips140=only go test -count=1 ./...) || exit 1; done

vet:
	for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

# The SDK has OS-specific code (fingerprints); vet it for every supported OS.
vet-cross:
	for os in linux windows darwin freebsd; do (cd sdk/go && GOOS=$$os go vet ./...) || exit 1; done

lint: vet
	for m in $(MODULES); do (cd $$m && golangci-lint run) || exit 1; done
	for os in windows darwin; do (cd sdk/go && GOOS=$$os golangci-lint run ./...) || exit 1; done

fmt:
	gofmt -w .

run:
	go run ./cmd/licenseforge

# Code generation (ent). CI fails if generated code is stale.
generate:
	go generate ./internal/store

# Throwaway PostgreSQL for tests and migration generation.
DEV_DB_IMAGE := postgres:17@sha256:3b0cda93be7c8dba2ed484d19393d93845dc3dafb88973e248ba8e6d99d784e1
DEV_DB_URL := postgres://postgres:dev@127.0.0.1:55432/postgres?sslmode=disable
dev-db:
	docker run -d --rm --name lf-dev-db -e POSTGRES_PASSWORD=dev -p 127.0.0.1:55432:5432 $(DEV_DB_IMAGE)
	until docker exec lf-dev-db pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	docker exec lf-dev-db psql -U postgres -qc 'CREATE DATABASE lf_dev'
	@echo "export LICENSEFORGE_TEST_DATABASE_URL='$(DEV_DB_URL)'"
	@echo "export LICENSEFORGE_DEV_DATABASE_URL='postgres://postgres:dev@127.0.0.1:55432/lf_dev?sslmode=disable'"

dev-db-stop:
	docker stop lf-dev-db

# Fails if the ent schema needs a migration that isn't in internal/store/migrations.
migrate-check:
	go run ./internal/store/tools/migrate check

# Validates compliance/ (OSCAL schema, cited evidence, links); its own module.
compliance:
	cd compliance && go test -count=1 ./...
