VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-fips vet lint fmt run
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

lint: vet
	for m in $(MODULES); do (cd $$m && golangci-lint run) || exit 1; done

fmt:
	gofmt -w .

run:
	go run ./cmd/licenseforge
