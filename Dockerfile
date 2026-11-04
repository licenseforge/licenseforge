# syntax=docker/dockerfile:1
# LicenseForge server image (ADR-0005): static binary on distroless, non-root.
# FIPS variant: docker build --build-arg GOFIPS140=certified (ADR-0024).
FROM docker.io/library/golang:1.26-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG GOFIPS140=off
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOFIPS140=${GOFIPS140} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/licenseforge ./cmd/licenseforge

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/licenseforge /licenseforge
# Numeric, so Kubernetes runAsNonRoot can verify it (distroless "nonroot").
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/licenseforge"]
