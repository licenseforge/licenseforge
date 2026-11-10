# syntax=docker/dockerfile:1
# LicenseForge server image (ADR-0005): static binary on distroless, non-root.
# FIPS variant: docker build --build-arg GOFIPS140=certified (ADR-0024).
# Build on the runner's platform and cross-compile (no emulation for arm64).

# The dashboard (ADR-0020): static files, the same for every architecture.
# Only web/ goes in (.dockerignore drops node_modules and dist), so the
# bundle is always built here from the lockfile. engine-strict (.npmrc) fails
# the build if this Node doesn't match web/package.json's engines; keep the
# tag equal to web/.nvmrc. ignore-scripts (.npmrc): no install scripts run.
FROM --platform=$BUILDPLATFORM docker.io/library/node:24.22.2-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /src/web/dist web/dist
ARG VERSION=dev
ARG GOFIPS140=off
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFIPS140=${GOFIPS140} go build -trimpath -tags webui -ldflags "-s -w -X main.version=${VERSION}" -o /out/licenseforge ./cmd/licenseforge

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/licenseforge /licenseforge
LABEL org.opencontainers.image.source=https://github.com/licenseforge/licenseforge
# Numeric, so Kubernetes runAsNonRoot can verify it (distroless "nonroot").
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/licenseforge"]
