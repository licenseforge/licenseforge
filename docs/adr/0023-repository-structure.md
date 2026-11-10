# ADR-0023 Repository structure

*Status: accepted · Date: 2026-11-02*

## Context
Deliverables: Go server, CLI, in-cluster agent, admin dashboard (embedded), Helm chart, OpenAPI spec, license format spec + conformance vectors, Go/Java/TypeScript SDKs, secret-manager add-ons per language, n8n node, Salesforce package (v0.4). Each language has its own toolchain and package registry (Go modules, Maven Central, npm, Salesforce).

Rules:
- Things that must change **atomically** live together (license format code ↔ spec ↔ vectors ↔ server ↔ Go SDK).
- Things with **their own toolchain and release pipeline** get their own repo.
- No git submodules.

## Decision
### Repos (GitHub org [`licenseforge`](https://github.com/licenseforge))
| Repo | Contents | Publishes | From |
|---|---|---|---|
| `licenseforge` | Server, `lf` CLI (now `licenseforge` subcommands: [ADR-0048 Admin CLI via the REST API](0048-admin-cli-via-the-rest-api.md)), agent, **Go SDK** + Go add-ons (nested modules), dashboard (`web/`), Helm chart, OpenAPI, license spec + conformance vectors, docs | Container images (ghcr.io, signed), Helm chart (OCI), CLI binaries, Go modules, conformance-vector tarball | v0.1 |
| `licenseforge-java` | Java SDK + add-ons (Maven multi-module) | Maven Central | v0.2 |
| `licenseforge-node` | TypeScript SDK + add-ons + n8n node (pnpm workspace) | npm | v0.2 |
| `licenseforge-salesforce` | SFDX unlocked package (metadata only), Flow recipe | Salesforce package versions | v0.3 recipe / v0.4 package |
| `website` | Landing page for `licenseforge.io` (static site), Go `go-import` meta tags | Static hosting | v0.1 |
| `.github` | Org-wide `SECURITY.md`, `CONTRIBUTING.md` (DCO), Code of Conduct, issue templates | | v0.1 |


### Why the Go SDK lives in the main repo
The server (signing), agent and Go SDK (verification) share the license format code. Keeping them together means a format change, its spec, its test vectors and both sides land in one PR. The Go SDK is still a **separate Go module**, so vendors importing it pull none of the server's dependencies.

> [!NOTE]
> **Amended 2026-11-10**: the TypeScript and Java SDKs live in the main repo
> (`sdk/ts`, `sdk/java`), not in `licenseforge-node` and `licenseforge-java`. A format change touches the spec, the vectors and every SDK at once (#181: weak keys, in the spec, Go and TypeScript in one PR), and SDK CI reads the vectors in place. Each SDK is still its own package (npm `@licenseforge/sdk`, Maven `io.licenseforge:licenseforge-sdk`) with its own semver and tag prefix (`sdk/ts/vX.Y.Z`, `sdk/java/vX.Y.Z`), built, tested and released by its own path-filtered workflows. This overrides, below: the `licenseforge-java` and `licenseforge-node` rows (the main repo also publishes to npm and Maven Central); the pinned vector download (the versioned tarball stays, for SDKs outside the repo); "plus Java/Node at v0.2" and "the pinned vectors catch it" in Consequences (the in-place vectors do); and it partly adopts the rejected "one monorepo" alternative, for the SDKs only. Add-ons with their own toolchain (the n8n node, the Salesforce package) keep repos of their own.

### Go module paths (vanity imports)
Serve `go-import` meta tags from `licenseforge.io` so import paths survive repo moves:
- Server: `licenseforge.io/licenseforge`
- Go SDK: `licenseforge.io/licenseforge/sdk/go` (tags `sdk/go/v0.x.y`)
- Add-ons: `licenseforge.io/licenseforge/sdk/go/store/vault`, `/awssm`, … one module each (vendors pull only the cloud SDK they use, [ADR-0011 Secret manager integrations](0011-secret-manager-integrations.md))

### Domains
| Host | Serves | Why separate |
|---|---|---|
| `licenseforge.io` | Landing page (marketing, SEO) + `go-import` meta for vanity paths | Static, fast, independent from app releases |
| `app.licenseforge.io` | Hosted dashboard | Product analytics separate from marketing analytics; session cookies **host-only** on this name, never `Domain=.licenseforge.io` |
| `api.licenseforge.io` | Hosted REST + activation API | Vendors embed this URL in their shipped software **forever**: must never move with dashboard or marketing changes. Own rate limits, no cookies, CORS only for app. |
| `docs.licenseforge.io` | Documentation (from `licenseforge/docs`) | SEO, versioned docs |

- Same server binary serves app and API; hostnames are routing, not separate deployments.
- Later: per-tenant custom activation domains (white-label, `license.vendor.com` CNAME) on the hosted plan.
- Self-hosters use their own domains; nothing is hardcoded to licenseforge.io except SDK docs examples.

### Cross-repo contract: conformance vectors
- Vectors live in `licenseforge/spec/vectors/`, released as a versioned tarball.
- Java and Node CI download a **pinned** vector version and must pass all of it ([ADR-0010 Official SDKs Go, Java, TypeScript](0010-official-sdks-go-java-typescript.md)). Bumping the pin is a deliberate PR.

### API contract: spec-first OpenAPI
- `api/openapi.yaml` is the source of truth.
- Go server handlers generated with **oapi-codegen** (strict server interfaces).
- Dashboard TypeScript client generated from the same file. SDK HTTP calls and docs follow it.
- CI fails if generated code is stale.

### Versioning
| Thing | Scheme |
|---|---|
| Server, CLI, agent, Helm chart | One semver, released together |
| Each SDK and add-on | Independent semver |
| REST API | `/v1` path; breaking change = `/v2` |
| License file format | `lf1` prefix; SDKs declare supported formats |

Layout of the main repo: Code Structure.

## Consequences
- 3 repos to start (`licenseforge`, `website`, `.github`), plus Java/Node at v0.2. Small team, few places to look.
- Main repo CI needs path filters (Go vs `web/` vs chart) to stay fast.
- Go nested modules need a `go.work` for local dev and prefixed tags for releases; scripted in the Makefile.
- Java/Node SDKs can't break the format silently: the pinned vectors catch it.

## Alternatives considered
- **One monorepo for all languages**: one place, but Maven + npm + Go + SFDX release pipelines in one repo; contributors to one SDK wade through everything.
- **Repo per component** (server, cli, agent, chart, dashboard, spec, sdk-go…): ~10 repos, cross-repo PRs for every format change.
- **Separate `licenseforge-go` SDK repo**: cleaner tags, but format changes become two-repo dances and the server would depend on a released SDK version.
