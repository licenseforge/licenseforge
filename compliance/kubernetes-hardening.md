# Kubernetes hardening

How the LicenseForge Helm chart lines up with the **NSA/CISA Kubernetes Hardening Guidance** (v1.2, August 2022), and which parts are the cluster operator's. The same split covers the container- and workload-level requirements of the DISA Kubernetes STIG: the chart meets the workload ones by default, while the control plane, nodes, etcd and cluster RBAC belong to whoever runs the cluster.

Every chart claim below is checked:
- `deploy/helm/chart_test.go` renders every workload (the Deployment, the migration Job and the audit-retention CronJob) with several value sets and fails if one breaks the Pod Security Standard *restricted* profile or the items marked **tested**.
- The chart CI job also lints and renders the chart (`.github/workflows/ci.yml`, `chart`).

Settings and their defaults are in the [Secure Configuration Guide](secure-configuration-guide.md); this page maps them to the guidance.

## Pod security

| Guidance | LicenseForge | Who |
|---|---|---|
| Non-root containers | Pods run as UID/GID 65532 with `runAsNonRoot: true`; the image is distroless `static:nonroot` and has no shell. **Tested.** | Chart |
| Immutable container file systems | `readOnlyRootFilesystem: true`; the server writes nothing locally (state is in PostgreSQL). **Tested.** | Chart |
| No privilege escalation, minimal capabilities | `allowPrivilegeEscalation: false`, capabilities `drop: [ALL]`, nothing added, never privileged. **Tested.** | Chart |
| Seccomp | `seccompProfile: RuntimeDefault` on every pod. **Tested.** | Chart |
| Host namespaces and paths | No `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` or `hostPort`. **Tested.** | Chart |
| Pod security enforcement | The pods meet *restricted*; label the namespace `pod-security.kubernetes.io/enforce: restricted` so the cluster enforces it (or use your admission controller: Kyverno, Gatekeeper). | Operator |
| Service account tokens | `automountServiceAccountToken: false` on the service account and every pod; LicenseForge doesn't call the Kubernetes API. **Tested.** | Chart |
| Secure images | Built from pinned, digest-referenced bases; release images are cosign-signed with SLSA provenance and an SBOM ([verifying releases](../docs/verifying-releases.md)). Set `image.digest` so the cluster runs exactly what you verified; admission policies (e.g. Kyverno `verifyImages`) can require the signature. | Chart + operator |
| Resource limits | Every container has CPU and memory requests and a memory limit (`resources`). **Tested.** A `LimitRange`/`ResourceQuota` on the namespace is the operator's. | Chart + operator |

## Network separation

| Guidance | LicenseForge | Who |
|---|---|---|
| Namespaces | Install into a namespace of its own. | Operator |
| Network policies | `networkPolicy.enabled: true` by default. The server accepts TCP 8080 only, from `ingressFrom`; its egress is limited to DNS, the database port, the OIDC provider and SIEM collectors when configured, and webhook receivers; metrics are on a separate port, reachable only from `metrics.scrapeFrom`. The migration Job has no ingress. Narrow `ingressFrom` and `databaseTo` to your ingress controller and database. | Chart + operator |
| A default-deny baseline | Add a namespace-wide default-deny policy; the chart's policies are additive and keep working under it. | Operator |
| Encryption in transit | Database connections must verify the server's certificate (`verify-full`) unless local; webhooks are https only; OIDC must be https. The server listens on plain HTTP behind your TLS ingress or service mesh (TLS 1.2+). | Chart + operator |
| Secrets | Secrets are read by `secretKeyRef` key by key, never `envFrom`; the owner (migration) login never reaches serving pods (rendering checks it). Use encryption at rest for Secrets (KMS provider) and, if you prefer, an external secret manager ([secret managers](../docs/secret-managers.md)). | Chart + operator |
| Control plane, etcd, kubelet, node segmentation | Not in the chart's scope. | Operator |

## Authentication and authorization

| Guidance | LicenseForge | Who |
|---|---|---|
| Cluster RBAC | The chart creates no Role or ClusterRole, and its service account has no token. | Chart |
| Anonymous access, API server auth | Cluster settings. | Operator |
| Application access | Users sign in through your OIDC provider (MFA policy per tenant, phishing-resistant optional); API tokens are scoped by role and product, and expire. See the Secure Configuration Guide. | LicenseForge |

## Audit logging and threat detection

| Guidance | LicenseForge | Who |
|---|---|---|
| Application audit trail | Every change and refusal is in a hash-chained audit log, verified periodically, with alerts when verification stalls or fails (`prometheusrule.yaml`), and exported to your SIEM over syslog (TLS) or OpenTelemetry. | LicenseForge |
| Kubernetes audit logs, runtime detection | Cluster settings (API server audit policy, Falco or similar). | Operator |

## Upgrades and patching

| Guidance | LicenseForge | Who |
|---|---|---|
| Patch promptly | Remediation timelines are in `SECURITY.md`; Dependabot keeps dependencies and base images current. | LicenseForge |
| Roll out safely | Two replicas, a PodDisruptionBudget and a drain period by default; migrations run as a pre-upgrade Job with the owner login only. | Chart |
| Upgrade Kubernetes | Cluster lifecycle. | Operator |

## Checking a deployment

- **Pod Security admission:** label the namespace and use `kubectl label --dry-run=server --overwrite ns <ns> pod-security.kubernetes.io/enforce=restricted` to see violations before you enforce.
- **Scanners:** tools such as kubescape (with the NSA framework) or Trivy's Kubernetes scan report the workload items above. Cluster-level findings belong to the operator.
