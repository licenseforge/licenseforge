# Secret managers

How to keep LicenseForge secrets, and a vendor app's license key and license file, in the secret manager you already run (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, OpenBao) without code in LicenseForge or its SDKs (ADR-0011, layers 1 and 2). A syncer writes the secret to a file, and LicenseForge or the SDK reads that file. Official SDK add-ons that read and write the stores directly are planned for v0.3.

## What goes where

| What | Kind | Delivered as | Notes |
|---|---|---|---|
| LicenseForge server: database URLs, master keys, OIDC client secret, CA bundle | Credentials | Kubernetes Secrets named in the chart (`secrets.server`, `secrets.migrate`, `auditRetention.secret`, `oidc.clientSecret.secretName`, `extraCA.secretName`, and the audit export's `caSecret`, `clientSecret` and `headersSecret`) | Any syncer that produces a Secret with the keys the chart's `values.yaml` lists works. The server reads them at start: roll the pods out after a rotation. |
| A vendor app's license key | Credential | A Secret mounted as a file (prefer it to an env var, which child processes, `/proc/<pid>/environ` and crash dumps can see) | Read once at start; a new key is a new license, so roll the pods out. |
| An air-gapped license file (`license.lic`) | Signed, not secret | A Secret or ConfigMap mounted **as a directory**, or a file rendered by an agent | Installed at start and again when it changes; see [In the app](#in-the-app). |
| The online lease | Signed, not secret, written by the SDK | Not through a syncer: syncers only copy from the store to the cluster | Use the SDK's `online.KubernetesConfigMap` (or `KubernetesSecret`) or `online.FileStore` (SDK README). |

Never mount a secret file with `subPath`: subPath mounts don't receive updates, so a renewed file isn't seen until the pod restarts. The SDK's clock guard and offline state (`clock.FileStore`) need a writable directory that outlives the pod (an `emptyDir` is lost when the pod is replaced, which resets them): one volume per replica (a StatefulSet's `volumeClaimTemplates`), or a shared volume whose file locks work across nodes.

## Kubernetes: External Secrets Operator

[External Secrets Operator](https://external-secrets.io) copies a secret from the store into a Kubernetes Secret and refreshes it every `refreshInterval`. Configure a `ClusterSecretStore` (or `SecretStore`) for your provider and its workload identity first. ESO 0.17 and later serve only `external-secrets.io/v1`.

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: acme-license
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secrets-manager      # or gcp-, azure-, vault-, openbao-…
  target:
    name: acme-license             # the Secret ESO writes
  data:
    - secretKey: license-key
      remoteRef: { key: acme/license, property: key }
    - secretKey: license.lic
      remoteRef: { key: acme/license, property: file }
```

The app's pod mounts the Secret as a directory:

```yaml
containers:
  - name: app
    volumeMounts:
      - name: license
        mountPath: /etc/acme/license   # license-key and license.lic; no subPath
        readOnly: true
volumes:
  - name: license
    secret:
      secretName: acme-license
      defaultMode: 0440   # with the pod's fsGroup: not readable by other users in the pod
```

The LicenseForge chart works the same way: an `ExternalSecret` whose `target.name` is `licenseforge-server`, with the keys `database-url`, `platform-database-url`, `identity-database-url` and `master-keys`, then `--set secrets.server=licenseforge-server`, and one for `licenseforge-migrate` (`owner-database-url`). Both must have synced before `helm install`: the migration Job runs first and fails (after `migrate.activeDeadlineSeconds`) while its Secret is missing.

## Kubernetes: Secrets Store CSI Driver

The [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io) mounts the secret straight from the store, with no Kubernetes Secret in between. The secret is only refreshed while the pod is running if the driver is installed with rotation on (`enableSecretRotation=true`, every `rotationPollInterval`). The AWS provider example below splits one JSON secret into two files (the provider also mounts the whole secret as `acme_license`, key included); the GCP, Azure, Vault and OpenBao providers take their own `parameters`.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: acme-license
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "acme/license"
        objectType: "secretsmanager"
        jmesPath:
          - path: key
            objectAlias: license-key
          - path: file
            objectAlias: license.lic
---
# in the pod
containers:
  - name: app
    volumeMounts:
      - name: license
        mountPath: /etc/acme/license   # license-key, license.lic
        readOnly: true
volumes:
  - name: license
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: acme-license
```

## Vault and OpenBao Agent

On Kubernetes, the agent injector adds a sidecar that renders the secret into `/vault/secrets/<name>` and keeps it up to date. Vault's annotations start with `vault.hashicorp.com/`. OpenBao's have the same names under `openbao.org/`, and OpenBao also renders into `/vault/secrets`.

```yaml
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: acme
    vault.hashicorp.com/agent-inject-secret-license.lic: secret/data/acme/license
    vault.hashicorp.com/agent-inject-template-license.lic: |
      {{- with secret "secret/data/acme/license" -}}{{ .Data.data.file }}{{- end }}
```

On VMs and bare metal, run `vault agent` or `bao agent` (they use the same configuration) with your `auto_auth` method and a template:

```hcl
template {
  destination = "/etc/acme/license/license.lic"
  perms       = "0640"
  contents    = <<-EOT
    {{- with secret "secret/data/acme/license" }}{{ .Data.data.file }}{{ end }}
  EOT
}
```

## In the app

- **License key**: read the file (or env var) at start and trim it: `key, err := os.ReadFile("/etc/acme/license/license-key")`, then `strings.TrimSpace`.
- **License file**: the offline client keeps the installed file in its own store, so a file that changes on disk has to be installed again. The SDK doesn't watch files: check the mounted file now and then (in its own goroutine) and call `Install` when it changes, as the `ExampleClient_Install_mounted` example in [`sdk/go/offline`](../sdk/go/offline/example_test.go) does. Point it at your mount (`/vault/secrets/license.lic` with the agent injector).
  - The same file again changes nothing, and an older file of the same license is refused (`ErrOlderFile`), so installing at every start can't roll a renewal back.
  - Removing the file uninstalls nothing: the installed file works until its `exp`.
  - Switching to another license through the secret manager needs `Deactivate` first (the new file is refused with `ErrOtherLicense` until then; the example tries each file once, so install it again or restart), which also gives the old seat back with a receipt. A returned file left in the mount is refused (`ErrReturned`).
