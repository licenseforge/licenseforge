# LicenseForge Go SDK

Module `licenseforge.io/licenseforge/sdk/go`, standard library only (ADR-0023, ADR-0030).

| Package | Does |
|---|---|
| `licensefile` | Verifies `lf1` license files and leases offline: Ed25519 signature against the keys embedded in your build, then the claim checks (`Open`). Entitlements: `HasFeature`, `Limit`, `Allows`. |
| `fingerprint` | This machine's (or Kubernetes cluster's) fingerprint, as the server binds it (ADR-0017). |
| `clock` | Protects time checks against the clock being turned back (ADR-0018). |
| `online` | Activates against the server with a license key and keeps the signed lease fresh (ADR-0004, ADR-0034). |
| `offline` | Air-gapped machines: writes the activation request, installs the vendor's license file, returns the seat with a deactivation receipt (ADR-0006, ADR-0043). |

## Online activation

Embed the trusted keys from the dashboard (Settings → Signing keys): paste its Go `licensefile.KeySet`, or embed its JSON and load it with `licensefile.ParseKeySet`:

```go
//go:embed trusted-keys.json
var trustedKeysJSON []byte

trustedKeys, err := licensefile.ParseKeySet(trustedKeysJSON)
```

```go
fp, err := fingerprint.Compute(ctx, tenantID, "acme-db", fingerprint.Options{})
guard, err := clock.New(clock.FileStore{Path: stateDir + "/clock"}, licenseKey, clock.Options{})
c, err := online.New(online.Config{
	BaseURL:     "https://api.vendor.example", // the server's API host
	TenantID:    tenantID,                     // tnt_…
	Product:     "acme-db",
	LicenseKey:  licenseKey,                   // as the user typed it
	Keys:        trustedKeys,                  // licensefile.KeySet embedded in the build
	Fingerprint: fp,
	AppVersion:  version,
	Clock:       guard,                        // optional
})
if _, err := c.Activate(ctx); err != nil { … } // once per machine; retries never take a second seat
go func() {
	// Run returns only on ctx's end or a refusal retrying can't fix: act on it.
	err := c.Run(ctx, logProblem) // every failure and warning goes to logProblem
	switch {
	case errors.Is(err, online.ErrNotActivated):
		// the seat was freed (deactivated, reset by support, moved): Activate again
	case errors.Is(err, online.ErrRevoked), errors.Is(err, online.ErrUnauthenticated), errors.Is(err, online.ErrBindingMismatch):
		// stop running as licensed
	case errors.Is(err, online.ErrNoLease):
		// nothing to keep fresh: Activate first
	}
}()

claims, status, err := c.Current() // before each licensed operation
if err != nil { /* not licensed */ }
if status == licensefile.StatusGrace { /* warn: the term ended, renewal pending */ }
```

- **Every lease is verified before it is used or cached**: signature against `Keys`, the claim checks at the lease's own `iat` (server time), the product, this machine's fingerprint and the tenant. A lease older than the one held (a replay) is refused. Anything else is `online.ErrBadLease` and is discarded; the last good lease stays.
- **Refreshing**: `Run` refreshes from `refresh_after` on, in server time (without one, at half the time to `exp`, at most 5 minutes apart). While the lease passes `Current` it wakes no later than half the time left to `exp` and to `iat + max_offline`, and, when the local clock runs fast (so `Current` would fail before `refresh_after`), shortly before that moment (10% of the time left, at most 2 minutes). It refreshes at once when the cached lease doesn't pass `Current` and the last refresh didn't succeed (for example a skewed clock after a restart), and never sooner than `online.MinRefreshInterval` (1 minute) after a success, always with jitter. A problem a fresh lease can't fix (e.g. a build newer than `updates_until`) doesn't make it poll. On `ErrRevoked` and `ErrNotActivated`, `Run` forgets the lease before returning: the server has said this machine is no longer licensed, so `Current` fails from then on, unless another call committed a newer lease meanwhile. With `max_offline` 0 (`refresh_after` is the lease's `iat`, ADR-0034), every use needs a fresh lease: **call `Refresh` before each check** yourself.
- **Transport**: `BaseURL` must be https (http only for loopback hosts); the license key travels in a header. The default HTTP client follows no redirects; a custom `HTTPClient` should do the same (`CheckRedirect` returning `http.ErrUseLastResponse`).
- **Retries**: network errors, 429, 5xx and `idempotency_in_progress` are retried (`Config.MaxAttempts`, default 4) with exponential backoff and jitter, never sooner than the server's `Retry-After` (seconds or an HTTP date, capped at 10 minutes). Refusals are not retried. Activate sends one random `Idempotency-Key` for all its retries.
- **Errors**: the API's stable codes are typed errors, e.g. `errors.Is(err, online.ErrRevoked)`; `*online.APIError` has the status, code and request ID. `Run` stops on refusals retrying can't fix (`ErrRevoked`, `ErrUnauthenticated`, `ErrNotActivated`, `ErrBindingMismatch`, `ErrOfflineSeat`) and returns that error; it keeps retrying the others.
- **Time (ADR-0018)**: the client keeps the offset between each lease's `iat` (authenticated server time) and the local clock, and checks with max(local, local + offset). With `Config.Clock`, it resets the guard's high-water mark to each lease's `iat`. The HTTP `Date` header is never trusted.
- **Persistence**: `Config.Store` (`Load`/`Save` of the lease string; `Save("")` means delete; it must not call back into the client, which holds its commit lock while saving) keeps the lease across restarts (ADR-0004). Stored leases are verified again when loaded and raise the clock guard to their `iat`; without a store, the lease lives in memory (a warning). Three ship, or bring your own:
  - `online.FileStore{Path: stateDir + "/lease"}`: locked across processes, atomic writes, mode 0600.
  - `&online.KubernetesConfigMap{Name: "acme-db-license"}`: one key (`lease`, or `Key`) of a ConfigMap in the pod's namespace (or `Namespace`), through the in-cluster API with the pod's service account, so every replica of a cluster-bound app shares the lease (the lease is signed, not secret). The token is read on every request (projected tokens rotate). Each Save reads the object and writes it back conditionally, keeping everything else in it; a concurrent update (409) or a deletion meanwhile is retried a few times with a short jittered pause, and the whole Save is bounded at 15 seconds. `&online.KubernetesSecret{...}` is the same on a Secret, for clusters whose policy prefers one. RBAC: create the object beforehand and grant `get` and `update` on it by name (granting `create` instead can't be limited to one name):

    ```yaml
    rules:
      - apiGroups: [""]
        resources: [configmaps] # or secrets
        resourceNames: [acme-db-license]
        verbs: [get, update]
    ```
- **Warnings**: a memory-only store, a stored lease that couldn't be loaded or didn't verify, and a clock guard or store that couldn't be written are reported through `Run`'s callback and `Warnings()`. `Activate` and `Refresh` succeed once the lease is in use; such write failures are warnings, not their errors.
- **Claims** returned by `Current` and in a `Lease` are copies. `Config.ClockTolerance` and `Config.BuildDate` reach the claim checks (`updates_until` is enforced with a build date).
- **Recovering from a far-future `iat`**: a lease issued by a server whose clock ran far ahead makes every correct later lease look older (a replay) and be refused. `Forget()` drops the cached and stored lease without contacting the server; then `Refresh` (or `Activate`). A refresh still in flight when `Forget` runs doesn't bring the lease back (`ErrSuperseded`).
- **Deactivate**: a machine the server already has as not activated (deactivated before, or the first attempt's answer was lost) counts as success; either way the lease is forgotten.
- **Offline**: with a cached lease the app keeps working through server outages until the lease's `max_offline` or `exp` (+ grace at the end of the term) runs out.

## Offline activation

For machines that can't reach the server (ADR-0043). Requests, files and receipts are carried by hand; the vendor answers them in the dashboard, the CLI or `POST /tenants/{tenant}/activation-requests` and `/deactivation-receipts`.

```go
guard, err := clock.New(clock.FileStore{Path: stateDir + "/clock"}, licenseKey, clock.Options{})
c, err := offline.New(offline.Config{
	TenantID:    tenantID,
	Product:     "acme-db",
	LicenseKey:  licenseKey,
	Keys:        trustedKeys,
	Fingerprint: fp,
	Store:       clock.FileStore{Path: stateDir + "/offline"}, // the installed file and the files returned; never the clock's file
	Clock:       guard,                                        // strongly advised: no server time comes in offline
})
req, err := c.Request()          // give this to the vendor: it contains the license key
claims, status, err := c.Install(fileFromVendor)
claims, status, err = c.Current() // before each licensed operation; any error: not licensed
receipt, err := c.Deactivate()   // gives the seat back: the file is deleted; send the receipt to the vendor
```

- **Delivered by a secret manager** (a mounted Secret or ConfigMap, a Vault or OpenBao Agent file): install it at start and again when it changes; see [Secret managers](../../docs/secret-managers.md) and `ExampleClient_Install_mounted`.
- **Install** verifies the file (signature, tenant, product, this machine's fingerprint, a machine or cluster binding) and checks it now; anything else is refused and nothing changes. Installing a renewed file replaces the old one, and an older file of the same license is refused (`ErrOlderFile`), so a stale copy can't roll a renewal back; `Current` reads the store on every call, so another process picks it up without a restart. Another license's file is refused while one is installed (`ErrOtherLicense`): deactivate first, so the seat can be returned. `clock.ErrLocked` means another process is changing the state: retry.
- **State**: the offline store must be its own (a store shared with the clock guard fails with `ErrForeignState`). Unreadable or corrupt state counts as none, like deleting it (ADR-0014).
- **The file is the offline term**: it works until its `exp` (the license's expiry, or the plan's `max_offline_seconds` from issue), with grace only when the license's own term ends. Renew with a new `Request` from the same machine (same seat).
- **Deactivate** deletes the file and remembers it in the store: that file, and older ones of the same license, can't be installed again (`ErrReturned`); deleting the store forgets this, like deleting the clock state (ADR-0014). Keep the receipt until the vendor has it; without it the vendor frees the seat from the dashboard, and the file would have worked until its `exp` anyway.
- **Time**: with `Config.Clock` (on its own store), every check uses the guarded time, so turning the clock back doesn't extend the file; a file whose `iat` is ahead of this machine's clock (the vendor's clock) is accepted within the guard's tolerance, and the guard is raised to it once the file is installed. Without a guard, the clock can be turned back freely.
- **Deactivate** needs a file that still verifies here; one whose signing key was dropped from `Keys`, or after a fingerprint change, is freed by the vendor from the dashboard.
