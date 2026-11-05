# LicenseForge Go SDK

Module `licenseforge.io/licenseforge/sdk/go`, standard library only (ADR-0023, ADR-0030).

| Package | Does |
|---|---|
| `licensefile` | Verifies `lf1` license files and leases offline: Ed25519 signature against the keys embedded in your build, then the claim checks (`Open`). Entitlements: `HasFeature`, `Limit`, `Allows`. |
| `fingerprint` | This machine's (or Kubernetes cluster's) fingerprint, as the server binds it (ADR-0017). |
| `clock` | Protects time checks against the clock being turned back (ADR-0018). |
| `online` | Activates against the server with a license key and keeps the signed lease fresh (ADR-0004, ADR-0034). |

## Online activation

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
		// the seat was freed (deactivated or reset by support): Activate again
	case errors.Is(err, online.ErrRevoked), errors.Is(err, online.ErrUnauthenticated), errors.Is(err, online.ErrBindingMismatch):
		// stop running as licensed
	}
}()

claims, status, err := c.Current() // before each licensed operation
if err != nil { /* not licensed */ }
if status == licensefile.StatusGrace { /* warn: the term ended, renewal pending */ }
```

- **Every lease is verified before it is used or cached**: signature against `Keys`, the claim checks at the lease's own `iat` (server time), the product, this machine's fingerprint and the tenant. A lease older than the one held (a replay) is refused. Anything else is `online.ErrBadLease` and is discarded; the last good lease stays.
- **Refreshing**: `Run` refreshes from `refresh_after` on, at once when the cached lease doesn't pass `Current` (for example a skewed clock after a restart), and never sooner than `online.MinRefreshInterval` (1 minute) after a success, always with jitter. With `max_offline` 0 (`refresh_after` is the lease's `iat`, ADR-0034), every use needs a fresh lease: **call `Refresh` before each check** yourself.
- **Transport**: `BaseURL` must be https (http only for loopback hosts); the license key travels in a header. The default HTTP client follows no redirects; a custom `HTTPClient` should do the same (`CheckRedirect` returning `http.ErrUseLastResponse`).
- **Retries**: network errors, 429, 5xx and `idempotency_in_progress` are retried (`Config.MaxAttempts`, default 4) with exponential backoff and jitter, never sooner than the server's `Retry-After` (seconds or an HTTP date, capped at 10 minutes). Refusals are not retried. Activate sends one random `Idempotency-Key` for all its retries.
- **Errors**: the API's stable codes are typed errors, e.g. `errors.Is(err, online.ErrRevoked)`; `*online.APIError` has the status, code and request ID. `Run` stops on refusals retrying can't fix (`ErrRevoked`, `ErrUnauthenticated`, `ErrNotActivated`, `ErrBindingMismatch`) and returns that error; it keeps retrying the others.
- **Time (ADR-0018)**: the client keeps the offset between each lease's `iat` (authenticated server time) and the local clock, and checks with max(local, local + offset). With `Config.Clock`, it resets the guard's high-water mark to each lease's `iat`. The HTTP `Date` header is never trusted.
- **Persistence**: `Config.Store` (`Load`/`Save` of the lease string; `Save("")` means delete) keeps the lease across restarts: a file, or a Kubernetes ConfigMap or Secret (ADR-0004). Stored leases are verified again when loaded and raise the clock guard to their `iat`. Only the interface ships for now; without a store, the lease lives in memory (a warning).
- **Warnings**: a memory-only store, a stored lease that couldn't be loaded or didn't verify, and a clock guard or store that couldn't be written are reported through `Run`'s callback and `Warnings()`. `Activate` and `Refresh` return the lease together with such an error: the lease is in use.
- **Claims** returned by `Current` and in a `Lease` are copies. `Config.ClockTolerance` and `Config.BuildDate` reach the claim checks (`updates_until` is enforced with a build date).
- **Recovering from a far-future `iat`**: a lease issued by a server whose clock ran far ahead makes every correct later lease look older (a replay) and be refused. `Forget()` drops the cached and stored lease without contacting the server; then `Refresh` (or `Activate`).
- **Deactivate** after a lost answer: a retry that finds the machine already deactivated counts as success.
- **Offline**: with a cached lease the app keeps working through server outages until the lease's `max_offline` or `exp` (+ grace at the end of the term) runs out.
