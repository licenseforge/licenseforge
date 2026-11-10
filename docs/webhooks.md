# Webhooks

LicenseForge calls your HTTPS endpoint when licenses and activations change, so a CRM, a provisioning system or a chat channel can follow along (ADR-0044). Each delivery is signed per [Standard Webhooks](https://www.standardwebhooks.com), so any of its receiver libraries can check it.

Manage endpoints in the dashboard (Settings → Webhooks) or with the API (`/tenants/{tenant}/webhooks`, see `api/openapi.yaml`). Owners and admins change them; members who see the whole tenant can read them. A tenant has at most 10 endpoints.

Your URL must be `https`, with no credentials or fragment, on port 443 unless your LicenseForge operator allows more, and reach a public address: LicenseForge refuses private, loopback and cloud metadata addresses when it connects. A URL that breaks these rules on connection (another port, an internal host) is accepted when you save it but fails every delivery as `connection failed`. A token in the path or query is fine: only the scheme, host and port are ever shown again.

## Events

| Event | When |
|---|---|
| `license.issued` | A license is issued |
| `license.suspended` | A license is suspended |
| `license.reinstated` | A suspended license is reinstated |
| `license.revoked` | A license is revoked (final) |
| `activation.created` | A machine or cluster takes a seat, online or offline (an offline renewal of a seat it holds isn't a new activation) |
| `activation.deactivated` | A seat is freed: deactivated by the SDK or the dashboard, or returned offline with a receipt |

License expiry isn't an event yet. An endpoint receives the events it subscribes to from its creation on, never earlier ones.

## What you receive

`POST` to your URL, with `Content-Type: application/json` and these headers:

| Header | Value |
|---|---|
| `webhook-id` | The event's ID (an audit entry ID, `aud_…`): the same on every retry. Deduplicate on it. |
| `webhook-timestamp` | Unix seconds of this attempt |
| `webhook-signature` | `v1,<base64>`: HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{body}` with your endpoint's secret. During a secret rotation, two signatures separated by a space; accept either. |
| `User-Agent` | `LicenseForge-Webhooks/1` |

The body is a snapshot of the change, built from the audit log:

```json
{
  "type": "license.revoked",
  "timestamp": "2026-11-10T12:00:00.123456Z",
  "data": {
    "license_id": "lic_…",
    "product_id": "prd_…",
    "customer_id": "cus_…",
    "plan": "pro",
    "status": "revoked",
    "expires_at": "2027-11-10T12:00:00Z"
  }
}
```

The body is the same on every retry; its `timestamp` is when the change happened (use it for ordering and staleness), while the `webhook-timestamp` header is the time of this attempt.

Activation events carry `activation_id`, `license_id`, `product_id`, `customer_id`, `fingerprint` (the hashed machine or cluster ID), `binding` (`machine` or `cluster`) and `mode` (`online` or `offline`). `expires_at` is `null` for a license that never expires, and also for one whose term starts at its first activation and hasn't started yet: then `license.issued` says `null`, and no event announces the expiry once the first activation sets it (GET the license after its `activation.created` to learn it). A field the event's entry doesn't have is left out rather than sent as `null`. The schemas are `WebhookPayload`, `WebhookLicenseData` and `WebhookActivationData` in the OpenAPI spec. Bodies never hold a license key, a license file or a secret.

## Verifying a delivery

The secret is shown once, when you create the endpoint or rotate its secret: `whsec_` followed by base64. Verify every request before acting on it, and refuse timestamps more than 5 minutes from your clock (replays).

With a Standard Webhooks library (pass the raw body, before parsing it):

```python
from standardwebhooks.webhooks import Webhook   # pip install standardwebhooks

payload = Webhook(secret).verify(raw_body, request.headers)  # raises if invalid or too old
```

```js
import { Webhook } from "standardwebhooks"; // npm install standardwebhooks

const payload = new Webhook(secret).verify(rawBody, headers); // throws if invalid or too old
```

Or by hand, in Go with the standard library only (imports: `crypto/hmac`, `crypto/sha256`, `encoding/base64`, `math`, `net/http`, `strconv`, `strings`, `time`):

```go
func verify(secret string, h http.Header, body []byte, now time.Time) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	ts, terr := strconv.ParseInt(h.Get("webhook-timestamp"), 10, 64)
	// An empty key (an unset secret) would accept anyone's signature.
	if err != nil || len(key) == 0 || terr != nil || math.Abs(now.Sub(time.Unix(ts, 0)).Seconds()) > 300 {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(h.Get("webhook-id") + "." + h.Get("webhook-timestamp") + "."))
	m.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	for _, sig := range strings.Fields(h.Get("webhook-signature")) {
		if hmac.Equal([]byte(sig), []byte(want)) {
			return true
		}
	}
	return false
}
```

## Delivery

- **Answer 2xx within 15 seconds**; do slow work after answering. Anything else is a failure: another status, a timeout, a TLS or connection error. A redirect is never followed.
- **In order, at least once, per endpoint.** An event can arrive twice (after a timeout, or a server restarting mid-send): deduplicate on `webhook-id`. Your endpoint's next event waits until this one succeeds; other endpoints aren't held up.
- **Retries** after 5 seconds, 5 minutes, 30 minutes, 2, 5, 10 and 10 hours (±10% jitter; never sooner than a `Retry-After` you send with a 429 or 503, up to 10 hours, which can stretch the schedule). After the 8th failed attempt, about 28 hours on with the normal pauses, the endpoint is **disabled**.
- **410 Gone** disables the endpoint at once.
- **History has a limit**: events stay deliverable as long as the tenant's audit log keeps them (at least 365 days). An endpoint disabled or behind for longer resumes after the gap, and the audit log records which entries it passed over.
- The delivery log (dashboard, or `GET …/webhooks/{id}/deliveries`) keeps 7 days of attempts with fixed error words (`timeout`, `connection failed`, `tls`, `redirect`, `http 500` and so on); never your server's address or response.

## When deliveries are stuck

In the dashboard, or with the API (`POST /tenants/{tenant}/webhooks/{id}/…`):

- **Disable** (`…/disable`): stop deliveries; events stay queued.
- **Enable** (`…/enable`) a disabled endpoint: it resumes at the event it stopped on, with a fresh retry schedule.
- **Skip held event** (`…/skip-event` with `{"seq": N}`): pass over the one event your receiver will never accept; N is the endpoint's `delivery.next_seq`. The next one is sent.
- **Skip to now** (`…/skip-to-now`): pass over everything not yet delivered.
- **Rotate secret** (`…/rotate-secret`): a new secret, shown once; the previous one keeps signing alongside it for 24 hours. There is one previous secret: rotating again within 24 hours ends the older one at once. A secret LicenseForge can no longer read (its master key was retired) is replaced without keeping it.

Every change and recovery action is recorded in the tenant's audit log.

## For operators

Every server pod delivers webhooks (`webhooks.workers`, default 8; `0` for none). The server connects only to public addresses on the allowed ports (443): it refuses private, loopback, link-local and cloud metadata addresses itself, checking each address it dials. The Helm chart's NetworkPolicy allows egress on those ports to any destination unless `webhooks.egress.to` narrows it. A self-hosted, single-vendor install with receivers on a private network can allow those ranges with `webhooks.allowCIDRs` (every tenant can then reach them; loopback, link-local and metadata addresses stay refused). `webhooks.ports` is the full list of allowed ports (include 443 if you set it), and `webhooks.denyCIDRs` refuses more ranges (an operator-chosen NAT64 prefix on an IPv6-only cluster). Without Helm, the same settings are `LICENSEFORGE_WEBHOOK_WORKERS`, `_PORTS`, `_ALLOW_CIDRS` and `_DENY_CIDRS`. See the chart's README, the Secure Configuration Guide, and the metrics `licenseforge_webhook_*`.
