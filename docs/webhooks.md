# Webhooks

LicenseForge calls your HTTPS endpoint when licenses and activations change, so a CRM, a provisioning system or a chat channel can follow along (ADR-0044). Each delivery is signed per [Standard Webhooks](https://www.standardwebhooks.com), so any of its receiver libraries can check it.

Manage endpoints in the dashboard (Settings → Webhooks) or with the API (`/tenants/{tenant}/webhooks`, see `api/openapi.yaml`). Owners and admins change them; members who see the whole tenant can read them. A tenant has at most 10 endpoints.

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

Activation events carry `activation_id`, `license_id`, `product_id`, `customer_id`, `fingerprint` (the hashed machine or cluster ID), `binding` (`machine` or `cluster`) and `mode` (`online` or `offline`). `expires_at` is `null` for a license that never expires. A field the event's entry doesn't have is left out rather than sent as `null`. The schemas are `WebhookPayload`, `WebhookLicenseData` and `WebhookActivationData` in the OpenAPI spec. Bodies never hold a license key, a license file or a secret.

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

Or by hand, in Go with the standard library only:

```go
func verify(secret string, h http.Header, body []byte, now time.Time) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	ts, terr := strconv.ParseInt(h.Get("webhook-timestamp"), 10, 64)
	if err != nil || terr != nil || math.Abs(now.Sub(time.Unix(ts, 0)).Seconds()) > 300 {
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
- **Retries** after 5 seconds, 5 minutes, 30 minutes, 2, 5, 10 and 10 hours (with a little jitter; never sooner than a `Retry-After` you send with a 429 or 503, up to 10 hours). After the last failure, about 28 hours on, the endpoint is **disabled**.
- **410 Gone** disables the endpoint at once.
- The dashboard's delivery log keeps 7 days of attempts with fixed error words (`timeout`, `connection failed`, `tls`, `redirect`, `http 500` and so on); never your server's address or response.

## When deliveries are stuck

- **Enable** a disabled endpoint: it resumes at the event it stopped on, with a fresh retry schedule.
- **Skip held event**: pass over the one event your receiver will never accept (its seq is the endpoint's `delivery.next_seq`); the next one is sent.
- **Skip to now**: pass over everything not yet delivered.
- **Rotate secret**: a new secret, shown once; the previous one keeps signing alongside it for 24 hours.

Every change and recovery action is recorded in the tenant's audit log.

## For operators

Every server pod delivers webhooks (`webhooks.workers`, default 8; `0` for none). The server connects only to public addresses on the allowed ports (443): it refuses private, loopback, link-local and cloud metadata addresses itself, checking each address it dials. The Helm chart's NetworkPolicy allows egress on those ports to any destination unless `webhooks.egress.to` narrows it. A self-hosted, single-vendor install with receivers on a private network can allow those ranges with `webhooks.allowCIDRs` (every tenant can then reach them). See the chart's README, the Secure Configuration Guide, and the metrics `licenseforge_webhook_*`.
