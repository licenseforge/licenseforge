# Command line

The `licenseforge` binary is also the CLI (ADR-0048). Commands that talk to a running LicenseForge use the REST API with an API token, and read three environment variables:

| Variable | Value |
|---|---|
| `LICENSEFORGE_URL` | The API's base URL, `https://licenses.example.com`. `http` works only for loopback hosts: the token goes with every request. |
| `LICENSEFORGE_TENANT` | The tenant's slug, filled in for `{tenant}` in paths |
| `LICENSEFORGE_TOKEN` | An API token (dashboard: Settings → API tokens), with the role and product scope the commands need |

Keep the token in a secret manager or your CI's secrets, never in a script.

## `licenseforge api`

One request to the API, with the answer printed as JSON. Every route in `api/openapi.yaml` works, within the token's access.

```sh
licenseforge api [--data JSON|@FILE|-] [--idempotency-key KEY] METHOD PATH
```

- `METHOD` is `GET`, `POST`, `PATCH` or `DELETE`. `PATH` starts after `/api/v1`, and may carry a query.
- `--data` is the JSON body: literal, `@file.json`, or `-` for stdin. A `PATCH` is sent as a JSON Merge Patch.
- `--idempotency-key` makes a `POST` safe to retry: the same key returns the first answer.
- A list returns at most one page: pass its `next_cursor` back as `?cursor=` for the next one.

The exit code tells a script what happened:

| Exit | Meaning |
|---|---|
| 0 | Success (2xx) |
| 1 | The API refused: the problem JSON is on stdout, and its status, code, detail and request ID are on stderr |
| 2 | A usage error: nothing was sent |
| 3 | The API couldn't be reached (connection, TLS, timeout) |

Redirects aren't followed, so the token never goes to another host.

### Recipes

Create a customer and issue a license on a plan:

```sh
cus=$(licenseforge api POST '/tenants/{tenant}/customers' --data '{"name":"Globex"}' | jq -r .id)
licenseforge api POST '/tenants/{tenant}/licenses' --idempotency-key "order-1042" \
  --data "{\"product_id\":\"prd_…\",\"plan_id\":\"pln_…\",\"customer_id\":\"$cus\",\"external_refs\":{\"order\":\"1042\"}}" | jq -r .key
```

The license key is in the issue answer only. Store it or hand it over then.

List a customer's licenses, and suspend or revoke one:

```sh
licenseforge api GET "/tenants/{tenant}/licenses?customer_id=$cus" | jq '.items[] | {id, status, expires_at}'
licenseforge api POST '/tenants/{tenant}/licenses/lic_…/suspend'
licenseforge api POST '/tenants/{tenant}/licenses/lic_…/revoke'
```

Renew maintenance to a date (ADR-0045):

```sh
licenseforge api POST '/tenants/{tenant}/licenses/lic_…/updates-until' --data '{"updates_until":"2027-12-31T23:59:59Z"}'
```

Page through every license:

```sh
cursor=""
while :; do
  page=$(licenseforge api GET "/tenants/{tenant}/licenses?limit=200${cursor:+&cursor=$cursor}")
  echo "$page" | jq -c '.items[]'
  cursor=$(echo "$page" | jq -r '.next_cursor // empty')
  [ -n "$cursor" ] || break
done
```

## `licenseforge offline`

This carries an air-gapped machine's files to the API (ADR-0043), with a token that has `activation:offline` on the product:

```sh
licenseforge offline activate --request request.txt > license.lic
licenseforge offline return --receipt receipt.txt
```

## `licenseforge tenant`

These run on the server's platform database login (`LICENSEFORGE_PLATFORM_DATABASE_URL`), not the API, for headless installs (ADR-0042):

```sh
licenseforge tenant create --slug acme --name "Acme" --owner-email owner@acme.example [--test]
licenseforge tenant invite-owner --tenant acme --owner-email owner@acme.example
```
