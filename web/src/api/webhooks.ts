import { infiniteQueryOptions, queryOptions } from "@tanstack/react-query";
import { api, check, unwrap } from "./client";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type Webhook = components["schemas"]["Webhook"];
export type WebhookCreated = components["schemas"]["WebhookCreated"];
export type WebhookEventType = components["schemas"]["WebhookEventType"];
export type WebhookDelivery = components["schemas"]["WebhookDelivery"];

/** The event catalog (ADR-0044), in the order the dashboard shows it. */
export const webhookEvents: WebhookEventType[] = [
  "license.issued",
  "license.revoked",
  "license.suspended",
  "license.reinstated",
  "activation.created",
  "activation.deactivated",
];

const mergePatch = { "Content-Type": "application/merge-patch+json" };

/** The tenant's endpoints (at most 10). Never holds a secret or a URL's path. */
export const webhooksQuery = (tenant: string) =>
  queryOptions({
    queryKey: ["webhooks", tenant],
    queryFn: async () => unwrap(await api.GET("/tenants/{tenant}/webhooks", { params: { path: { tenant } } })),
  });

/** An endpoint's delivery log, newest first, one cursor page at a time. */
export const webhookDeliveriesQuery = (tenant: string, id: string) =>
  infiniteQueryOptions({
    queryKey: ["webhooks", tenant, id, "deliveries"],
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/tenants/{tenant}/webhooks/{id}/deliveries", { params: { path: { tenant, id }, query: { cursor: pageParam } } }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor,
  });

/** Creates an endpoint. The result holds the secret: keep it in component state only. */
export async function createWebhook(tenant: string, url: string, events: WebhookEventType[]): Promise<WebhookCreated> {
  return unwrap(await api.POST("/tenants/{tenant}/webhooks", { params: { path: { tenant } }, body: { url, events } }));
}

/** A new signing secret, like createWebhook's: component state only. */
export async function rotateWebhookSecret(tenant: string, id: string): Promise<WebhookCreated> {
  return unwrap(await api.POST("/tenants/{tenant}/webhooks/{id}/rotate-secret", { params: { path: { tenant, id } } }));
}

export async function updateWebhook(tenant: string, id: string, patch: { url?: string; events?: WebhookEventType[] }): Promise<Webhook> {
  return unwrap(await api.PATCH("/tenants/{tenant}/webhooks/{id}", { params: { path: { tenant, id } }, body: patch, headers: mergePatch }));
}

export async function deleteWebhook(tenant: string, id: string): Promise<void> {
  check(await api.DELETE("/tenants/{tenant}/webhooks/{id}", { params: { path: { tenant, id } } }));
}

type Action = "disable" | "enable" | "skip-to-now";

export async function webhookAction(tenant: string, id: string, action: Action): Promise<Webhook> {
  const path = { params: { path: { tenant, id } } };
  switch (action) {
    case "disable":
      return unwrap(await api.POST("/tenants/{tenant}/webhooks/{id}/disable", path));
    case "enable":
      return unwrap(await api.POST("/tenants/{tenant}/webhooks/{id}/enable", path));
    case "skip-to-now":
      return unwrap(await api.POST("/tenants/{tenant}/webhooks/{id}/skip-to-now", path));
  }
}

export async function skipWebhookEvent(tenant: string, id: string, seq: number): Promise<Webhook> {
  return unwrap(await api.POST("/tenants/{tenant}/webhooks/{id}/skip-event", { params: { path: { tenant, id } }, body: { seq } }));
}

/** webhook:read is tenant-wide: a product-scoped member sees none. */
export const canReadWebhooks = (m: Membership | undefined) => !!m && m.scope.all;
/** webhook:write: owners and admins on every product. Only to hide controls; the API is the real check. */
export const canManageWebhooks = (m: Membership | undefined) => !!m && (m.role === "owner" || m.role === "admin") && m.scope.all;

/** Whether an event is held back: failing (retries counted) or disabled with one pending. */
export const heldBack = (w: Webhook) => w.delivery.next_seq != null && (w.delivery.attempts > 0 || !w.enabled);
