import { infiniteQueryOptions } from "@tanstack/react-query";
import { detailsSpans } from "@/lib/audit-chain";
import { api, unwrap } from "./client";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type AuditEvent = components["schemas"]["AuditEvent"];
type AuditEventPage = components["schemas"]["AuditEventPage"];

/** One loaded page: the entries, and each entry's details exactly as sent (for the chain check). */
export type AuditPage = { items: AuditEvent[]; rawDetails: string[]; next_cursor?: string };

/** Reads one page as text: the parsed entries, plus their details cut raw from the body. */
export async function auditPage(tenant: string, cursor?: string): Promise<AuditPage> {
  const body = unwrap(
    await api.GET("/tenants/{tenant}/audit-events", { params: { path: { tenant }, query: { cursor } }, parseAs: "text" }),
  );
  const page = JSON.parse(body) as AuditEventPage;
  const rawDetails = detailsSpans(body);
  if (rawDetails.length !== page.items.length) throw new Error("audit page: details and items don't line up");
  return { items: page.items, rawDetails, next_cursor: page.next_cursor };
}

/** The tenant's audit log, newest first by seq (ADR-0027), a cursor page at a time. */
export const auditQuery = (tenant: string) =>
  infiniteQueryOptions({
    queryKey: ["audit-events", tenant],
    queryFn: ({ pageParam }) => auditPage(tenant, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor,
  });

/** audit:read on every product: owners and admins with all products (the API is the real check). */
export const canReadAudit = (m: Membership | undefined) => !!m && (m.role === "owner" || m.role === "admin") && m.scope.all;

/**
 * details as indented JSON text for a <pre>. React renders it as text
 * (escaped); it never goes through innerHTML, since details are recorded
 * values and may hold user-supplied strings.
 */
export const detailsText = (details: AuditEvent["details"]) => JSON.stringify(details, null, 2);

/** "user usr_…", "system": who acted. */
export const actorText = (e: Pick<AuditEvent, "actor_type" | "actor_id">) => (e.actor_id ? `${e.actor_type} ${e.actor_id}` : e.actor_type);

/** "license lic_…", or "" for a tenant-wide action. */
export const objectText = (e: Pick<AuditEvent, "object_type" | "object_id">) => [e.object_type, e.object_id].filter(Boolean).join(" ");
