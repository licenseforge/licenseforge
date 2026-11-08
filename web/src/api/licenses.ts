import { infiniteQueryOptions, queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import { everyPage } from "./members";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type License = components["schemas"]["License"];
export type LicenseIssue = components["schemas"]["LicenseIssue"];
export type LicenseIssued = components["schemas"]["LicenseIssued"];
export type LicenseStatus = components["schemas"]["LicenseStatus"];
export type LicenseFilter = { product_id?: string; customer_id?: string; status?: LicenseStatus };

/** Licenses in the caller's product scope, newest first, with the API's equality filters. */
export const licensesQuery = (tenant: string, filter: LicenseFilter) =>
  infiniteQueryOptions({
    queryKey: ["licenses", tenant, filter],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/tenants/{tenant}/licenses", { params: { path: { tenant }, query: { ...filter, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor,
  });

/**
 * Issues a license. idempotencyKey is fixed for one issue dialog, so a retry
 * (a lost answer, a double click) gets the same license, never a second one.
 * The result holds the key: keep it in component state only.
 */
export async function issueLicense(tenant: string, body: LicenseIssue, idempotencyKey: string): Promise<LicenseIssued> {
  return unwrap(
    await api.POST("/tenants/{tenant}/licenses", { params: { path: { tenant }, header: { "Idempotency-Key": idempotencyKey } }, body }),
  );
}

export type LicenseAction = "suspend" | "reinstate" | "revoke";

export async function changeLicense(tenant: string, id: string, action: LicenseAction): Promise<License> {
  const params = { params: { path: { tenant, id } } };
  switch (action) {
    case "suspend":
      return unwrap(await api.POST("/tenants/{tenant}/licenses/{id}/suspend", params));
    case "reinstate":
      return unwrap(await api.POST("/tenants/{tenant}/licenses/{id}/reinstate", params));
    case "revoke":
      return unwrap(await api.POST("/tenants/{tenant}/licenses/{id}/revoke", params));
  }
}

/** What each status allows (the server answers 409 invalid_state otherwise). Revoked is final. */
export const actionsFor = (s: LicenseStatus): LicenseAction[] =>
  s === "active" ? ["suspend", "revoke"] : s === "suspended" ? ["reinstate", "revoke"] : [];

export type Activation = components["schemas"]["Activation"];

/** A license's machines, deactivated ones included, newest first (bounded paging). */
export const activationsQuery = (tenant: string, license: string) =>
  queryOptions({
    queryKey: ["activations", tenant, license],
    queryFn: () =>
      everyPage(async (cursor) =>
        unwrap(await api.GET("/tenants/{tenant}/licenses/{id}/activations", { params: { path: { tenant, id: license }, query: { cursor, limit: 200 } } })),
      ),
  });

/** Frees a machine's seat, as the SDK's deactivate does (ADR-0034); not a seat move. */
export async function deactivateActivation(tenant: string, license: string, activation: string): Promise<Activation> {
  return unwrap(
    await api.POST("/tenants/{tenant}/licenses/{id}/activations/{activation_id}/deactivate", { params: { path: { tenant, id: license, activation_id: activation } } }),
  );
}

/** Support rehost (ADR-0039): the license's seat moves count from zero again. */
export async function resetRehosts(tenant: string, license: string): Promise<License> {
  return unwrap(await api.POST("/tenants/{tenant}/licenses/{id}/rehosts/reset", { params: { path: { tenant, id: license } } }));
}

const rank = ["owner", "admin", "manager", "support", "viewer"];
/** activation:manage: support and up, on a product in their scope (deactivate machines, reset moves). */
export const canManageActivations = (m: Membership) => m.role !== "sdk" && rank.indexOf(m.role) <= rank.indexOf("support");
/**
 * license:issue and license:write: managers and up, on a product in their
 * scope (a scoped manager sees and picks only its products).
 */
export const canManageLicenses = (m: Membership) => m.role !== "sdk" && rank.indexOf(m.role) <= rank.indexOf("manager");
