import { infiniteQueryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type { components } from "./schema";

export type Role = components["schemas"]["Role"];
export type ApiToken = components["schemas"]["ApiToken"];
export type ApiTokenCreate = components["schemas"]["ApiTokenCreate"];
export type ApiTokenCreated = components["schemas"]["ApiTokenCreated"];

/** The token list, one cursor page at a time (ADR-0032). Never holds a secret. */
export const tokensQuery = (tenant: string) =>
  infiniteQueryOptions({
    queryKey: ["api-tokens", tenant],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/tenants/{tenant}/api-tokens", { params: { path: { tenant }, query: { cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor,
  });

/** Creates a token. The result holds the secret: keep it in component state only, never in the query cache. */
export async function createToken(tenant: string, body: ApiTokenCreate): Promise<ApiTokenCreated> {
  return unwrap(await api.POST("/tenants/{tenant}/api-tokens", { params: { path: { tenant } }, body }));
}

export async function revokeToken(tenant: string, id: string): Promise<ApiToken> {
  return unwrap(await api.POST("/tenants/{tenant}/api-tokens/{id}/revoke", { params: { path: { tenant, id } } }));
}

// Member roles, most powerful first: each has every permission of the ones after it (internal/authz).
const ranked: Role[] = ["owner", "admin", "manager", "support", "viewer"];

/** Whether the role may create and revoke tokens (token:write). */
export const canManageTokens = (role: Role) => role === "owner" || role === "admin";

/**
 * Roles a member may give a token: their own and below, plus sdk
 * (authz.CanAssign). Only to hide choices; the API is the real check.
 */
export function assignableTokenRoles(role: Role): Role[] {
  if (!canManageTokens(role)) return [];
  return [...ranked.slice(ranked.indexOf(role)), "sdk"];
}
