import { infiniteQueryOptions } from "@tanstack/react-query";
import { api, ApiError, unwrap } from "./client";
import type { components } from "./schema";

export type PlatformTenant = components["schemas"]["PlatformTenant"];
export type PlatformTenantCreated = components["schemas"]["PlatformTenantCreated"];

/** Every tenant, newest first (platform admins, ADR-0042). */
export const platformTenantsQuery = infiniteQueryOptions({
  queryKey: ["platform-tenants"],
  queryFn: async ({ pageParam }) => unwrap(await api.GET("/platform/tenants", { params: { query: { cursor: pageParam } } })),
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (p) => p.next_cursor,
});

/** Creates a tenant and its first owner's invitation; the result holds the link token, shown once. */
export async function createPlatformTenant(slug: string, name: string, ownerEmail: string): Promise<PlatformTenantCreated> {
  return unwrap(await api.POST("/platform/tenants", { body: { slug, name, owner_email: ownerEmail } }));
}

/**
 * A new owner invitation for a tenant without an owner (ADR-0042, amended):
 * earlier pending ones stop working. The result holds the link token, shown once.
 */
export async function reinviteOwner(tenant: string, ownerEmail: string): Promise<PlatformTenantCreated> {
  return unwrap(await api.POST("/platform/tenants/{id}/owner-invitation", { params: { path: { id: tenant } }, body: { owner_email: ownerEmail } }));
}

/**
 * Where to sign in again when the session is short of the platform MFA
 * policy (403 mfa_required, ADR-0038), coming back here; null for other errors.
 */
export function platformStepUpHref(e: unknown): string | null {
  if (!(e instanceof ApiError) || e.code !== "mfa_required") return null;
  const level = (e.problem as { required_assurance?: string } | undefined)?.required_assurance;
  return level ? `/auth/login?${new URLSearchParams({ assurance: level, return: "/platform/" })}` : null;
}
