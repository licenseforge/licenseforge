import { type QueryClient, queryOptions } from "@tanstack/react-query";
import { api, ApiError, onAuthError, unwrap } from "./client";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type MfaPolicy = components["schemas"]["MfaPolicy"];

/**
 * A tenant of the signed-in user, with their role and scope there (hides
 * actions they can't do), its MFA policy and whether this session meets it
 * (ADR-0038; false: the tenant's routes answer 403 mfa_required).
 */
export type Tenant = { id: string; slug: string; name: string; mfaPolicy: MfaPolicy; accessible: boolean } & Membership;

/** The signed-in user's tenants (GET /me/tenants), sorted by slug. */
export async function listTenants(): Promise<Tenant[]> {
  const page = unwrap(await api.GET("/me/tenants"));
  return page.items.map((m) => ({
    id: m.tenant_id,
    slug: m.slug,
    name: m.name,
    role: m.role,
    scope: { all: m.all_products, products: m.product_ids },
    mfaPolicy: m.mfa_policy,
    accessible: m.accessible !== false, // only an explicit false blocks (the server always sends it)
  }));
}

/**
 * Where to sign in again with a stronger method for a tenant (ADR-0038
 * step-up): the server asks the identity provider for a fresh
 * authentication at that level and comes back to the tenant.
 */
export const stepUpHref = (level: Exclude<MfaPolicy, "none">, slug: string, page = "") =>
  `/auth/login?${new URLSearchParams({ assurance: level, return: `/t/${slug}/${page}` })}`;

/** Sets the tenant's MFA policy (owners, from a session; raising it needs a session that meets it). */
export async function setMfaPolicy(tenant: string, policy: MfaPolicy) {
  return unwrap(
    await api.PATCH("/tenants/{tenant}", { params: { path: { tenant } }, body: { mfa_policy: policy }, headers: { "Content-Type": "application/merge-patch+json" } }),
  );
}

/** Whether an error is a tenant's MFA refusal: the session no longer meets its policy. */
export const isMfaRequired = (e: unknown) => e instanceof ApiError && e.problem?.code === "mfa_required";

export const tenantsQuery = queryOptions({ queryKey: ["tenants"], queryFn: listTenants, staleTime: 60_000 });

/**
 * The app's query and mutation error handler: a 401 goes to sign-in; a 403
 * mfa_required means the tenant's policy changed under this session
 * (ADR-0038), so the tenants are fetched again and the layout explains and
 * offers the step-up instead of every screen failing. The platform screen's
 * refusals are the platform policy's, not a tenant's: it explains them itself.
 */
export const queryErrorHandler = (qc: () => QueryClient) => (e: unknown, q?: unknown) => {
  onAuthError(e);
  const key = (q as { queryKey?: readonly unknown[] } | undefined)?.queryKey; // set for a query, not a mutation
  if (isMfaRequired(e) && key?.[0] !== "platform-tenants") void qc().invalidateQueries({ queryKey: tenantsQuery.queryKey });
};
