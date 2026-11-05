import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type { Membership } from "./tokens";

/** A tenant of the signed-in user, with their role and scope there (hides actions they can't do). */
export type Tenant = { id: string; slug: string; name: string } & Membership;

/** The signed-in user's tenants (GET /me/tenants), sorted by slug. */
export async function listTenants(): Promise<Tenant[]> {
  const page = unwrap(await api.GET("/me/tenants"));
  return page.items.map((m) => ({
    id: m.tenant_id,
    slug: m.slug,
    name: m.name,
    role: m.role,
    scope: { all: m.all_products, products: m.product_ids },
  }));
}

export const tenantsQuery = queryOptions({ queryKey: ["tenants"], queryFn: listTenants, staleTime: 60_000 });
