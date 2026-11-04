import { queryOptions } from "@tanstack/react-query";
import type { Membership } from "./tokens";

/** A tenant of the signed-in user, with their role and scope there (hides actions they can't do). */
export type Tenant = { slug: string; name: string } & Membership;

// ponytail: stub until api/openapi.yaml has the signed-in user's tenants;
// swap the body for the generated client call, the type stays.
export async function listTenants(): Promise<Tenant[]> {
  return [
    { slug: "acme", name: "Acme Inc.", role: "owner", scope: { all: true, products: [] } },
    { slug: "acme-test", name: "Acme Inc. (test)", role: "admin", scope: { all: false, products: ["prd_1"] } },
  ];
}

export const tenantsQuery = queryOptions({ queryKey: ["tenants"], queryFn: listTenants, staleTime: 60_000 });
