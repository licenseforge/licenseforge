import { queryOptions } from "@tanstack/react-query";
import type { Role } from "./tokens";

/** A tenant of the signed-in user, with their role there (hides actions they can't do). */
export type Tenant = { slug: string; name: string; role: Role };

// ponytail: stub until api/openapi.yaml has the signed-in user's tenants;
// swap the body for the generated client call, the type stays.
export async function listTenants(): Promise<Tenant[]> {
  return [
    { slug: "acme", name: "Acme Inc.", role: "owner" },
    { slug: "acme-test", name: "Acme Inc. (test)", role: "viewer" },
  ];
}

export const tenantsQuery = queryOptions({ queryKey: ["tenants"], queryFn: listTenants, staleTime: 60_000 });
