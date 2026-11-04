import { queryOptions } from "@tanstack/react-query";

export type Tenant = { slug: string; name: string };

// ponytail: stub until api/openapi.yaml has the signed-in user's tenants;
// swap the body for the generated client call, the type stays.
export async function listTenants(): Promise<Tenant[]> {
  return [
    { slug: "acme", name: "Acme Inc." },
    { slug: "acme-test", name: "Acme Inc. (test)" },
  ];
}

export const tenantsQuery = queryOptions({ queryKey: ["tenants"], queryFn: listTenants, staleTime: 60_000 });
