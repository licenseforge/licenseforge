import { infiniteQueryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type Product = components["schemas"]["Product"];
export type Customer = components["schemas"]["Customer"];
export type CustomerCreate = components["schemas"]["CustomerCreate"];
export type CustomerPatch = components["schemas"]["CustomerPatch"];

const mergePatch = { "Content-Type": "application/merge-patch+json" };

/** Products the caller may see: a product-scoped caller gets only its own (the server filters). */
export const productsQuery = (tenant: string) =>
  infiniteQueryOptions({
    queryKey: ["products", tenant],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/tenants/{tenant}/products", { params: { path: { tenant }, query: { cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor,
  });

export async function createProduct(tenant: string, slug: string, name: string): Promise<Product> {
  return unwrap(await api.POST("/tenants/{tenant}/products", { params: { path: { tenant } }, body: { slug, name } }));
}

/** Renames a product (JSON Merge Patch). The slug is the license's product claim and never changes. */
export async function renameProduct(tenant: string, id: string, name: string): Promise<Product> {
  return unwrap(await api.PATCH("/tenants/{tenant}/products/{id}", { params: { path: { tenant, id } }, body: { name }, headers: mergePatch }));
}

export const customersQuery = (tenant: string) =>
  infiniteQueryOptions({
    queryKey: ["customers", tenant],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/tenants/{tenant}/customers", { params: { path: { tenant }, query: { cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor,
  });

export async function createCustomer(tenant: string, body: CustomerCreate): Promise<Customer> {
  return unwrap(await api.POST("/tenants/{tenant}/customers", { params: { path: { tenant } }, body }));
}

export async function updateCustomer(tenant: string, id: string, patch: CustomerPatch): Promise<Customer> {
  return unwrap(await api.PATCH("/tenants/{tenant}/customers/{id}", { params: { path: { tenant, id } }, body: patch, headers: mergePatch }));
}

export async function archiveCustomer(tenant: string, id: string): Promise<Customer> {
  return unwrap(await api.POST("/tenants/{tenant}/customers/{id}/archive", { params: { path: { tenant, id } } }));
}

/**
 * The JSON Merge Patch (RFC 7396) from a customer's name and email as they
 * were to as edited: only what changed; an emptied email is null (cleared),
 * since absent would mean "keep".
 */
export function customerPatch(before: Pick<Customer, "name" | "email">, after: { name: string; email: string }): CustomerPatch {
  const patch: CustomerPatch = {};
  const name = after.name.trim();
  const email = after.email.trim();
  if (name !== before.name) patch.name = name;
  if (email === "" && before.email !== null) patch.email = null;
  else if (email !== "" && email !== before.email) patch.email = email;
  return patch;
}

/** External references from "key=value" lines; blank lines are skipped. Throws on a line without "=". */
export function parseRefs(text: string): Record<string, string> {
  const refs: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const at = line.indexOf("=");
    if (at <= 0) throw new Error(line);
    refs[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return refs;
}

const rank = ["owner", "admin", "manager", "support", "viewer"];
const atLeast = (m: Membership, role: string) => m.role !== "sdk" && rank.indexOf(m.role) <= rank.indexOf(role);

/** catalog:write on every product: admins and owners with all products (creating is tenant-wide). */
export const canCreateProducts = (m: Membership) => atLeast(m, "admin") && m.scope.all;
/** catalog:write on a product: admins and owners; a scoped admin only lists (and so renames) its own products. */
export const canRenameProducts = (m: Membership) => atLeast(m, "admin");
/** customer:write, tenant-wide: managers and up with every product. */
export const canWriteCustomers = (m: Membership) => atLeast(m, "manager") && m.scope.all;
