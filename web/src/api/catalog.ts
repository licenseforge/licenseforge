import { infiniteQueryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import { everyPage } from "./members";
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

/** Every product and customer the caller can see, for pickers and names (bounded paging). */
export const allProducts = (tenant: string) =>
  everyPage(async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/products", { params: { path: { tenant }, query: { cursor, limit: 200 } } })),
  );
export const allCustomers = (tenant: string) =>
  everyPage(async (cursor) =>
    unwrap(await api.GET("/tenants/{tenant}/customers", { params: { path: { tenant }, query: { cursor, limit: 200 } } })),
  );

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
 * The JSON Merge Patch (RFC 7396) from a customer as it was to as edited:
 * only what changed. A field counts as changed only if its raw input differs
 * from the stored value, so editing one field never rewrites another (a
 * stored name with a trailing space stays as it is); a changed value is
 * trimmed. An emptied email is null (cleared), since absent would mean
 * "keep". external_refs merges key by key on the server: a new or changed
 * key carries its value, a removed key is null, and untouched keys are left
 * out (external_refs is absent if no key changed).
 */
export function customerPatch(
  before: Pick<Customer, "name" | "email" | "external_refs">,
  after: { name: string; email: string; refs?: Map<string, string> },
): CustomerPatch {
  const patch: CustomerPatch = {};
  if (after.name !== before.name) patch.name = after.name.trim();
  if (after.email !== (before.email ?? "")) {
    const email = after.email.trim();
    if (email === "") {
      if (before.email !== null) patch.email = null;
    } else if (email !== before.email) patch.email = email;
  }
  if (after.refs) {
    const stored = (k: string) => (Object.hasOwn(before.external_refs, k) ? before.external_refs[k] : undefined);
    const changes: [string, string | null][] = [];
    for (const [k, raw] of after.refs) if (raw !== stored(k)) changes.push([k, raw.trim()]);
    for (const k of Object.keys(before.external_refs)) if (!after.refs.has(k)) changes.push([k, null]);
    // fromEntries defines own properties: "__proto__" or "constructor" are plain keys here.
    if (changes.length > 0) patch.external_refs = Object.fromEntries(changes);
  }
  return patch;
}

/** External references as the "key=value" lines parseRefs reads. */
export const formatRefs = (refs: Record<string, string>) =>
  Object.entries(refs)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

/**
 * External references from "key=value" lines; blank lines are skipped.
 * Keys are trimmed; values are kept raw (customerPatch compares them with
 * the stored ones, refsBody trims them). A Map, so any key is a plain key.
 * Throws on a line without a key.
 */
export function parseRefs(text: string): Map<string, string> {
  const refs = new Map<string, string>();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const at = line.indexOf("=");
    if (at < 0 || !line.slice(0, at).trim()) throw new Error(line.trim());
    refs.set(line.slice(0, at).trim(), line.slice(at + 1));
  }
  return refs;
}

/** References for a create: trimmed values, as an object with own keys only. */
export const refsBody = (refs: Map<string, string>): Record<string, string> =>
  Object.fromEntries([...refs].map(([k, v]) => [k, v.trim()]));

const rank = ["owner", "admin", "manager", "support", "viewer"];
const atLeast = (m: Membership, role: string) => m.role !== "sdk" && rank.indexOf(m.role) <= rank.indexOf(role);

/** catalog:write on every product: admins and owners with all products (creating is tenant-wide). */
export const canCreateProducts = (m: Membership) => atLeast(m, "admin") && m.scope.all;
/** catalog:write on a product: admins and owners; a scoped admin only lists (and so renames) its own products. */
export const canRenameProducts = (m: Membership) => atLeast(m, "admin");
/** customer:write, tenant-wide: managers and up with every product. */
export const canWriteCustomers = (m: Membership) => atLeast(m, "manager") && m.scope.all;
