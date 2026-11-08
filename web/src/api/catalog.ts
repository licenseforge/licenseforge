import { infiniteQueryOptions, queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "./client";
import { everyPage } from "./members";
import type { components } from "./schema";
import type { Membership } from "./tokens";

export type Product = components["schemas"]["Product"];
export type Customer = components["schemas"]["Customer"];
export type CustomerCreate = components["schemas"]["CustomerCreate"];
export type CustomerPatch = components["schemas"]["CustomerPatch"];
export type Feature = components["schemas"]["Feature"];
export type FeatureCreate = components["schemas"]["FeatureCreate"];
export type Plan = components["schemas"]["Plan"];
export type PlanCreate = components["schemas"]["PlanCreate"];
export type PlanPatch = components["schemas"]["PlanPatch"];

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

export async function getProduct(tenant: string, id: string): Promise<Product> {
  return unwrap(await api.GET("/tenants/{tenant}/products/{id}", { params: { path: { tenant, id } } }));
}

export async function getCustomer(tenant: string, id: string): Promise<Customer> {
  return unwrap(await api.GET("/tenants/{tenant}/customers/{id}", { params: { path: { tenant, id } } }));
}

/** Archives a product, one-way (ADR-0015): no new licenses, plans or features; existing licenses keep working. */
export async function archiveProduct(tenant: string, id: string): Promise<Product> {
  return unwrap(await api.POST("/tenants/{tenant}/products/{id}/archive", { params: { path: { tenant, id } } }));
}

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

/** A product's features and plans, archived ones included, newest first (bounded paging). */
export const productFeaturesQuery = (tenant: string, product: string) =>
  queryOptions({
    queryKey: ["features", tenant, product],
    queryFn: () =>
      everyPage(async (cursor) =>
        unwrap(await api.GET("/tenants/{tenant}/features", { params: { path: { tenant }, query: { product_id: product, cursor, limit: 200 } } })),
      ),
  });
export const productPlansQuery = (tenant: string, product: string) =>
  queryOptions({
    queryKey: ["plans", tenant, product],
    queryFn: () =>
      everyPage(async (cursor) =>
        unwrap(await api.GET("/tenants/{tenant}/plans", { params: { path: { tenant }, query: { product_id: product, cursor, limit: 200 } } })),
      ),
  });

export async function createFeature(tenant: string, body: FeatureCreate): Promise<Feature> {
  return unwrap(await api.POST("/tenants/{tenant}/features", { params: { path: { tenant } }, body }));
}

/** Archives a feature, one-way: plans that grant it keep the grant; licenses keep their snapshot. */
export async function archiveFeature(tenant: string, id: string): Promise<Feature> {
  return unwrap(await api.POST("/tenants/{tenant}/features/{id}/archive", { params: { path: { tenant, id } } }));
}

export async function createPlan(tenant: string, body: PlanCreate): Promise<Plan> {
  return unwrap(await api.POST("/tenants/{tenant}/plans", { params: { path: { tenant } }, body }));
}

/** Changes a plan's name or terms (merge patch); licenses already sold keep theirs (ADR-0013). */
export async function updatePlan(tenant: string, id: string, patch: PlanPatch): Promise<Plan> {
  return unwrap(await api.PATCH("/tenants/{tenant}/plans/{id}", { params: { path: { tenant, id } }, body: patch, headers: mergePatch }));
}

/** Units for a duration in seconds, largest first. */
export const durationUnits = { days: 86400, hours: 3600, minutes: 60, seconds: 1 } as const;
export type DurationUnit = keyof typeof durationUnits;

/** A duration in seconds as the largest unit that holds it exactly (so editing loses nothing). */
export function splitDuration(seconds: number): { n: string; unit: DurationUnit } {
  for (const [unit, size] of Object.entries(durationUnits) as [DurationUnit, number][]) {
    if (seconds > 0 && seconds % size === 0) return { n: String(seconds / size), unit };
  }
  return { n: String(seconds), unit: "seconds" };
}

/** The plan edit form's raw fields. Empty optional numbers mean null (perpetual, unlimited, no offline limit). */
export type PlanForm = {
  name: string;
  term: string; termUnit: "months" | DurationUnit;
  expiryBasis: Plan["expiry_basis"];
  maxActivations: string; maxRehosts: string;
  offlineAllowed: boolean;
  lease: string; leaseUnit: DurationUnit;
  maxOffline: string; maxOfflineUnit: DurationUnit;
  grace: string; graceUnit: DurationUnit;
};

/** The form for a plan as it is. */
export function planForm(p: Plan): PlanForm {
  const term = p.duration_months != null ? { n: String(p.duration_months), unit: "months" as const } : p.duration_seconds != null ? splitDuration(p.duration_seconds) : { n: "", unit: "months" as const };
  const lease = splitDuration(p.lease_seconds);
  const offline = p.max_offline_seconds != null ? splitDuration(p.max_offline_seconds) : { n: "", unit: "days" as const };
  const grace = p.grace_seconds === 0 ? { n: "0", unit: "days" as const } : splitDuration(p.grace_seconds);
  return {
    name: p.name, term: term.n, termUnit: term.unit, expiryBasis: p.expiry_basis,
    maxActivations: p.max_activations == null ? "" : String(p.max_activations), maxRehosts: p.max_rehosts == null ? "" : String(p.max_rehosts),
    offlineAllowed: p.offline_allowed, lease: lease.n, leaseUnit: lease.unit, maxOffline: offline.n, maxOfflineUnit: offline.unit,
    grace: grace.n, graceUnit: grace.unit,
  };
}

/**
 * The merge patch from a plan to the edited form: only what changed, null
 * for a cleared optional term. Throws a FieldError naming a number that
 * isn't a whole number (the server checks the ranges and the whole result).
 */
export function planPatch(before: Plan, f: PlanForm): PlanPatch {
  const whole = (field: string, raw: string, size = 1) => {
    const s = raw.trim();
    if (!/^\d{1,12}$/.test(s)) throw new FieldError(field);
    const n = Number(s) * size;
    if (!Number.isSafeInteger(n)) throw new FieldError(field, "large"); // whole, but beyond any range the server takes
    return n;
  };
  const optional = (field: string, raw: string, size = 1) => (raw.trim() === "" ? null : whole(field, raw, size));
  const patch: PlanPatch = {};
  if (f.name.trim() !== before.name) patch.name = f.name.trim(); // trailing spaces alone aren't a rename
  let months: number | null = null;
  let seconds: number | null = null;
  if (f.term.trim() !== "") {
    if (f.termUnit === "months") months = whole("term", f.term);
    else seconds = whole("term", f.term, durationUnits[f.termUnit]);
  }
  if (months !== before.duration_months) patch.duration_months = months;
  if (seconds !== before.duration_seconds) patch.duration_seconds = seconds;
  if (f.expiryBasis !== before.expiry_basis) patch.expiry_basis = f.expiryBasis;
  const activations = optional("max_activations", f.maxActivations);
  if (activations !== before.max_activations) patch.max_activations = activations;
  const rehosts = optional("max_rehosts", f.maxRehosts);
  if (rehosts !== before.max_rehosts) patch.max_rehosts = rehosts;
  if (f.offlineAllowed !== before.offline_allowed) patch.offline_allowed = f.offlineAllowed;
  const lease = whole("lease_seconds", f.lease, durationUnits[f.leaseUnit]);
  if (lease !== before.lease_seconds) patch.lease_seconds = lease;
  const offline = optional("max_offline_seconds", f.maxOffline, durationUnits[f.maxOfflineUnit]);
  if (offline !== before.max_offline_seconds) patch.max_offline_seconds = offline;
  const grace = whole("grace_seconds", f.grace, durationUnits[f.graceUnit]);
  if (grace !== before.grace_seconds) patch.grace_seconds = grace;
  return patch;
}

/** Archives a plan, one-way: no new license from it; licenses already sold keep their terms. */
export async function archivePlan(tenant: string, id: string): Promise<Plan> {
  return unwrap(await api.POST("/tenants/{tenant}/plans/{id}/archive", { params: { path: { tenant, id } } }));
}

/**
 * A plan's term in words-ready parts: months, a day count (whole days of
 * duration_seconds), seconds otherwise, or perpetual.
 */
export function planTerm(p: Pick<Plan, "duration_months" | "duration_seconds">): { kind: "months" | "days" | "seconds"; n: number } | { kind: "perpetual" } {
  if (p.duration_months != null) return { kind: "months", n: p.duration_months };
  if (p.duration_seconds != null) return p.duration_seconds % 86400 === 0 ? { kind: "days", n: p.duration_seconds / 86400 } : { kind: "seconds", n: p.duration_seconds };
  return { kind: "perpetual" };
}

/** A form field refused before any request (planBody); field names it. */
export class FieldError extends Error {
  constructor(
    readonly field: string,
    readonly reason: "whole" | "large" = "whole",
  ) {
    super(field);
    this.name = "FieldError";
  }
}

/**
 * A plan create body from the dialog's raw fields: a blank number is left
 * out (the server's default: perpetual, unlimited); a term in days becomes
 * seconds. Throws a FieldError naming a number that isn't a whole number.
 */
export function planBody(product: string, f: { slug: string; name: string; term: string; termUnit: "months" | "days"; maxActivations: string; bindType: string }): PlanCreate {
  const whole = (field: string, raw: string) => {
    const s = raw.trim();
    if (!/^\d{1,9}$/.test(s)) throw new FieldError(field); // the server's ranges are far below 10^9
    return Number(s);
  };
  const body: PlanCreate = { product_id: product, slug: f.slug.trim(), name: f.name.trim(), bind_type: f.bindType as PlanCreate["bind_type"] };
  if (f.term.trim() !== "") {
    const n = whole("term", f.term);
    if (f.termUnit === "months") body.duration_months = n;
    else body.duration_seconds = n * 86400;
  }
  if (f.maxActivations.trim() !== "") body.max_activations = whole("max_activations", f.maxActivations);
  return body;
}

/** What a plan grants, by feature key: true (on/off) or a limit (-1 unlimited). */
export type Grants = Record<string, boolean | number>;

export const planFeaturesQuery = (tenant: string, plan: string) =>
  queryOptions({
    queryKey: ["plan-features", tenant, plan],
    queryFn: async () => unwrap(await api.GET("/tenants/{tenant}/plans/{id}/features", { params: { path: { tenant, id: plan } } })) as Grants,
  });

/** A merge patch of a plan's grants (ADR-0015): true, a limit, or null to remove; all or nothing. */
export async function updatePlanFeatures(tenant: string, plan: string, patch: Record<string, true | number | null>): Promise<Grants> {
  return unwrap(
    await api.PATCH("/tenants/{tenant}/plans/{id}/features", { params: { path: { tenant, id: plan } }, body: patch, headers: mergePatch }),
  ) as Grants;
}

/** A matrix cell as edited: on/off for a boolean feature, the raw text of a limit ("" not granted). */
export type Cell = boolean | string;

/** A limit cell's text: -1 (unlimited) or a whole number up to 2^53-1, else null. */
export function parseLimit(raw: string): number | null {
  const s = raw.trim();
  if (!/^(-1|\d{1,16})$/.test(s)) return null;
  const n = Number(s);
  return n <= Number.MAX_SAFE_INTEGER ? n : null;
}

/**
 * The merge patch that sets each touched cell to what it shows: true, the
 * limit, or null (cleared checkbox, emptied limit). Every touched cell is
 * sent, not only those differing from the grants as loaded: those may be
 * stale (another admin's change), and the server applies the patch as a
 * whole, changing and auditing only what differs. Returns the keys whose
 * limit text isn't valid instead.
 */
export function grantsPatch(cells: Record<string, Cell>): { patch: Record<string, true | number | null> } | { invalid: string[] } {
  const patch: Record<string, true | number | null> = {};
  const invalid: string[] = [];
  for (const [key, cell] of Object.entries(cells)) {
    if (typeof cell === "boolean") patch[key] = cell ? true : null;
    else if (cell.trim() === "") patch[key] = null;
    else {
      const n = parseLimit(cell);
      if (n === null) invalid.push(key);
      else patch[key] = n;
    }
  }
  return invalid.length > 0 ? { invalid } : { patch };
}

/** The cells a plan's grants start from: checkboxes and limit texts for every feature. */
export function grantCells(grants: Grants, features: Pick<Feature, "key" | "type">[]): Record<string, Cell> {
  const has = (k: string) => Object.hasOwn(grants, k);
  return Object.fromEntries(features.map((f) => [f.key, f.type === "limit" ? (has(f.key) ? String(grants[f.key]) : "") : has(f.key)]));
}

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
