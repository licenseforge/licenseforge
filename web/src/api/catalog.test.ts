import { afterEach, describe, expect, it, vi } from "vitest";
import {
  archiveCustomer,
  canCreateProducts,
  canRenameProducts,
  canWriteCustomers,
  createCustomer,
  customerPatch,
  formatRefs,
  FieldError,
  grantCells,
  grantsPatch,
  parseLimit,
  parseRefs,
  planBody,
  planTerm,
  refsBody,
  renameProduct,
  updateCustomer,
} from "./catalog";
import { setCsrfToken } from "./client";

function serve(status: number, body: unknown) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", f);
  return f;
}
const sent = (f: ReturnType<typeof serve>) => f.mock.calls[0]![0];
const base = `${window.location.origin}/api/v1/tenants/acme`;
const customer = { id: "cus_1", name: "Acme", email: "a@acme.example", external_refs: {}, archived_at: null, created_at: "2026-11-01T00:00:00Z" };

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken("");
});

describe("customerPatch (JSON Merge Patch)", () => {
  it("sends only what changed", () => {
    expect(customerPatch(customer, { name: "Acme", email: "a@acme.example" })).toEqual({});
    expect(customerPatch(customer, { name: " Acme Corp ", email: "a@acme.example" })).toEqual({ name: "Acme Corp" });
    expect(customerPatch(customer, { name: "Acme", email: "b@acme.example" })).toEqual({ email: "b@acme.example" });
  });
  it("clears an emptied email with null (absent would keep it)", () => {
    expect(customerPatch(customer, { name: "Acme", email: "  " })).toEqual({ email: null });
  });
  it("doesn't clear an email that was never set", () => {
    expect(customerPatch({ ...customer, email: null }, { name: "Acme", email: "" })).toEqual({});
  });
});

describe("customerPatch: external_refs merge key by key", () => {
  const before = { ...customer, external_refs: { stripe: "cus_1", crm: "42" } };
  it("sends a new or changed key with its value, a removed key as null, and leaves the rest out", () => {
    expect(customerPatch(before, { name: "Acme", email: "a@acme.example", refs: new Map([["stripe", "cus_2"], ["erp", "9"]]) })).toEqual({
      external_refs: { stripe: "cus_2", erp: "9", crm: null },
    });
  });
  it("omits external_refs when no key changed", () => {
    expect(customerPatch(before, { name: "Acme", email: "a@acme.example", refs: new Map([["crm", "42"], ["stripe", "cus_1"]]) })).toEqual({});
  });
  it("editing one field never rewrites another stored with spaces", () => {
    const spaced = { ...customer, name: "Acme ", external_refs: { crm: " 42" } };
    expect(customerPatch(spaced, { name: "Acme ", email: "b@acme.example", refs: new Map([["crm", " 42"]]) })).toEqual({ email: "b@acme.example" });
    // a value that did change is trimmed
    expect(customerPatch(spaced, { name: "Acme ", email: "a@acme.example", refs: new Map([["crm", " 43 "]]) })).toEqual({ external_refs: { crm: "43" } });
  });
  it("treats __proto__ and constructor as plain keys", () => {
    const refs = parseRefs("__proto__=x\nconstructor=y");
    expect([...refs]).toEqual([["__proto__", "x"], ["constructor", "y"]]);
    const patch = customerPatch({ ...customer, external_refs: {} }, { name: "Acme", email: "a@acme.example", refs });
    expect(JSON.stringify(patch)).toBe('{"external_refs":{"__proto__":"x","constructor":"y"}}');
    // a stored key named like an Object.prototype member isn't "already there"
    expect(customerPatch({ ...customer, external_refs: {} }, { name: "Acme", email: "a@acme.example", refs: new Map([["toString", "z"]]) })).toEqual({ external_refs: { toString: "z" } });
  });
});

describe("catalog calls", () => {
  it("edits a customer with merge-patch, null included", async () => {
    setCsrfToken("csrf-1");
    const f = serve(200, { ...customer, email: null });
    await updateCustomer("acme", "cus_1", customerPatch(customer, { name: "Acme", email: "" }));
    const req = sent(f);
    expect(req.method).toBe("PATCH");
    expect(req.url).toBe(`${base}/customers/cus_1`);
    expect(req.headers.get("Content-Type")).toBe("application/merge-patch+json");
    expect(req.headers.get("X-CSRF-Token")).toBe("csrf-1");
    expect(await req.text()).toBe('{"email":null}');
  });
  it("renames a product with merge-patch, never sending the slug", async () => {
    const f = serve(200, { id: "prd_1", slug: "db", name: "DB 2", created_at: "2026-11-01T00:00:00Z" });
    await renameProduct("acme", "prd_1", "DB 2");
    expect(sent(f).headers.get("Content-Type")).toBe("application/merge-patch+json");
    expect(await sent(f).text()).toBe('{"name":"DB 2"}');
  });
  it("creates a customer and archives one", async () => {
    let f = serve(201, customer);
    await createCustomer("acme", { name: "Acme", external_refs: { stripe: "cus_9" } });
    expect(await sent(f).text()).toBe('{"name":"Acme","external_refs":{"stripe":"cus_9"}}');
    f = serve(200, { ...customer, archived_at: "2026-11-05T00:00:00Z" });
    await archiveCustomer("acme", "cus_1");
    expect([sent(f).method, sent(f).url]).toEqual(["POST", `${base}/customers/cus_1/archive`]);
  });
  it("parses an archived customer's refusal as a problem", async () => {
    serve(409, { type: "about:blank", title: "Conflict", status: 409, code: "invalid_state", request_id: "r" });
    await expect(archiveCustomer("acme", "cus_1")).rejects.toMatchObject({ code: "invalid_state" });
  });
});

describe("parseRefs", () => {
  it("reads back what formatRefs writes", () => {
    expect(Object.fromEntries(parseRefs(formatRefs({ stripe: "cus_1", crm: "a=b" })))).toEqual({ stripe: "cus_1", crm: "a=b" });
  });
  it("reads key=value lines, skipping blanks", () => {
    // keys trimmed, values raw (refsBody trims them for a create)
    expect(Object.fromEntries(parseRefs("stripe=cus_1\n\n crm = 42 \n"))).toEqual({ stripe: "cus_1", crm: " 42 " });
    expect(refsBody(parseRefs("stripe=cus_1\n crm = 42 "))).toEqual({ stripe: "cus_1", crm: "42" });
  });
  it("refuses a line without a key", () => {
    expect(() => parseRefs("stripe")).toThrow("stripe");
    expect(() => parseRefs("=x")).toThrow();
  });
});

describe("who sees which actions", () => {
  const all = { all: true, products: [] };
  const scoped = { all: false, products: ["prd_1"] };
  it("creating products: admins and owners with every product", () => {
    expect(canCreateProducts({ role: "admin", scope: all })).toBe(true);
    expect(canCreateProducts({ role: "admin", scope: scoped })).toBe(false);
    expect(canCreateProducts({ role: "manager", scope: all })).toBe(false);
  });
  it("renaming: admins and owners, scoped ones on their own products", () => {
    expect(canRenameProducts({ role: "admin", scope: scoped })).toBe(true);
    expect(canRenameProducts({ role: "manager", scope: all })).toBe(false);
  });
  it("customers: managers and up with every product", () => {
    expect(canWriteCustomers({ role: "manager", scope: all })).toBe(true);
    expect(canWriteCustomers({ role: "support", scope: all })).toBe(false);
    expect(canWriteCustomers({ role: "owner", scope: scoped })).toBe(false);
    expect(canWriteCustomers({ role: "sdk", scope: all })).toBe(false);
  });
});

describe("planBody", () => {
  const base = { slug: " pro ", name: " Pro ", term: "", termUnit: "months" as const, maxActivations: "", bindType: "machine" };
  it("leaves blank numbers out: perpetual, unlimited", () => {
    expect(planBody("prd_1", base)).toEqual({ product_id: "prd_1", slug: "pro", name: "Pro", bind_type: "machine" });
  });
  it("sends months as months and days as seconds", () => {
    expect(planBody("prd_1", { ...base, term: "12", maxActivations: " 3 " })).toMatchObject({ duration_months: 12, max_activations: 3 });
    const trial = planBody("prd_1", { ...base, term: "14", termUnit: "days" });
    expect(trial.duration_seconds).toBe(14 * 86400);
    expect(trial).not.toHaveProperty("duration_months");
  });
  it("names the field that isn't a whole number", () => {
    expect(() => planBody("prd_1", { ...base, term: "1.5" })).toThrow(FieldError);
    expect(() => planBody("prd_1", { ...base, term: "1.5" })).toThrow("term");
    expect(() => planBody("prd_1", { ...base, maxActivations: "-1" })).toThrow("max_activations");
    expect(() => planBody("prd_1", { ...base, maxActivations: "1e3" })).toThrow("max_activations");
    expect(() => planBody("prd_1", { ...base, term: "1234567890", termUnit: "days" })).toThrow("term"); // would overflow or turn into 1e+21
  });
});

describe("planTerm", () => {
  it("prefers months, shows whole days, else seconds, else perpetual", () => {
    expect(planTerm({ duration_months: 12, duration_seconds: null })).toEqual({ kind: "months", n: 12 });
    expect(planTerm({ duration_months: null, duration_seconds: 14 * 86400 })).toEqual({ kind: "days", n: 14 });
    expect(planTerm({ duration_months: null, duration_seconds: 90 })).toEqual({ kind: "seconds", n: 90 });
    expect(planTerm({ duration_months: null, duration_seconds: null })).toEqual({ kind: "perpetual" });
  });
});

describe("the feature matrix's patch", () => {
  it("sets every touched cell to what it shows: true, the limit, or null", () => {
    expect(grantsPatch({ sso: true, export: false, max_users: " 050 ", nodes: "" })).toEqual({ patch: { sso: true, export: null, max_users: 50, nodes: null } });
    expect(grantsPatch({ max_users: "-1" })).toEqual({ patch: { max_users: -1 } });
    expect(grantsPatch({ nodes: "9007199254740991" })).toEqual({ patch: { nodes: 9007199254740991 } });
  });
  it("names limits that aren't valid and sends nothing", () => {
    expect(grantsPatch({ max_users: "1.5", nodes: "-2", seats: "9007199254740992", sso: false })).toEqual({ invalid: ["max_users", "nodes", "seats"] });
  });
  it("parses limits", () => {
    expect([parseLimit("-1"), parseLimit(" 12 "), parseLimit("-0"), parseLimit("1e3"), parseLimit("")]).toEqual([-1, 12, null, null, null]);
  });
  it("starts cells from the grants", () => {
    expect(grantCells({ sso: true, max_users: -1 }, [{ key: "sso", type: "boolean" }, { key: "export", type: "boolean" }, { key: "max_users", type: "limit" }, { key: "nodes", type: "limit" }]))
      .toEqual({ sso: true, export: false, max_users: "-1", nodes: "" });
  });
});
