import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "./client";
import { actionsFor, canManageActivations, canManageLicenses, changeLicense, issueLicense, licensesQuery } from "./licenses";

function serve(status: number, body: unknown) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", f);
  return f;
}
const sent = (f: ReturnType<typeof serve>, i = 0) => f.mock.calls[i]![0];
const base = `${window.location.origin}/api/v1/tenants/acme`;

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken("");
});

describe("license calls", () => {
  it("issues with the Idempotency-Key and the CSRF token", async () => {
    setCsrfToken("csrf-1");
    const f = serve(201, { id: "lic_1", key: "LF-SECRET" });
    await issueLicense("acme", { product_id: "prd_1", plan_id: "pln_1", customer_id: "cus_1", type: "paid" }, "idem-1");
    const req = sent(f);
    expect([req.method, req.url]).toEqual(["POST", `${base}/licenses`]);
    expect(req.headers.get("Idempotency-Key")).toBe("idem-1");
    expect(req.headers.get("X-CSRF-Token")).toBe("csrf-1");
    expect(JSON.parse(await req.text())).toEqual({ product_id: "prd_1", plan_id: "pln_1", customer_id: "cus_1", type: "paid" });
  });

  it("each action posts to its own path", async () => {
    for (const a of ["suspend", "reinstate", "revoke"] as const) {
      const f = serve(200, { id: "lic_1" });
      await changeLicense("acme", "lic_1", a);
      expect([sent(f).method, sent(f).url]).toEqual(["POST", `${base}/licenses/lic_1/${a}`]);
    }
  });

  it("a status that doesn't allow it is a problem", async () => {
    serve(409, { type: "about:blank", title: "Conflict", status: 409, code: "invalid_state", request_id: "r" });
    await expect(changeLicense("acme", "lic_1", "reinstate")).rejects.toMatchObject({ code: "invalid_state" });
  });

  it("lists with only the filters that are set", async () => {
    const f = serve(200, { items: [] });
    await new QueryClient().fetchInfiniteQuery(licensesQuery("acme", { product_id: "prd_1", status: "suspended" }));
    const url = new URL(sent(f).url);
    expect(url.pathname).toBe("/api/v1/tenants/acme/licenses");
    expect(Object.fromEntries(url.searchParams)).toEqual({ product_id: "prd_1", status: "suspended" });
  });
});

describe("actions and roles", () => {
  it("offers what each status allows; revoked is final", () => {
    expect(actionsFor("active")).toEqual(["suspend", "revoke"]);
    expect(actionsFor("suspended")).toEqual(["reinstate", "revoke"]);
    expect(actionsFor("revoked")).toEqual([]);
  });
  it("managers and up issue and change licenses", () => {
    const all = { all: true, products: [] };
    expect(canManageLicenses({ role: "manager", scope: { all: false, products: ["prd_1"] } })).toBe(true);
    expect(canManageLicenses({ role: "support", scope: all })).toBe(false);
    expect(canManageLicenses({ role: "sdk", scope: all })).toBe(false);
  });
  it("support and up manage machines and seat moves (activation:manage)", () => {
    const all = { all: true, products: [] };
    expect(canManageActivations({ role: "support", scope: { all: false, products: ["prd_1"] } })).toBe(true);
    expect(canManageActivations({ role: "owner", scope: all })).toBe(true);
    expect(canManageActivations({ role: "viewer", scope: all })).toBe(false);
    expect(canManageActivations({ role: "sdk", scope: all })).toBe(false);
  });
});
