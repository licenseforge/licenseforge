import { afterEach, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { isMfaRequired, listTenants, queryErrorHandler, setMfaPolicy, stepUpHref } from "./tenants";
import { QueryClient } from "@tanstack/react-query";
import { canManageTokens } from "./tokens";

afterEach(() => vi.unstubAllGlobals());

function serve(status: number, body: unknown) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", f);
  return f;
}

it("loads the user's tenants with role and scope", async () => {
  const f = serve(200, {
    items: [
      { tenant_id: "tnt_1", slug: "acme", name: "Acme", role: "owner", all_products: true, product_ids: [], mfa_policy: "none", accessible: true },
      { tenant_id: "tnt_2", slug: "beta", name: "Beta", role: "admin", all_products: false, product_ids: ["prd_1"], mfa_policy: "phishing_resistant", accessible: false, test: true },
    ],
  });
  const ts = await listTenants();
  const req = f.mock.calls[0]![0];
  expect(req.method).toBe("GET");
  expect(req.url).toBe(`${window.location.origin}/api/v1/me/tenants`);
  expect(req.credentials).toBe("same-origin");
  expect(ts).toEqual([
    { id: "tnt_1", slug: "acme", name: "Acme", role: "owner", scope: { all: true, products: [] }, mfaPolicy: "none", accessible: true, test: false },
    { id: "tnt_2", slug: "beta", name: "Beta", role: "admin", scope: { all: false, products: ["prd_1"] }, mfaPolicy: "phishing_resistant", accessible: false, test: true },
  ]);
  // The role and scope checks read it: a product-scoped admin can't manage tokens.
  expect(ts.map(canManageTokens)).toEqual([true, false]);
});

it("throws on a 401, so the session handler sends the user to sign in", async () => {
  serve(401, { type: "about:blank", title: "Unauthorized", status: 401, code: "unauthenticated", request_id: "r" });
  await expect(listTenants()).rejects.toBeInstanceOf(ApiError);
  await expect(listTenants()).rejects.toMatchObject({ status: 401, code: "unauthenticated" });
});

it("steps up to the tenant's level and comes back to it", () => {
  const u = new URL(stepUpHref("phishing_resistant", "acme"), window.location.origin);
  expect(u.pathname).toBe("/auth/login");
  expect(Object.fromEntries(u.searchParams)).toEqual({ assurance: "phishing_resistant", return: "/t/acme/" });
});

it("sets the MFA policy with a merge patch and recognizes the MFA refusal", async () => {
  const f = serve(200, { id: "tnt_1", slug: "acme", name: "Acme", mfa_policy: "mfa", active_api_tokens: 2 });
  await setMfaPolicy("acme", "mfa");
  const req = f.mock.calls[0]![0];
  expect([req.method, new URL(req.url).pathname, req.headers.get("Content-Type")]).toEqual(["PATCH", "/api/v1/tenants/acme", "application/merge-patch+json"]);
  expect(await req.text()).toBe('{"mfa_policy":"mfa"}');
  const refusal = new ApiError(403, "x", { type: "about:blank", title: "x", status: 403, code: "mfa_required", request_id: "r" });
  expect([isMfaRequired(refusal), isMfaRequired(new ApiError(403, "x")), isMfaRequired(new Error("x"))]).toEqual([true, false, false]);
});

it("treats a tenant without the accessible field as accessible", async () => {
  serve(200, { items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role: "owner", all_products: true, product_ids: [], mfa_policy: "none" }] });
  expect((await listTenants())[0]!.accessible).toBe(true);
});

it("refetches the tenants on an MFA refusal, not on other errors", () => {
  const qc = new QueryClient();
  const spy = vi.spyOn(qc, "invalidateQueries");
  const handle = queryErrorHandler(() => qc);
  handle(new ApiError(403, "x", { type: "about:blank", title: "x", status: 403, code: "forbidden", request_id: "r" }));
  expect(spy).not.toHaveBeenCalled();
  handle(new ApiError(403, "x", { type: "about:blank", title: "x", status: 403, code: "mfa_required", request_id: "r" }));
  expect(spy).toHaveBeenCalledWith({ queryKey: ["tenants"] });
  // The platform screen's refusal is the platform policy's, not a tenant's.
  spy.mockClear();
  handle(new ApiError(403, "x", { type: "about:blank", title: "x", status: 403, code: "mfa_required", request_id: "r" }), { queryKey: ["platform-tenants"] });
  expect(spy).not.toHaveBeenCalled();
});
