import { afterEach, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { listTenants } from "./tenants";
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
      { tenant_id: "tnt_1", slug: "acme", name: "Acme", role: "owner", all_products: true, product_ids: [] },
      { tenant_id: "tnt_2", slug: "beta", name: "Beta", role: "admin", all_products: false, product_ids: ["prd_1"] },
    ],
  });
  const ts = await listTenants();
  const req = f.mock.calls[0]![0];
  expect(req.method).toBe("GET");
  expect(req.url).toBe(`${window.location.origin}/api/v1/me/tenants`);
  expect(req.credentials).toBe("same-origin");
  expect(ts).toEqual([
    { id: "tnt_1", slug: "acme", name: "Acme", role: "owner", scope: { all: true, products: [] } },
    { id: "tnt_2", slug: "beta", name: "Beta", role: "admin", scope: { all: false, products: ["prd_1"] } },
  ]);
  // The role and scope checks read it: a product-scoped admin can't manage tokens.
  expect(ts.map(canManageTokens)).toEqual([true, false]);
});

it("throws on a 401, so the session handler sends the user to sign in", async () => {
  serve(401, { type: "about:blank", title: "Unauthorized", status: 401, code: "unauthenticated", request_id: "r" });
  await expect(listTenants()).rejects.toBeInstanceOf(ApiError);
  await expect(listTenants()).rejects.toMatchObject({ status: 401, code: "unauthenticated" });
});
