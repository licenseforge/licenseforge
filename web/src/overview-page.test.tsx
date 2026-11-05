import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { createAppRouter } from "./router";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
let root: Root | undefined;
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  vi.unstubAllGlobals();
});

const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
const license = (i: number, status: string) => ({
  id: `lic_${i}`, product_id: "prd_1", plan_id: "pln_1", plan_slug: "pro", customer_id: "cus_1", type: "paid", status,
  key_hint: `HINT0${i}`, expiry_basis: "from_issue", expires_at: null, max_activations: null,
  entitlements: { features: [], limits: {} }, external_refs: {}, issued_at: "2026-11-01T00:00:00Z",
  suspended_at: null, revoked_at: null, created_at: "2026-11-01T00:00:00Z",
});

async function open(scopeAll: boolean) {
  const asked: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      asked.push(u.pathname);
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants")
        return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role: "manager", all_products: scopeAll, product_ids: scopeAll ? [] : ["prd_1"] }] });
      if (u.pathname.endsWith("/summary"))
        return json({ licenses: { active: 3, suspended: 1, revoked: 0 }, ...(scopeAll ? { customers: { active: 1 } } : {}) });
      if (u.pathname.endsWith("/licenses")) return json({ items: [license(1, "active"), license(2, "suspended")] }); // the newest
      if (u.pathname.endsWith("/customers"))
        return json({ items: [{ id: "cus_1", name: "Globex", email: null, external_refs: {}, archived_at: null, created_at: "" }, { id: "cus_2", name: "Old", email: null, external_refs: {}, archived_at: "2026-01-01T00:00:00Z", created_at: "" }] });
      if (u.pathname.endsWith("/products")) return json({ items: [{ id: "prd_1", slug: "db", name: "DB Server", created_at: "" }] });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme"] }));
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  await act(async () =>
    root!.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  const tile = (label: string) => [...el.querySelectorAll(".rounded-md.border.p-4")].find((d) => d.firstChild?.textContent === label)?.lastChild?.textContent;
  return { el, tile, asked };
}

it("shows licenses by status, active customers and the newest licenses with names", async () => {
  const { el, tile } = await open(true);
  await vi.waitFor(() => expect([tile("Active"), tile("Suspended"), tile("Revoked"), tile("Active customers")]).toEqual(["3", "1", "0", "1"]));
  await vi.waitFor(() => expect(el.textContent).toContain("DB Server · Globex"));
  expect(el.textContent).toContain("…HINT01");
});

it("a product-scoped caller gets no customers tile and doesn't ask for customers", async () => {
  const { el, tile, asked } = await open(false);
  await vi.waitFor(() => expect(tile("Active")).toBe("3"));
  expect(tile("Active customers")).toBeUndefined();
  expect(el.textContent).toContain("Counts cover the products your role can see.");
  expect(asked.some((p) => p.endsWith("/customers"))).toBe(false);
});

it("counts in one request: no list paging for the tiles", async () => {
  const { tile, asked } = await open(true);
  await vi.waitFor(() => expect(tile("Revoked")).toBe("0"));
  expect(asked.filter((p) => p.endsWith("/summary"))).toHaveLength(1);
  expect(asked.filter((p) => p.endsWith("/licenses"))).toHaveLength(1); // only the newest five
});
