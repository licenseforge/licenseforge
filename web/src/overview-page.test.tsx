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

async function open(scopeAll: boolean, summaryCustomers = scopeAll, dailyFails = false) {
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
        return json({ licenses: { active: 3, suspended: 1, revoked: 0 }, ...(summaryCustomers ? { customers: { active: 1, seen_this_month: 7, month_start: "2026-11-01T00:00:00Z" } } : {}) });
      if (u.pathname.endsWith("/metrics/daily")) {
        asked.push(u.search);
        if (dailyFails) return new Response(JSON.stringify({ title: "Boom", status: 500, detail: "The daily series failed." }), { status: 500, headers: { "Content-Type": "application/problem+json" } });
        return json({ days: [
          { date: "2026-11-08", licenses_issued: 2, activations: 0, deactivations: 0 },
          { date: "2026-11-09", licenses_issued: 0, activations: 1, deactivations: 0 },
          { date: "2026-11-10", licenses_issued: 1, activations: 1200, deactivations: 1 },
        ] });
      }
      if (u.pathname.endsWith("/licenses")) return json({ items: [license(1, "active"), license(2, "suspended")] }); // the newest
      if (u.pathname.endsWith("/customers/cus_1")) return json({ id: "cus_1", name: "Globex", email: null, external_refs: {}, archived_at: null, created_at: "" });
      if (u.pathname.endsWith("/products/prd_1")) return json({ id: "prd_1", slug: "db", name: "DB Server", created_at: "" });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } }); // a failure shows at once
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

it("shows licenses by status, customers, those active this month and the newest licenses with names", async () => {
  const { el, tile, asked } = await open(true);
  await vi.waitFor(() => expect([tile("Active"), tile("Suspended"), tile("Revoked"), tile("Customers"), tile("Active in November 2026")]).toEqual(["3", "1", "0", "1", "7"]));
  await vi.waitFor(() => expect(el.textContent).toContain("DB Server · Globex"));
  expect(el.textContent).toContain("…HINT01");
  // Names by ID for the recent rows only: one lookup per distinct ID, no lists.
  expect(asked.filter((p) => /\/(customers|products)$/.test(p))).toEqual([]);
  expect(asked.filter((p) => p.endsWith("/customers/cus_1"))).toHaveLength(1);
  expect(asked.filter((p) => p.endsWith("/products/prd_1"))).toHaveLength(1);
});

it("a product-scoped caller gets no customers tile and doesn't ask for customers", async () => {
  const { el, tile, asked } = await open(false);
  await vi.waitFor(() => expect(tile("Active")).toBe("3"));
  expect(tile("Customers")).toBeUndefined();
  expect(tile("Active in November 2026")).toBeUndefined();
  expect(el.textContent).toContain("Counts cover the products your role can see.");
  expect(asked.some((p) => p.includes("/customers"))).toBe(false); // the summary omitted customers: no lookups either
});

it("counts in one request: no list paging for the tiles", async () => {
  const { tile, asked } = await open(true);
  await vi.waitFor(() => expect(tile("Revoked")).toBe("0"));
  expect(asked.filter((p) => p.endsWith("/summary"))).toHaveLength(1);
  expect(asked.filter((p) => p.endsWith("/licenses"))).toHaveLength(1); // only the newest five
});

it("looks customers up only when the summary includes them, whatever the caller's scope", async () => {
  const { el, tile, asked } = await open(true, false); // every product, but the server left customers out
  await vi.waitFor(() => expect(tile("Active")).toBe("3"));
  await vi.waitFor(() => expect(el.textContent).toContain("DB Server"));
  expect(tile("Customers")).toBeUndefined();
  expect(tile("Active in November 2026")).toBeUndefined();
  expect(asked.some((p) => p.includes("/customers"))).toBe(false);
});

it("charts the last 30 days per series, with totals, a tooltip per day and a table", async () => {
  const { el, asked } = await open(false);
  await vi.waitFor(() => expect(el.querySelectorAll("figure")).toHaveLength(3));
  expect(asked).toContain("?days=30");
  const figs = [...el.querySelectorAll("figure")];
  expect(figs.map((f) => f.querySelector("figcaption")?.textContent)).toEqual([
    "Licenses issued · 3 in 3 days", "Machines activated · 1,201 in 3 days", "Machines deactivated · 1 in 3 days",
  ]);
  // The chart is one image named by its caption (the series and the total).
  const svg = figs[0]!.querySelector("svg")!;
  expect(svg.getAttribute("role")).toBe("img");
  expect(document.getElementById(svg.getAttribute("aria-labelledby")!)).toBe(figs[0]!.querySelector("figcaption"));
  // A tooltip per day, empty days included; a column only where the count isn't zero.
  expect([...figs[0]!.querySelectorAll("title")].map((n) => n.textContent)).toEqual(["Nov 8: 2", "Nov 9: 0", "Nov 10: 1"]);
  expect(figs[0]!.querySelectorAll("path")).toHaveLength(2);
  // 1 against a peak of 1,200 still shows: 2 units tall, its rounded end no taller than itself.
  const small = [...figs[1]!.querySelectorAll("path")].map((n) => n.getAttribute("d")!);
  expect(small).toHaveLength(2);
  expect(small[0]).toMatch(/^M[\d.]+,80 V80 Q[\d.]+,78 /);
  // Heights are relative to the series' own peak: the tallest column reaches the top.
  const tops = [...figs[0]!.querySelectorAll("path")].map((n) => n.getAttribute("d")!.match(/^M[\d.]+,80 V([\d.]+)/)![1]);
  expect(tops.map(Number)).toEqual([80 - 76 + 4, 80 - 38 + 4]); // top of the column + its 4px rounded end
  const rows = [...el.querySelectorAll("details tbody tr")].map((r) => [...r.children].map((c) => c.textContent));
  expect(rows).toEqual([["Nov 8", "2", "0", "0"], ["Nov 9", "0", "1", "0"], ["Nov 10", "1", "1,200", "1"]]);
});

it("says when the daily series fails, and the rest of the overview still shows", async () => {
  const { el, tile } = await open(true, true, true);
  await vi.waitFor(() => expect(el.querySelector('[role="alert"]')?.textContent).toBeTruthy());
  expect(el.querySelectorAll("figure")).toHaveLength(0);
  expect(tile("Active")).toBe("3");
});
