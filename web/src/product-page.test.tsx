import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { createAppRouter } from "./router";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
    this.open = false;
  };
});
let root: Root | undefined;
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  vi.unstubAllGlobals();
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const product = { id: "prd_1", slug: "db", name: "DB Server", archived_at: null as string | null, created_at: "" };
const sso = { id: "ftr_1", product_id: "prd_1", key: "sso", name: "SSO", description: null, type: "boolean", unit: null, archived_at: null, created_at: "" };
const users = { ...sso, id: "ftr_2", key: "max_users", name: "Users", type: "limit", unit: "users" };
const pro = {
  id: "pln_1", product_id: "prd_1", slug: "pro", name: "Pro yearly", duration_months: 12, duration_seconds: null, expiry_basis: "from_issue",
  max_activations: 3, max_rehosts: null, bind_type: "machine", offline_allowed: false, lease_seconds: 604800, max_offline_seconds: null,
  grace_seconds: 0, archived_at: null, created_at: "",
};

async function page(role: string, opts: { archived?: boolean } = {}) {
  const posts: Request[] = [];
  const lists: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: true, product_ids: [] }] });
      if (req.method === "POST") {
        posts.push(req.clone());
        return json(u.pathname.endsWith("/plans") ? pro : sso, 201);
      }
      if (u.pathname.endsWith("/products/prd_1")) return json({ ...product, archived_at: opts.archived ? "2026-11-01T00:00:00Z" : null });
      lists.push(u);
      if (u.pathname.endsWith("/features")) return json({ items: [sso, users] });
      if (u.pathname.endsWith("/plans")) return json({ items: [pro] });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/products/prd_1"] }));
  await act(async () => root!.render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>));
  await vi.waitFor(() => expect(el.textContent).toContain("Pro yearly"));
  const button = (text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
  return { el, button, posts, lists };
}

it("lists the product's features and plans, filtered by product", async () => {
  const { el, lists } = await page("viewer");
  expect(el.querySelector("h1")!.textContent).toBe("DB Server");
  expect(el.textContent).toContain("max_users");
  expect(el.textContent).toContain("Limit users");
  expect(el.textContent).toContain("12 months");
  expect(lists.every((u) => u.searchParams.get("product_id") === "prd_1")).toBe(true);
});

it("offers writes to admins on an active product only", async () => {
  const viewer = await page("viewer");
  expect(viewer.button("New plan")).toBeUndefined();
  expect(viewer.button("Archive")).toBeUndefined();
  act(() => root?.unmount());
  const admin = await page("admin");
  expect(admin.button("New plan")).toBeDefined();
  expect(admin.button("New feature")).toBeDefined();
  act(() => root?.unmount());
  const archived = await page("admin", { archived: true });
  expect(archived.el.textContent).toContain("This product is archived");
  expect(archived.button("New plan")).toBeUndefined();
  expect(archived.button("Archive")).toBeUndefined();
});

it("creates a 14-day trial plan as seconds, with blank limits left out", async () => {
  const { el, button, posts } = await page("admin");
  await act(async () => button("New plan")!.click());
  const set = (name: string, value: string) => {
    const f = el.querySelector<HTMLInputElement | HTMLSelectElement>(`dialog [name="${name}"]`)!;
    const proto = f instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(f, value);
    f.dispatchEvent(new Event(f instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  };
  await act(async () => {
    set("slug", "trial");
    set("name", "Trial");
    set("term", "14");
    set("term_unit", "days");
  });
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(posts).toHaveLength(1));
  expect(JSON.parse(await posts[0]!.text())).toEqual({ product_id: "prd_1", slug: "trial", name: "Trial", bind_type: "machine", duration_seconds: 14 * 86400 });
});

it("refuses a term that isn't a whole number without a request", async () => {
  const { el, button, posts } = await page("admin");
  await act(async () => button("New plan")!.click());
  const term = el.querySelector<HTMLInputElement>('dialog [name="term"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(term, "1.5");
    term.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(el.textContent).toContain("A whole number."));
  expect(posts).toHaveLength(0);
});
