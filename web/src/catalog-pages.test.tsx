import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { CustomerDialog } from "./catalog-pages";
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
afterEach(() => vi.unstubAllGlobals());

it("clearing the email in the edit dialog sends only email: null", async () => {
  const customer = { id: "cus_1", name: "Acme", email: "a@acme.example", external_refs: {}, archived_at: null, created_at: "2026-11-01T00:00:00Z" };
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(JSON.stringify({ ...customer, email: null }), { headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", f);
  const onClose = vi.fn();
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <CustomerDialog tenant="acme" customer={customer} onClose={onClose} />
      </QueryClientProvider>,
    ),
  );
  const email = el.querySelector<HTMLInputElement>('input[name="email"]')!;
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  await act(async () => {
    setValue.call(email, "");
    email.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  const req = f.mock.calls[0]![0];
  expect(req.method).toBe("PATCH");
  expect(await req.text()).toBe('{"email":null}');
  act(() => root.unmount());
});

it("removing a reference line in the edit dialog sends that key as null", async () => {
  const customer = { id: "cus_1", name: "Acme", email: null, external_refs: { stripe: "cus_9", crm: "42" }, archived_at: null, created_at: "2026-11-01T00:00:00Z" };
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(JSON.stringify(customer), { headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", f);
  const onClose = vi.fn();
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <CustomerDialog tenant="acme" customer={customer} onClose={onClose} />
      </QueryClientProvider>,
    ),
  );
  const refs = el.querySelector<HTMLTextAreaElement>('textarea[name="refs"]')!;
  expect(refs.value).toBe("stripe=cus_9\ncrm=42");
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(refs, "stripe=cus_9");
    refs.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(await f.mock.calls[0]![0].text()).toBe('{"external_refs":{"crm":null}}');
  act(() => root.unmount());
});

it("a no-op edit closes without a request", async () => {
  const customer = { id: "cus_1", name: "Acme ", email: null, external_refs: { crm: " 42" }, archived_at: null, created_at: "2026-11-01T00:00:00Z" };
  const f = vi.fn<(req: Request) => Promise<Response>>();
  vi.stubGlobal("fetch", f);
  const onClose = vi.fn();
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <CustomerDialog tenant="acme" customer={customer} onClose={onClose} />
      </QueryClientProvider>,
    ),
  );
  await act(async () => el.querySelector("form")!.requestSubmit());
  await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(f).not.toHaveBeenCalled();
  act(() => root.unmount());
});

async function customersPage(role: string) {
  const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      if (path === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (path === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: true, product_ids: [] }] });
      if (path.endsWith("/customers")) return json({ items: [{ id: "cus_1", name: "Globex", email: null, external_refs: {}, archived_at: null, created_at: "2026-11-01T00:00:00Z" }] });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/customers"] }));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.textContent).toContain("Globex"));
  const buttons = [...el.querySelectorAll("button")].map((b) => b.textContent);
  act(() => root.unmount());
  return buttons;
}

it("hides Edit, Archive and New customer without customer:write", async () => {
  const support = await customersPage("support");
  expect(support).not.toContain("Edit");
  expect(support).not.toContain("Archive");
  expect(support).not.toContain("New customer");
  const manager = await customersPage("manager");
  expect(manager).toEqual(expect.arrayContaining(["Edit", "Archive", "New customer"]));
});

async function productsPage(role: string, scopeAll = true) {
  const posts: string[] = [];
  const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
  const db = { id: "prd_1", slug: "db", name: "DB", archived_at: null, created_at: "2026-11-01T00:00:00Z" };
  const old = { id: "prd_2", slug: "old", name: "Old", archived_at: "2026-11-02T00:00:00Z", created_at: "2026-10-01T00:00:00Z" };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      if (req.method === "POST") {
        posts.push(path);
        return json({ ...db, archived_at: "2026-11-05T00:00:00Z" });
      }
      if (path === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (path === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: scopeAll, product_ids: scopeAll ? [] : ["prd_1"] }] });
      if (path.endsWith("/products")) return json({ items: [db, old] });
      return json({ items: [] });
    }),
  );
  const qc = new QueryClient();
  const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/products"] }));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    ),
  );
  await vi.waitFor(() => expect(el.querySelector("header select option")?.textContent).toBe("Acme"));
  await vi.waitFor(() => expect(el.textContent).toContain("Old"));
  const rowButtons = (name: string) =>
    [...el.querySelectorAll("tbody tr")].find((r) => r.querySelector("td")?.textContent === name)!.querySelectorAll("button");
  return { el, root, posts, rowButtons };
}

it("archiving a product asks first, is one-way, and needs catalog:write", async () => {
  const { el, root, posts, rowButtons } = await productsPage("admin");
  expect(el.textContent).toContain("Archived");
  expect([...rowButtons("Old")].map((b) => b.textContent)).not.toContain("Archive"); // already archived: one-way
  const archive = [...rowButtons("DB")].find((b) => b.textContent === "Archive")!;
  await act(async () => archive.click());
  expect(el.querySelector("dialog")?.textContent).toContain("This is one-way");
  expect(posts).toHaveLength(0);
  const confirm = [...el.querySelectorAll<HTMLButtonElement>("dialog button")].find((b) => b.textContent === "Archive")!;
  await act(async () => confirm.click());
  await vi.waitFor(() => expect(posts).toEqual(["/api/v1/tenants/acme/products/prd_1/archive"]));
  act(() => root.unmount());

  const manager = await productsPage("manager");
  expect([...manager.rowButtons("DB")].map((b) => b.textContent)).not.toContain("Archive");
  act(() => manager.root.unmount());
});

it("names a Field with help by its label alone", async () => {
  const { Field } = await import("./catalog-pages");
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () => root.render(<Field label="Slug" name="slug" help="Lowercase words joined by dashes." error="taken" />));
  const f = el.querySelector("input")!;
  expect(f.labels?.[0]?.textContent).toBe("Slug");
  expect(f.getAttribute("aria-describedby")!.split(" ").map((id) => document.getElementById(id)?.textContent)).toEqual(["Lowercase words joined by dashes.", "taken"]);
  act(() => root.unmount());
});

it("names each field by its label alone; help and errors are its description", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { headers: { "Content-Type": "application/json" } })));
  const el = document.createElement("div");
  document.body.append(el);
  const root = createRoot(el);
  await act(async () =>
    root.render(
      <QueryClientProvider client={new QueryClient()}>
        <CustomerDialog tenant="acme" customer={null} onClose={() => {}} />
      </QueryClientProvider>,
    ),
  );
  for (const [name, label] of [["name", "Name"], ["refs", "External references"]] as const) {
    const f = el.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name="${name}"]`)!;
    expect(f.labels?.[0]?.textContent).toBe(label); // not label + help text, as it was
  }
  const refs = el.querySelector("textarea")!;
  expect(document.getElementById(refs.getAttribute("aria-describedby")!)?.textContent).toContain("key=value");
  act(() => root.unmount());
});
