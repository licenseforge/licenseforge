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
