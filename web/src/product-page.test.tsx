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

async function page(role: string, opts: { archived?: boolean; planPost?: () => Response | Promise<Response>; planPatch?: () => Response } = {}) {
  const posts: Request[] = [];
  const lists: URL[] = [];
  let planArchived = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (req: Request) => {
      const u = new URL(req.url);
      if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
      if (u.pathname === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: true, product_ids: [] }] });
      if (req.method === "PATCH" && u.pathname.endsWith("/plans/pln_1")) {
        posts.push(req.clone());
        return opts.planPatch?.() ?? json(pro);
      }
      if (req.method === "POST") {
        posts.push(req.clone());
        if (u.pathname.endsWith("/plans/pln_1/archive")) {
          planArchived = true;
          return json({ ...pro, archived_at: "2026-11-07T00:00:00Z" });
        }
        if (u.pathname.endsWith("/plans")) return opts.planPost?.() ?? json(pro, 201);
        return json(sso, 201);
      }
      if (u.pathname.endsWith("/products/prd_1")) return json({ ...product, archived_at: opts.archived ? "2026-11-01T00:00:00Z" : null });
      if (/\/plans\/[^/]+\/features$/.test(u.pathname)) return json({ sso: true }); // the matrix
      lists.push(u);
      if (u.pathname.endsWith("/features")) return json({ items: [sso, users] });
      if (u.pathname.endsWith("/plans")) return json({ items: [{ ...pro, archived_at: planArchived ? "2026-11-07T00:00:00Z" : null }] });
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
  await vi.waitFor(() => expect(el.querySelector('input[aria-label="SSO in Pro yearly"]')).not.toBeNull()); // the matrix
  expect(lists.length).toBeGreaterThanOrEqual(2);
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

function setter(el: HTMLElement) {
  return (name: string, value: string) => {
    const f = el.querySelector<HTMLInputElement | HTMLSelectElement>(`dialog [name="${name}"]`)!;
    const proto = f instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(f, value);
    f.dispatchEvent(new Event(f instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  };
}
const submit = (el: HTMLElement) => act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());

it("creates a 14-day trial plan as seconds, with blank limits left out, and refreshes the plans", async () => {
  const { el, button, posts, lists } = await page("admin");
  await act(async () => button("New plan")!.click());
  const set = setter(el);
  const planLists = () => lists.filter((u) => u.pathname.endsWith("/plans")).length;
  const before = planLists();
  await act(async () => {
    set("slug", "trial");
    set("name", "Trial");
    set("term", "14");
    set("term_unit", "days");
  });
  await act(async () => el.querySelector<HTMLFormElement>("dialog form")!.requestSubmit());
  await vi.waitFor(() => expect(posts).toHaveLength(1));
  expect(JSON.parse(await posts[0]!.text())).toEqual({ product_id: "prd_1", slug: "trial", name: "Trial", bind_type: "machine", duration_seconds: 14 * 86400 });
  await vi.waitFor(() => expect(planLists()).toBeGreaterThan(before));
  expect(el.querySelector("dialog[open]")).toBeNull();
});

it("shows the server's term error under Term, after clearing the form's own", async () => {
  const problem = { type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/duration_seconds", message: "1 to 3153600000 (36,500 days)" }] };
  const { el, button } = await page("admin", { planPost: () => json(problem, 422) });
  await act(async () => button("New plan")!.click());
  const set = setter(el);
  await act(async () => {
    set("slug", "long");
    set("name", "Long");
    set("term", "1.5");
    set("term_unit", "days");
  });
  await submit(el);
  await vi.waitFor(() => expect(el.textContent).toContain("A whole number."));
  await act(async () => set("term", "40000"));
  await submit(el);
  await vi.waitFor(() => expect(document.getElementById("term-error")?.textContent).toBe("1 to 3153600000 (36,500 days)"));
  expect(el.textContent).not.toContain("A whole number.");
});

it("shows a network failure as the dialog's alert", async () => {
  const { el, button } = await page("admin", { planPost: () => Promise.reject(new TypeError("Failed to fetch")) });
  await act(async () => button("New plan")!.click());
  const set = setter(el);
  await act(async () => {
    set("slug", "pro2");
    set("name", "Pro 2");
  });
  await submit(el);
  await vi.waitFor(() => expect(el.querySelector('dialog [role="alert"]')).not.toBeNull());
});

it("archives a plan through the plan endpoint and shows it archived", async () => {
  const { el, posts } = await page("admin");
  const row = () => [...el.querySelectorAll("tr")].find((r) => r.textContent?.includes("Pro yearly"))!;
  await act(async () => [...row().querySelectorAll("button")].find((b) => b.textContent === "Archive")!.click());
  expect(el.textContent).toContain("no new licenses can be issued from this plan");
  await act(async () => [...el.querySelectorAll<HTMLButtonElement>("dialog button")].find((b) => b.textContent === "Archive")!.click());
  await vi.waitFor(() => expect(posts.map((p) => new URL(p.url).pathname)).toEqual(["/api/v1/tenants/acme/plans/pln_1/archive"]));
  await vi.waitFor(() => expect(row().textContent).toContain("Archived"));
});

it("creates an on/off feature without a unit field, and refreshes the features", async () => {
  const { el, button, posts, lists } = await page("admin");
  const featureLists = lists.filter((u) => u.pathname.endsWith("/features")).length;
  await act(async () => button("New feature")!.click());
  expect(el.querySelector('dialog [name="unit"]')).toBeNull();
  const set = setter(el);
  await act(async () => {
    set("key", "audit_log");
    set("name", "Audit log");
  });
  await submit(el);
  await vi.waitFor(() => expect(posts).toHaveLength(1));
  expect(new URL(posts[0]!.url).pathname).toBe("/api/v1/tenants/acme/features");
  expect(JSON.parse(await posts[0]!.text())).toEqual({ product_id: "prd_1", key: "audit_log", name: "Audit log", type: "boolean" });
  await vi.waitFor(() => expect(lists.filter((u) => u.pathname.endsWith("/features")).length).toBeGreaterThan(featureLists));
  await act(async () => button("New feature")!.click());
  await act(async () => setter(el)("type", "limit"));
  expect(el.querySelector('dialog [name="unit"]')).not.toBeNull();
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

it("edits a plan's terms, sending only what changed", async () => {
  const { el, posts } = await page("admin");
  await act(async () => el.querySelector<HTMLButtonElement>('button[aria-label="Edit Pro yearly"]')!.click());
  const field = (name: string) => el.querySelector<HTMLInputElement>(`dialog [name="${name}"]`)!;
  expect([field("term").value, field("lease_seconds").value, field("max_activations").value]).toEqual(["12", "7", "3"]); // 12 months, 7 days
  const set = setter(el);
  await act(async () => {
    set("max_activations", "");
    set("lease_seconds", "2");
  });
  await submit(el);
  await vi.waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0]!.method).toBe("PATCH");
  expect(JSON.parse(await posts[0]!.text())).toEqual({ max_activations: null, lease_seconds: 2 * 86400 });
  await vi.waitFor(() => expect(el.querySelector("dialog[open]")).toBeNull());
});

it("closes an untouched edit without a request; shows the server's term error under Term", async () => {
  const problem = { type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/duration_months", message: "1 to 1200" }] };
  const { el, posts } = await page("admin", { planPatch: () => json(problem, 422) });
  const edit = () => act(async () => el.querySelector<HTMLButtonElement>('button[aria-label="Edit Pro yearly"]')!.click());
  await edit();
  await submit(el);
  await vi.waitFor(() => expect(el.querySelector("dialog[open]")).toBeNull());
  expect(posts).toHaveLength(0);
  await edit();
  await act(async () => setter(el)("term", "5000"));
  await submit(el);
  await vi.waitFor(() => expect(document.getElementById("term-error")?.textContent).toBe("1 to 1200"));
});

it("shows a seconds-term error from the server under Term in the edit dialog", async () => {
  const problem = { type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/duration_seconds", message: "1 to 3153600000 (36,500 days)" }] };
  const { el } = await page("admin", { planPatch: () => json(problem, 422) });
  await act(async () => el.querySelector<HTMLButtonElement>('button[aria-label="Edit Pro yearly"]')!.click());
  const unit = el.querySelector<HTMLSelectElement>('dialog fieldset select')!; // the term's unit
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(unit, "days");
    unit.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await act(async () => setter(el)("term", "40000"));
  await submit(el);
  await vi.waitFor(() => expect(document.getElementById("term-error")?.textContent).toBe("1 to 3153600000 (36,500 days)"));
});
