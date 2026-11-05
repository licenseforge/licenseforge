import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { License } from "./api/licenses";
import { ApiError } from "./api/client";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { expiryText, IssueDialog, keepIdempotencyKey, LicenseDialog } from "./licenses-page";
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
const acme = { id: "cus_1", name: "Acme", email: null, external_refs: {}, archived_at: null, created_at: "" };
const names = {
  products: [{ id: "prd_1", slug: "db", name: "DB", archived_at: null, created_at: "" }],
  issuableProducts: [{ id: "prd_1", slug: "db", name: "DB", archived_at: null, created_at: "" }],
  customers: [acme],
  issuable: [acme],
  complete: true,
  productName: (id: string) => (id === "prd_1" ? "DB" : id),
  customerName: (id: string) => (id === "cus_1" ? "Acme" : id),
};
const license: License = {
  id: "lic_1", product_id: "prd_1", plan_id: "pln_1", plan_slug: "pro", customer_id: "cus_1", type: "paid", status: "active",
  key_hint: "ABC123", expiry_basis: "from_issue", expires_at: null, max_activations: 3, active_activations: 0,
  entitlements: { features: ["sso"], limits: { seats: 10, nodes: -1 } }, external_refs: {},
  issued_at: "2026-11-01T00:00:00Z", suspended_at: null, revoked_at: null, created_at: "2026-11-01T00:00:00Z",
};

async function render(node: ReactNode, qc = new QueryClient()) {
  const el = document.createElement("div");
  document.body.append(el);
  root = createRoot(el);
  await act(async () => root!.render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>));
  const button = (text: string) => [...el.querySelectorAll("button")].find((b) => b.textContent === text);
  return { el, qc, button };
}

describe("IssueDialog", () => {
  it("retries with the same Idempotency-Key, shows the key once and keeps it nowhere after closing", async () => {
    const posts: Request[] = [];
    let attempt = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        if (req.method !== "POST") return json({ code: "internal" }, 500); // list refetches fail
        posts.push(req);
        return ++attempt === 1 ? json({ type: "about:blank", title: "x", status: 503, code: "internal", request_id: "r" }, 503) : json({ ...license, key: "LF-TOP-SECRET-KEY" }, 201);
      }),
    );
    let closed = false;
    const { el, qc, button } = await render(<IssueDialog tenant="acme" names={names} onClose={() => (closed = true)} />);
    const set = (name: string, value: string) => {
      const f = el.querySelector<HTMLInputElement | HTMLSelectElement>(`[name="${name}"]`)!;
      const proto = f instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(f, value);
      f.dispatchEvent(new Event(f instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
    };
    await act(async () => {
      set("product_id", "prd_1");
      set("customer_id", "cus_1");
      set("plan_id", "pln_1");
    });
    await act(async () => el.querySelector("form")!.requestSubmit()); // 503
    await vi.waitFor(() => expect(el.querySelector('[role="alert"]')).not.toBeNull());
    await act(async () => el.querySelector("form")!.requestSubmit()); // retry: 201
    await vi.waitFor(() => expect(el.querySelector<HTMLInputElement>("input[readonly]")?.value).toBe("LF-TOP-SECRET-KEY"));
    expect(posts).toHaveLength(2);
    expect(posts[0]!.headers.get("Idempotency-Key")).toBeTruthy();
    expect(posts[1]!.headers.get("Idempotency-Key")).toBe(posts[0]!.headers.get("Idempotency-Key"));

    await act(async () => button("Close")!.click());
    expect(closed).toBe(true);
    act(() => root?.unmount());
    root = undefined;
    const kept = JSON.stringify([
      document.body.innerHTML,
      qc.getQueryCache().getAll().map((q) => q.state),
      qc.getMutationCache().getAll().map((m) => m.state),
      { ...localStorage },
      { ...sessionStorage },
    ]);
    expect(kept).not.toContain("LF-TOP-SECRET-KEY");
  });
});

describe("LicenseDialog", () => {
  function server() {
    const posts: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        posts.push(new URL(req.url).pathname);
        const action = new URL(req.url).pathname.split("/").pop();
        return json({ ...license, status: action === "reinstate" ? "active" : action === "suspend" ? "suspended" : "revoked" });
      }),
    );
    return posts;
  }

  it("shows the entitlement snapshot", async () => {
    const { el } = await render(<LicenseDialog tenant="acme" license={license} manage names={names} onClose={() => {}} onChanged={() => {}} />);
    expect(el.textContent).toContain("sso");
    expect(el.textContent).toMatch(/seats\s*10/);
    expect(el.textContent).toMatch(/nodes\s*Unlimited/);
    expect(el.textContent).toContain("DB");
    expect(el.textContent).toContain("Acme");
  });

  it("revoking asks first, then posts", async () => {
    const posts = server();
    const changed = vi.fn();
    const { el, button } = await render(<LicenseDialog tenant="acme" license={license} manage names={names} onClose={() => {}} onChanged={changed} />);
    expect(button("Reinstate")).toBeUndefined();
    await act(async () => button("Revoke")!.click());
    expect(el.textContent).toContain("This is final");
    expect(posts).toHaveLength(0);
    await act(async () => button("Revoke")!.click()); // the confirmation's button
    await vi.waitFor(() => expect(changed).toHaveBeenCalled());
    expect(posts).toEqual(["/api/v1/tenants/acme/licenses/lic_1/revoke"]);
  });

  it("suspending asks first; reinstating doesn't", async () => {
    const posts = server();
    const { button } = await render(<LicenseDialog tenant="acme" license={license} manage names={names} onClose={() => {}} onChanged={() => {}} />);
    await act(async () => button("Suspend")!.click());
    expect(posts).toHaveLength(0);
    act(() => root?.unmount());
    const r2 = await render(<LicenseDialog tenant="acme" license={{ ...license, status: "suspended" }} manage names={names} onClose={() => {}} onChanged={() => {}} />);
    await act(async () => r2.button("Reinstate")!.click());
    await vi.waitFor(() => expect(posts).toEqual(["/api/v1/tenants/acme/licenses/lic_1/reinstate"]));
  });

  it("offers no actions without license:write, or on a revoked license", async () => {
    let r = await render(<LicenseDialog tenant="acme" license={license} manage={false} names={names} onClose={() => {}} onChanged={() => {}} />);
    expect([r.button("Suspend"), r.button("Revoke")]).toEqual([undefined, undefined]);
    act(() => root?.unmount());
    r = await render(<LicenseDialog tenant="acme" license={{ ...license, status: "revoked" }} manage names={names} onClose={() => {}} onChanged={() => {}} />);
    expect([r.button("Suspend"), r.button("Revoke"), r.button("Reinstate")]).toEqual([undefined, undefined, undefined]);
  });
});

it("describes the expiry: a date, perpetual, or from first activation", () => {
  expect(expiryText({ expires_at: null, expiry_basis: "from_issue" })).toBe("Never (perpetual)");
  expect(expiryText({ expires_at: null, expiry_basis: "from_first_activation" })).toBe("Counted from first activation");
  expect(expiryText({ expires_at: "2027-01-01T00:00:00Z", expiry_basis: "from_issue" })).not.toMatch(/Never|first/);
});

/** Fills and submits the issue form; customerField is "select" or "input". */
async function fillIssue(el: HTMLElement, plan: string) {
  const set = (name: string, value: string) => {
    const f = el.querySelector<HTMLInputElement | HTMLSelectElement>(`[name="${name}"]`)!;
    const proto = f instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(f, value);
    f.dispatchEvent(new Event(f instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  };
  await act(async () => {
    set("product_id", "prd_1");
    set("customer_id", "cus_1");
    set("plan_id", plan);
  });
  await act(async () => el.querySelector("form")!.requestSubmit());
}

describe("Idempotency-Key after an error", () => {
  it("keeps the key only when the request may have been processed", () => {
    const problem = (status: number, code: string) => new ApiError(status, "x", { type: "about:blank", title: "x", status, code, request_id: "r" });
    expect(keepIdempotencyKey(new TypeError("network"))).toBe(true);
    expect(keepIdempotencyKey(problem(503, "internal"))).toBe(true);
    expect(keepIdempotencyKey(problem(409, "idempotency_in_progress"))).toBe(true);
    expect(keepIdempotencyKey(problem(422, "idempotency_key_reused"))).toBe(true);
    expect(keepIdempotencyKey(problem(422, "validation_failed"))).toBe(false);
    expect(keepIdempotencyKey(problem(403, "forbidden"))).toBe(false);
  });

  it("a 422, an edit and a resubmit send a new key", async () => {
    const posts: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        if (req.method !== "POST") return json({ items: [] });
        posts.push(req);
        return posts.length === 1
          ? json({ type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/plan_id", message: "unknown plan" }] }, 422)
          : json({ ...license, key: "LF-KEY" }, 201);
      }),
    );
    const { el } = await render(<IssueDialog tenant="acme" names={names} onClose={() => {}} />);
    await fillIssue(el, "pln_wrong");
    await vi.waitFor(() => expect(el.textContent).toContain("unknown plan"));
    await fillIssue(el, "pln_1");
    await vi.waitFor(() => expect(posts).toHaveLength(2));
    expect(posts[1]!.headers.get("Idempotency-Key")).not.toBe(posts[0]!.headers.get("Idempotency-Key"));
  });
});

describe("issue pickers", () => {
  it("leaves archived customers out of the picker", async () => {
    const old = { ...acme, id: "cus_2", name: "Old Co", archived_at: "2026-01-01T00:00:00Z" };
    const { el } = await render(<IssueDialog tenant="acme" names={{ ...names, customers: [acme, old], issuable: [acme] }} onClose={() => {}} />);
    const options = [...el.querySelectorAll('select[name="customer_id"] option')].map((o) => o.textContent);
    expect(options).toContain("Acme");
    expect(options).not.toContain("Old Co");
  });

  it("without visible customers (a product-scoped caller), asks for a customer ID", async () => {
    const posts: Request[] = [];
    vi.stubGlobal("fetch", vi.fn(async (req: Request) => (req.method === "POST" ? (posts.push(req), json({ ...license, key: "LF-KEY" }, 201)) : json({ items: [] }))));
    const { el } = await render(<IssueDialog tenant="acme" names={{ ...names, customers: [], issuable: [] }} onClose={() => {}} />);
    expect(el.querySelector('input[name="customer_id"]')).not.toBeNull();
    expect(el.textContent).toContain("paste the customer's ID");
    await fillIssue(el, "pln_1");
    await vi.waitFor(() => expect(posts).toHaveLength(1));
    expect(JSON.parse(await posts[0]!.text()).customer_id).toBe("cus_1");
  });

  it("says when the lists behind the pickers are incomplete", async () => {
    const { el } = await render(<IssueDialog tenant="acme" names={{ ...names, complete: false }} onClose={() => {}} />);
    expect(el.textContent).toContain("weren't loaded");
  });
});

it("the suspend confirmation mentions air-gapped activation files", async () => {
  const { el, button } = await render(<LicenseDialog tenant="acme" license={license} manage names={names} onClose={() => {}} onChanged={() => {}} />);
  await act(async () => button("Suspend")!.click());
  expect(el.textContent).toContain("Air-gapped activation files stay valid until they expire.");
});

describe("the licenses page", () => {
  async function page(role: string, opts: { customers?: object[]; endlessCustomers?: boolean; products?: object[] } = {}) {
    const lists: URL[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        const u = new URL(req.url);
        if (u.pathname === "/auth/session") return json({ user: { id: "usr_1", email: "a@example.com", name: "A" }, csrf_token: "c" });
        if (u.pathname === "/api/v1/me/tenants") return json({ items: [{ tenant_id: "tnt_1", slug: "acme", name: "Acme", role, all_products: true, product_ids: [] }] });
        if (u.pathname.endsWith("/licenses")) {
          lists.push(u);
          return json({ items: [license] });
        }
        if (u.pathname.endsWith("/products")) return json({ items: opts.products ?? names.products });
        if (u.pathname.endsWith("/customers")) return json({ items: opts.customers ?? [acme], ...(opts.endlessCustomers ? { next_cursor: "more" } : {}) });
        return json({ items: [] });
      }),
    );
    const qc = new QueryClient();
    const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/licenses"] }));
    const r = await render(<RouterProvider router={router} />, qc);
    await vi.waitFor(() => expect(r.el.textContent).toContain("…ABC123"));
    return { ...r, lists };
  }

  it("resetting a filter to Any sends no filter", async () => {
    const { el, lists } = await page("manager");
    const product = el.querySelector<HTMLSelectElement>("main select")!; // the product filter (the header has the tenant switcher)
    const pick = async (v: string) =>
      act(async () => {
        Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(product, v);
        product.dispatchEvent(new Event("change", { bubbles: true }));
      });
    await pick("prd_1");
    await vi.waitFor(() => expect(lists.at(-1)!.searchParams.get("product_id")).toBe("prd_1"));
    await pick("");
    await vi.waitFor(() => expect(lists.at(-1)!.searchParams.has("product_id")).toBe(false));
    expect([...lists.at(-1)!.searchParams.keys()]).toEqual([]);
  });

  it("the issue picker leaves out archived products; the filter keeps them", async () => {
    const { el, button } = await page("manager", { products: [names.products[0]!, { id: "prd_old", slug: "old", name: "Old Product", archived_at: "2026-01-01T00:00:00Z", created_at: "" }] });
    await act(async () => button("Issue license")!.click());
    const picker = [...el.querySelectorAll('dialog select[name="product_id"] option')].map((o) => o.textContent);
    expect(picker).toContain("DB");
    expect(picker).not.toContain("Old Product");
    expect([...el.querySelectorAll("main select option")].map((o) => o.textContent)).toContain("Old Product");
  });

  it("the issue picker leaves out archived customers the page loaded", async () => {
    const old = { ...acme, id: "cus_2", name: "Old Co", archived_at: "2026-01-01T00:00:00Z" };
    const { el, button } = await page("manager", { customers: [acme, old] });
    await act(async () => button("Issue license")!.click());
    const options = [...el.querySelectorAll('dialog select[name="customer_id"] option')].map((o) => o.textContent);
    expect(options).toContain("Acme");
    expect(options).not.toContain("Old Co");
    // the customer filter keeps them (licenses of archived customers stay findable)
    expect([...el.querySelectorAll("main select option")].map((o) => o.textContent)).toContain("Old Co");
  });

  it("says when a list behind the filters stopped at its bound", async () => {
    const { el } = await page("manager", { endlessCustomers: true });
    await vi.waitFor(() => expect(el.textContent).toContain("weren't loaded"));
  });

  it("support sees licenses but no Issue button and no actions; a manager gets both", async () => {
    const s = await page("support");
    expect(s.button("Issue license")).toBeUndefined();
    await act(async () => s.button("Details")!.click());
    expect([s.button("Suspend"), s.button("Revoke")]).toEqual([undefined, undefined]);
    act(() => root?.unmount());
    root = undefined;
    const m = await page("manager");
    expect(m.button("Issue license")).toBeDefined();
    await act(async () => m.button("Details")!.click());
    expect(m.button("Suspend")).toBeDefined();
  });
});
