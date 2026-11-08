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
const plan = (id: string, name: string, archived = false) => ({
  id, product_id: "prd_1", slug: id.replace("pln_", ""), name, duration_months: 12, duration_seconds: null, expiry_basis: "from_issue", max_activations: 3,
  max_rehosts: null, bind_type: "machine", offline_allowed: false, lease_seconds: 604800, max_offline_seconds: null, grace_seconds: 0,
  archived_at: archived ? "2026-11-01T00:00:00Z" : null, created_at: "",
});
const plansOf = (req: Request) => (new URL(req.url).pathname.endsWith("/plans") ? json({ items: [plan("pln_1", "Pro"), plan("pln_old", "Legacy", true)] }) : null);
const license: License = {
  id: "lic_1", product_id: "prd_1", plan_id: "pln_1", plan_slug: "pro", customer_id: "cus_1", type: "paid", status: "active",
  key_hint: "ABC123", expiry_basis: "from_issue", expires_at: null, max_activations: 3, active_activations: 0, max_rehosts: null, rehost_count: 0,
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
        if (req.method !== "POST") return plansOf(req) ?? json({ code: "internal" }, 500); // other list refetches fail
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
    });
    await vi.waitFor(() => expect(el.querySelector('select[name="plan_id"] option[value="pln_1"]')).not.toBeNull());
    await act(async () => set("plan_id", "pln_1"));
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
        if (req.method === "GET") return json({ items: [] }); // the machines list
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
  });
  await vi.waitFor(() => expect(el.querySelector(`select[name="plan_id"] option[value="${plan}"]`)).not.toBeNull());
  await act(async () => set("plan_id", plan));
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
        if (req.method !== "POST") return plansOf(req) ?? json({ items: [] });
        posts.push(req);
        return posts.length === 1
          ? json({ type: "about:blank", title: "x", status: 422, code: "validation_failed", request_id: "r", errors: [{ field: "/plan_id", message: "unknown plan" }] }, 422)
          : json({ ...license, key: "LF-KEY" }, 201);
      }),
    );
    const { el } = await render(<IssueDialog tenant="acme" names={names} onClose={() => {}} />);
    await fillIssue(el, "pln_1");
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
    vi.stubGlobal("fetch", vi.fn(async (req: Request) => (req.method === "POST" ? (posts.push(req), json({ ...license, key: "LF-KEY" }, 201)) : plansOf(req) ?? json({ items: [] }))));
    const { el } = await render(<IssueDialog tenant="acme" names={{ ...names, customers: [], issuable: [] }} onClose={() => {}} />);
    expect(el.querySelector('input[name="customer_id"]')).not.toBeNull();
    expect(el.textContent).toContain("paste the customer's ID");
    await fillIssue(el, "pln_1");
    await vi.waitFor(() => expect(posts).toHaveLength(1));
    expect(JSON.parse(await posts[0]!.text()).customer_id).toBe("cus_1");
  });

  it("offers the chosen product's active plans, after the product, and sends the chosen one", async () => {
    const posts: Request[] = [];
    const lists: URL[] = [];
    vi.stubGlobal("fetch", vi.fn(async (req: Request) => {
      if (req.method === "POST") return (posts.push(req), json({ ...license, key: "LF-KEY" }, 201));
      lists.push(new URL(req.url));
      return plansOf(req) ?? json({ items: [] });
    }));
    const { el } = await render(<IssueDialog tenant="acme" names={names} onClose={() => {}} />);
    expect(el.textContent).toContain("Choose the product first.");
    expect(el.querySelectorAll('select[name="plan_id"] option:not([disabled])')).toHaveLength(0);
    const product = el.querySelector<HTMLSelectElement>('select[name="product_id"]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(product, "prd_1");
      product.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await vi.waitFor(() => expect(el.querySelector('select[name="plan_id"] option[value="pln_1"]')).not.toBeNull());
    const options = [...el.querySelectorAll('select[name="plan_id"] option')].map((o) => o.textContent);
    expect(options).toContain("Pro (1)");
    expect(options).not.toContain("Legacy (old)"); // archived: issues nothing
    expect(lists.find((u) => u.pathname.endsWith("/plans"))!.searchParams.get("product_id")).toBe("prd_1");
    await fillIssue(el, "pln_1");
    await vi.waitFor(() => expect(posts).toHaveLength(1));
    expect(JSON.parse(await posts[0]!.text())).toMatchObject({ product_id: "prd_1", plan_id: "pln_1", customer_id: "cus_1" });
  });

  it("says when the product has no active plan", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ items: [plan("pln_old", "Legacy", true)] })));
    const { el } = await render(<IssueDialog tenant="acme" names={names} onClose={() => {}} />);
    const product = el.querySelector<HTMLSelectElement>('select[name="product_id"]')!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(product, "prd_1");
      product.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await vi.waitFor(() => expect(el.textContent).toContain("This product has no active plan."));
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
        if (u.pathname.endsWith("/activations")) {
          return json({ items: [{ id: "act_1", license_id: "lic_1", fingerprint: "f".repeat(64), fp_source: "machine-id", binding: "machine", mode: "online", hostname: "build-01",
            app_version: null, sdk_version: null, first_seen_at: "2026-11-01T00:00:00Z", last_seen_at: "2026-11-05T00:00:00Z", deactivated_at: null, created_at: "2026-11-01T00:00:00Z" }] });
        }
        return json({ items: [] });
      }),
    );
    const qc = new QueryClient();
    const router = createAppRouter(qc, createMemoryHistory({ initialEntries: ["/t/acme/licenses"] }));
    const r = await render(<RouterProvider router={router} />, qc);
    await vi.waitFor(() => expect(r.el.textContent).toContain("…ABC123"));
    return { ...r, lists };
  }

  it("gives support callers the machine actions in the license details; viewers none", async () => {
    for (const [role, offered] of [["support", true], ["viewer", false]] as const) {
      const { el } = await page(role);
      await act(async () => [...el.querySelectorAll("button")].find((b) => b.textContent === "Details")!.click());
      await vi.waitFor(() => expect(el.textContent).toContain("build-01"));
      expect(el.querySelector('button[aria-label="Deactivate build-01"]') !== null).toBe(offered);
      act(() => root?.unmount());
      root = undefined;
      vi.unstubAllGlobals();
    }
  });

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

describe("the license's machines (support rehost, ADR-0039)", () => {
  const machine = (id: string, host: string | null, off: string | null = null) => ({
    id, license_id: "lic_1", fingerprint: `${id}fingerprintabcdef`, fp_source: "machine-id", binding: "machine", mode: "online", hostname: host,
    app_version: "2.1.0", sdk_version: null, first_seen_at: "2026-11-01T00:00:00Z", last_seen_at: "2026-11-05T00:00:00Z", deactivated_at: off, created_at: "2026-11-01T00:00:00Z",
  });
  function stub() {
    const posts: string[] = [];
    let gets = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) => {
        const p = new URL(req.url).pathname;
        if (req.method === "POST") {
          posts.push(p);
          if (p.endsWith("/rehosts/reset")) return json({ ...license, max_rehosts: 2, rehost_count: 0 });
          return json(machine("act_1", "build-01", "2026-11-08T00:00:00Z"));
        }
        if (p.endsWith("/activations")) {
          gets++;
          return json({ items: [machine("act_1", "build-01"), machine("act_2", null, "2026-11-02T00:00:00Z")] });
        }
        return json({ items: [] });
      }),
    );
    return { posts, gets: () => gets };
  }
  const atLimit = { ...license, max_rehosts: 2, rehost_count: 2 };

  it("lists machines and moves; support may deactivate one", async () => {
    const s = stub();
    const { el, button } = await render(<LicenseDialog tenant="acme" license={atLimit} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />);
    await vi.waitFor(() => expect(el.textContent).toContain("build-01"));
    expect(el.textContent).toContain("Seat moves used: 2 of 2");
    expect(el.textContent).toContain("act_2fingerp"); // no hostname: the fingerprint's start
    expect(el.textContent).toContain("Deactivated");
    expect([...el.querySelectorAll("button")].filter((b) => b.textContent === "Deactivate")).toHaveLength(1); // the active one only
    await act(async () => button("Deactivate")!.click());
    expect(el.textContent).toContain("Deactivate build-01?");
    const before = s.gets();
    await act(async () => [...el.querySelectorAll('[role="group"] button')].find((b) => b.textContent === "Deactivate")!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    await vi.waitFor(() => expect(s.posts).toEqual(["/api/v1/tenants/acme/licenses/lic_1/activations/act_1/deactivate"]));
    await vi.waitFor(() => expect(s.gets()).toBeGreaterThan(before));
  });

  it("resets the moves after a confirmation and shows the license as it is now", async () => {
    const s = stub();
    let changed: License | null = null;
    const { el, button } = await render(<LicenseDialog tenant="acme" license={atLimit} manage={false} machines names={names} onClose={() => {}} onChanged={(l) => (changed = l)} />);
    await act(async () => button("Reset moves")!.click());
    expect(el.textContent).toContain("This is audited.");
    expect(s.posts).toEqual([]);
    await act(async () => [...el.querySelectorAll('[role="group"] button')].find((b) => b.textContent === "Reset moves")!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    await vi.waitFor(() => expect(s.posts).toEqual(["/api/v1/tenants/acme/licenses/lic_1/rehosts/reset"]));
    await vi.waitFor(() => expect(changed?.rehost_count).toBe(0));
  });

  it("lets support deactivate a machine of a suspended or revoked license", async () => {
    for (const status of ["suspended", "revoked"] as const) {
      stub();
      const r = await render(<LicenseDialog tenant="acme" license={{ ...atLimit, status }} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />);
      await vi.waitFor(() => expect(r.el.querySelector('button[aria-label="Deactivate build-01"]')).not.toBeNull());
      act(() => root?.unmount());
      root = undefined;
    }
  });

  it("clears a failed action's alert when the next confirmation opens", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (req: Request) =>
        req.method === "POST"
          ? json({ type: "about:blank", title: "x", status: 409, code: "invalid_state", request_id: "r" }, 409)
          : json({ items: [machine("act_1", "build-01")] }),
      ),
    );
    const { el, button } = await render(<LicenseDialog tenant="acme" license={atLimit} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />);
    await vi.waitFor(() => expect(el.textContent).toContain("build-01"));
    await act(async () => button("Reset moves")!.click());
    await act(async () => [...el.querySelectorAll('[role="group"] button')].find((b) => b.textContent === "Reset moves")!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    const alert = () => el.querySelector('section [role="alert"]');
    await vi.waitFor(() => expect(alert()).not.toBeNull());
    await act(async () => [...el.querySelectorAll('[role="group"] button')].find((b) => b.textContent === "Cancel")!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    expect(alert()).toBeNull();
  });

  it("drops an open machine confirmation when the license's status changes", async () => {
    stub();
    const qc = new QueryClient();
    const dialog = (l: License) => <LicenseDialog tenant="acme" license={l} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />;
    const { el, button } = await render(dialog(atLimit), qc);
    await act(async () => button("Reset moves")!.click());
    expect(el.textContent).toContain("This is audited.");
    await act(async () => root!.render(<QueryClientProvider client={qc}>{dialog({ ...atLimit, status: "revoked", revoked_at: "2026-11-08T00:00:00Z" })}</QueryClientProvider>));
    expect(el.textContent).not.toContain("This is audited.");
  });

  it("offers no actions without activation:manage, none to reset at zero, and no reset on a revoked license", async () => {
    stub();
    const viewer = await render(<LicenseDialog tenant="acme" license={atLimit} manage={false} names={names} onClose={() => {}} onChanged={() => {}} />);
    await vi.waitFor(() => expect(viewer.el.textContent).toContain("build-01"));
    expect(viewer.button("Deactivate")).toBeUndefined();
    expect(viewer.button("Reset moves")).toBeUndefined();
    act(() => root?.unmount());
    const zero = await render(<LicenseDialog tenant="acme" license={{ ...license, max_rehosts: null, rehost_count: 0 }} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />);
    expect(zero.el.textContent).toContain("Seat moves used: 0 (unlimited)");
    expect(zero.button("Reset moves")).toBeUndefined();
    act(() => root?.unmount());
    const revoked = await render(<LicenseDialog tenant="acme" license={{ ...atLimit, status: "revoked", revoked_at: "2026-11-08T00:00:00Z" }} manage={false} machines names={names} onClose={() => {}} onChanged={() => {}} />);
    expect(revoked.button("Reset moves")).toBeUndefined();
  });
});
