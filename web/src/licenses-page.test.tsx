import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { License } from "./api/licenses";
import { expiryText, IssueDialog, LicenseDialog } from "./licenses-page";

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
const names = {
  products: [{ id: "prd_1", slug: "db", name: "DB", created_at: "" }],
  customers: [{ id: "cus_1", name: "Acme", email: null, external_refs: {}, archived_at: null, created_at: "" }],
  productName: (id: string) => (id === "prd_1" ? "DB" : id),
  customerName: (id: string) => (id === "cus_1" ? "Acme" : id),
};
const license: License = {
  id: "lic_1", product_id: "prd_1", plan_id: "pln_1", plan_slug: "pro", customer_id: "cus_1", type: "paid", status: "active",
  key_hint: "ABC123", expiry_basis: "from_issue", expires_at: null, max_activations: 3,
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
